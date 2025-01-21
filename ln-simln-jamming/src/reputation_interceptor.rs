use crate::clock::InstantClock;
use crate::{endorsement_from_records, records_from_endorsement, BoxError, InterceptResult};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::outgoing_reputation::{ForwardManager, ForwardManagerParams};
use ln_resource_mgr::{
    AllocationCheck, EndorsementSignal, ForwardResolution, ForwardingOutcome, HtlcRef,
    ProposedForward, ReputationError, ReputationManager,
};
use simln_lib::sim_node::{ForwardingError, InterceptRequest, InterceptResolution, Interceptor};
use simln_lib::NetworkParser;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ops::Sub;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use triggered::Trigger;

#[derive(Clone)]
pub struct HtlcAdd {
    pub forwarding_node: PublicKey,
    pub htlc: ProposedForward,
}

impl HtlcAdd {
    /// Creates a htlc add from an intercept request, returning non if the request is for a htlc receive (there is no
    /// forward in this case).
    fn from_request(req: &InterceptRequest, added_at: Instant) -> Option<Self> {
        let outgoing_channel_id = match req.outgoing_channel_id {
            Some(o) => o.into(),
            None => return None,
        };

        let htlc = ProposedForward {
            incoming_ref: HtlcRef {
                channel_id: req.incoming_htlc.channel_id.into(),
                htlc_index: req.incoming_htlc.index,
            },
            outgoing_channel_id,
            amount_in_msat: req.incoming_amount_msat,
            amount_out_msat: req.outgoing_amount_msat,
            expiry_in_height: req.incoming_expiry_height,
            expiry_out_height: req.outgoing_expiry_height,
            added_at,
            incoming_endorsed: endorsement_from_records(&req.incoming_custom_records),
        };

        Some(HtlcAdd {
            forwarding_node: req.forwarding_node,
            htlc,
        })
    }
}

struct HtlcResolve {
    outgoing_channel_id: u64,
    forwarding_node: PublicKey,
    incoming_htlc: HtlcRef,
    forward_resolution: ForwardResolution,
    resolved_ins: Instant,
}

enum BootstrapEvent {
    BootstrapAdd(HtlcAdd),
    BootstrapResolve(HtlcResolve),
}

/// Provides details of a htlc forward that is used to bootstrap reputation values for the network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapForward {
    pub incoming_amt: u64,
    pub outgoing_amt: u64,
    pub incoming_expiry: u32,
    pub outgoing_expiry: u32,
    pub added_ns: u64,
    pub settled_ns: u64,
    pub forwarding_node: PublicKey,
    pub channel_in_id: u64,
    pub channel_out_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReputationPair {
    pub incoming_scid: u64,
    pub outgoing_scid: u64,
    pub incoming_revenue: i64,
    pub outgoing_reputation: i64,
}

impl ReputationPair {
    /// Determines whether a pair has sufficient reputation for the htlc risk provided.
    pub fn outgoing_reputation(&self, risk: u64) -> bool {
        self.outgoing_reputation > self.incoming_revenue + risk as i64
    }
}

/// Functionality to monitor reputation values in a network.
#[async_trait]
pub trait ReputationMonitor {
    async fn list_reputation_pairs(
        &self,
        node: PublicKey,
        access_ins: Instant,
    ) -> Result<Vec<ReputationPair>, BoxError>;

    async fn check_htlc_outcome(
        &self,
        htlc_add: HtlcAdd,
    ) -> Result<AllocationCheck, ReputationError>;
}

/// Implements a network-wide interceptor that implements resource management for every forwarding node in the
/// network.
#[derive(Clone)]
pub struct ReputationInterceptor {
    network_nodes: Arc<Mutex<HashMap<PublicKey, (ForwardManager, String)>>>,
    clock: Arc<dyn InstantClock + Send + Sync>,
    shutdown: Trigger,
}

impl ReputationInterceptor {
    pub fn new_for_network(
        params: ForwardManagerParams,
        edges: &[NetworkParser],
        clock: Arc<dyn InstantClock + Send + Sync>,
        shutdown: Trigger,
    ) -> Result<Self, BoxError> {
        let mut network_nodes: HashMap<PublicKey, (ForwardManager, String)> = HashMap::new();

        macro_rules! add_node_to_network {
            ($network_nodes:expr, $node_pubkey:expr, $node_alias:expr, $channel:expr) => {
                match $network_nodes.entry($node_pubkey) {
                    Entry::Vacant(e) => {
                        let forward_manager = ForwardManager::new(params);

                        let _ = forward_manager
                            .add_channel($channel.scid.into(), $channel.capacity_msat)?;

                        e.insert((forward_manager, $node_alias));
                    }
                    Entry::Occupied(mut e) => {
                        let _ = e
                            .get_mut()
                            .0
                            .add_channel($channel.scid.into(), $channel.capacity_msat)?;
                    }
                }
            };
        }

        for channel in edges {
            add_node_to_network!(
                network_nodes,
                channel.node_1.pubkey,
                channel.node_1.alias.clone(),
                channel
            );
            add_node_to_network!(
                network_nodes,
                channel.node_2.pubkey,
                channel.node_2.alias.clone(),
                channel
            );
        }

        Ok(Self {
            network_nodes: Arc::new(Mutex::new(network_nodes)),
            clock,
            shutdown,
        })
    }

    /// Creates a network from the set of edges provided and bootstraps the reputation of nodes in the network using
    /// the historical forwards provided. Forwards are expected to be sorted by added_ns in ascending order.
    pub async fn new_with_bootstrap(
        params: ForwardManagerParams,
        edges: &[NetworkParser],
        history: &[BootstrapForward],
        clock: Arc<dyn InstantClock + Send + Sync>,
        shutdown: Trigger,
    ) -> Result<Self, BoxError> {
        let mut interceptor = Self::new_for_network(params, edges, clock, shutdown)
            .map_err(|_| "could not create network")?;
        interceptor.bootstrap_network_history(history).await?;
        Ok(interceptor)
    }

    async fn bootstrap_network_history(
        &mut self,
        history: &[BootstrapForward],
    ) -> Result<(), BoxError> {
        // We'll get all instants relative to the last timestamp we're given, so we get an instant now and track
        // the last timestamp in the set of forwards.
        let start_ins = self.clock.now();
        let last_ts = history
            .iter()
            .max_by(|x, y| x.settled_ns.cmp(&y.settled_ns))
            .ok_or("at least one entry required in bootstrap history")?
            .settled_ns;

        // Run through history and create instants relative to the current time, we'll have two events per forward
        // so we can allocate accordingly.
        let mut bootstrap_events = Vec::with_capacity(history.len() * 2);
        for (i, h) in history.iter().enumerate() {
            let incoming_ref = HtlcRef {
                channel_id: h.channel_in_id,
                htlc_index: i as u64,
            };

            bootstrap_events.push(BootstrapEvent::BootstrapAdd(HtlcAdd {
                forwarding_node: h.forwarding_node,
                htlc: ProposedForward {
                    incoming_ref,
                    outgoing_channel_id: h.channel_out_id,
                    amount_in_msat: h.incoming_amt,
                    amount_out_msat: h.outgoing_amt,
                    expiry_in_height: h.incoming_expiry,
                    expiry_out_height: h.outgoing_expiry,
                    added_at: start_ins.sub(Duration::from_nanos(
                        last_ts
                            .checked_sub(h.added_ns)
                            .ok_or(format!("added ts: {} > last ts: {last_ts}", h.added_ns))?,
                    )),
                    incoming_endorsed: EndorsementSignal::Unendorsed,
                },
            }));

            bootstrap_events.push(BootstrapEvent::BootstrapResolve(HtlcResolve {
                outgoing_channel_id: h.channel_out_id,
                forwarding_node: h.forwarding_node,
                incoming_htlc: incoming_ref,
                resolved_ins: start_ins.sub(Duration::from_nanos(
                    last_ts
                        .checked_sub(h.settled_ns)
                        .ok_or(format!("settled ts: {} > last ts: {last_ts}", h.settled_ns))?,
                )),
                forward_resolution: ForwardResolution::Settled,
            }));
        }

        // Sort all events by timestamp so that we can replay them "live". Fail on any error because we expect all
        // htlcs to be able to replay through our bootstrapping network.
        //
        // TODO: queue?
        bootstrap_events.sort_by_key(|event| match event {
            BootstrapEvent::BootstrapAdd(htlc_add) => htlc_add.htlc.added_at,
            BootstrapEvent::BootstrapResolve(htlc_resolve) => htlc_resolve.resolved_ins,
        });

        // Data generation does not run the reputation algorithm, so it's possible that we'll hit a few htlcs that
        // can't be forwarded due to bucketing restrictions. This isn't critical, and we'll hit them deterministically
        // for each run so we can just log them and then skip resolving them.
        let mut skipped_htlcs = HashSet::new();
        for e in bootstrap_events {
            match e {
                BootstrapEvent::BootstrapAdd(htlc_add) => {
                    if let Err(e) = self.inner_add_htlc(htlc_add.clone()).await? {
                        skipped_htlcs.insert(htlc_add.htlc.incoming_ref);
                        log::error!("Routing failure for bootstrap: {e}");
                    }
                }
                BootstrapEvent::BootstrapResolve(htlc_resolve) => {
                    if !skipped_htlcs.remove(&htlc_resolve.incoming_htlc) {
                        self.inner_resolve_htlc(htlc_resolve).await?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Adds a htlc forward to the jamming interceptor, performing forwarding checks and returning the decided
    /// forwarding outcome for the htlc. Callers should fail if the outer result is an error, because an unexpected
    /// error has occurred.
    async fn inner_add_htlc(
        &self,
        htlc_add: HtlcAdd,
    ) -> InterceptResult{
        // If the forwarding node can't be found, we've hit a critical error and can't proceed.
        let (allocation_check, alias) = match self
            .network_nodes
            .lock()
            .unwrap()
            .entry(htlc_add.forwarding_node)
        {
            Entry::Occupied(mut e) => {
                let (node, alias) = e.get_mut();
                (node.add_outgoing_hltc(&htlc_add.htlc)?, alias.to_string())
            }
            Entry::Vacant(_) => {
                return Err(ReputationError::ErrUnrecoverable(format!(
                    "node not found: {}",
                    htlc_add.forwarding_node,
                )))
            }
        };

        // Once we have a forwarding decision, return successfully to the interceptor with the call.
        let fwd_decision = allocation_check.forwarding_outcome(
            htlc_add.htlc.amount_out_msat,
            htlc_add.htlc.incoming_endorsed,
        );

        log::info!(
            "Node {} forwarding: {} with outcome {}",
            alias,
            htlc_add.htlc,
            fwd_decision,
        );

        match fwd_decision {
            ForwardingOutcome::Forward(endorsement) => {
                Ok(Ok(records_from_endorsement(endorsement)))
            }
            ForwardingOutcome::Fail(reason) => Ok(Err(ForwardingError::InterceptorError(
                reason.to_string().into(),
            ))),
        }
    }

    /// Removes a htlc from the jamming interceptor, reporting its success/failure to the inner state machine.
    async fn inner_resolve_htlc(
        &self,
        resolved_htlc: HtlcResolve,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        log::info!(
            "Resolving htlc {}:{} on {} with outcome {}",
            resolved_htlc.incoming_htlc.channel_id,
            resolved_htlc.incoming_htlc.htlc_index,
            resolved_htlc.outgoing_channel_id,
            resolved_htlc.forward_resolution,
        );

        match self
            .network_nodes
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .entry(resolved_htlc.forwarding_node)
        {
            Entry::Occupied(mut e) => Ok(e.get_mut().0.resolve_htlc(
                resolved_htlc.outgoing_channel_id,
                resolved_htlc.incoming_htlc,
                resolved_htlc.forward_resolution,
                resolved_htlc.resolved_ins,
            )?),
            Entry::Vacant(_) => {
                Err(format!("Node: {} not found", resolved_htlc.forwarding_node).into())
            }
        }
    }
}

#[async_trait]
impl ReputationMonitor for ReputationInterceptor {
    /// Returns all reputation pairs for the node provided. For example, if a node has channels 1, 2 and 3 it will
    /// return the following reputation pairs: [1 -> 2], [1 -> 3], [2 -> 1], [2 -> 3], [3 -> 1], [3 -> 2].
    async fn list_reputation_pairs(
        &self,
        node: PublicKey,
        access_ins: Instant,
    ) -> Result<Vec<ReputationPair>, BoxError> {
        let reputations = self
            .network_nodes
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .get(&node)
            .ok_or(format!("node: {node} not found"))?
            .0
            .list_reputation(access_ins)?;

        let mut pairs = Vec::with_capacity(reputations.len() * (reputations.len() - 1));
        for (incoming_scid, snapshot_incoming) in reputations.iter() {
            for (outgoing_scid, snapshot_outgoing) in reputations.iter() {
                if incoming_scid == outgoing_scid {
                    continue;
                }

                pairs.push(ReputationPair {
                    incoming_scid: *incoming_scid,
                    outgoing_scid: *outgoing_scid,
                    incoming_revenue: snapshot_incoming.incoming_revenue,
                    outgoing_reputation: snapshot_outgoing.outgoing_reputation,
                })
            }
        }

        Ok(pairs)
    }

    /// Checks the forwarding decision for a htlc without adding it to internal state.
    async fn check_htlc_outcome(
        &self,
        htlc_add: HtlcAdd,
    ) -> Result<AllocationCheck, ReputationError> {
        match self
            .network_nodes
            .lock()
            .unwrap()
            .entry(htlc_add.forwarding_node)
        {
            Entry::Occupied(e) => e.get().0.get_forwarding_outcome(&htlc_add.htlc),
            Entry::Vacant(_) => Err(ReputationError::ErrUnrecoverable(format!(
                "node not found: {}",
                htlc_add.forwarding_node,
            ))),
        }
    }
}

#[async_trait]
impl Interceptor for ReputationInterceptor {
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        // Only intercept htlcs which are being forwarded, if it's a receive (no outgoing) then we'll just send the
        // okay straight to the interceptor.
        let htlc = match HtlcAdd::from_request(&req, self.clock.now()) {
            Some(h) => h,
            None => {
                if let Err(e) = req
                    .response
                    .send(Ok(Ok(records_from_endorsement(
                        EndorsementSignal::Unendorsed,
                    ))))
                    .await
                {
                    log::error!("Could not send response to interceptor: {e}");
                    self.shutdown.trigger();
                }
                return;
            }
        };

        let resp = self.inner_add_htlc(htlc).await.map_err(|e| e.into());

        if let Err(e) = req.response.send(resp).await {
            log::error!("Failed to send response: {:?}", e);
            self.shutdown.trigger();
        }
    }

    async fn notify_resolution(
        &self,
        res: InterceptResolution,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        // If there's not outgoing channel, we're notifying on the receiving node which doesn't need any action.
        let outgoing_channel_id = match res.outgoing_channel_id {
            Some(c) => c.into(),
            None => return Ok(()),
        };

        self.inner_resolve_htlc(HtlcResolve {
            outgoing_channel_id,
            forwarding_node: res.forwarding_node,
            incoming_htlc: HtlcRef {
                channel_id: res.incoming_htlc.channel_id.into(),
                htlc_index: res.incoming_htlc.index,
            },
            forward_resolution: ForwardResolution::from(res.success),
            resolved_ins: self.clock.now(),
        })
        .await
    }

    /// Returns an identifying name for the interceptor for logging, does not need to be unique.
    fn name(&self) -> String {
        "channel jammer".to_string()
    }
}
