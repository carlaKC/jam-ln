use crate::analysis::ForwardReporter;
use crate::clock::InstantClock;
use crate::{endorsement_from_records, records_from_endorsement, BoxError};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::forward_manager::{
    ForwardManager, ForwardManagerParams, SimualtionDebugManager,
};
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

pub struct BoostrapRecords {
    pub forwards: Vec<BootstrapForward>,
    pub last_timestamp_nanos: u64,
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

struct Node<M>
where
    M: ReputationManager,
{
    forward_manager: M,
    alias: String,
}

impl<M> Node<M>
where
    M: ReputationManager,
{
    fn new(forward_manager: M, alias: String) -> Self {
        Node {
            forward_manager,
            alias,
        }
    }
}

/// Implements a network-wide interceptor that implements resource management for every forwarding node in the
/// network.
#[derive(Clone)]
pub struct ReputationInterceptor<R, M>
where
    R: ForwardReporter,
    M: ReputationManager,
{
    network_nodes: Arc<Mutex<HashMap<PublicKey, Node<M>>>>,
    clock: Arc<dyn InstantClock + Send + Sync>,
    results: Option<Arc<Mutex<R>>>,
    shutdown: Trigger,
}

impl<R> ReputationInterceptor<R, ForwardManager>
where
    R: ForwardReporter,
{
    pub fn new_for_network(
        params: ForwardManagerParams,
        edges: &[NetworkParser],
        clock: Arc<dyn InstantClock + Send + Sync>,
        results: Option<Arc<Mutex<R>>>,
        shutdown: Trigger,
    ) -> Result<Self, BoxError> {
        let mut network_nodes: HashMap<PublicKey, Node<ForwardManager>> = HashMap::new();

        macro_rules! add_node_to_network {
            ($network_nodes:expr, $node_pubkey:expr, $node_alias:expr, $channel:expr) => {
                match $network_nodes.entry($node_pubkey) {
                    Entry::Vacant(e) => {
                        let forward_manager = ForwardManager::new(params);

                        let _ = forward_manager.add_channel(
                            $channel.scid.into(),
                            $channel.capacity_msat,
                            clock.now(),
                        )?;

                        e.insert(Node::new(forward_manager, $node_alias));
                    }
                    Entry::Occupied(mut e) => {
                        let _ = e.get_mut().forward_manager.add_channel(
                            $channel.scid.into(),
                            $channel.capacity_msat,
                            clock.now(),
                        )?;
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
            results,
            shutdown,
        })
    }

    /// Creates a network from the set of edges provided and bootstraps the reputation of nodes in the network using
    /// the historical forwards provided. Forwards are expected to be sorted by added_ns in ascending order.
    pub async fn new_with_bootstrap(
        params: ForwardManagerParams,
        edges: &[NetworkParser],
        general_jammed: &[(u64, PublicKey)],
        bootstrap: &BoostrapRecords,
        clock: Arc<dyn InstantClock + Send + Sync>,
        results: Option<Arc<Mutex<R>>>,
        shutdown: Trigger,
    ) -> Result<Self, BoxError> {
        let mut interceptor = Self::new_for_network(params, edges, clock, results, shutdown)
            .map_err(|_| "could not create network")?;
        interceptor.bootstrap_network_history(bootstrap).await?;

        // After the network has been bootstrapped, we can go ahead and general jam required channels.
        for (channel, pubkey) in general_jammed.iter() {
            interceptor
                .network_nodes
                .lock()
                .map_err(|e| format!("mutex err: {e}"))?
                .get_mut(pubkey)
                .ok_or(format!("jammed node: {} not found", pubkey))?
                .forward_manager
                .general_jam_channel(*channel)?;
        }

        Ok(interceptor)
    }

    async fn bootstrap_network_history(
        &mut self,
        bootstrap: &BoostrapRecords,
    ) -> Result<(), BoxError> {
        // We'll get all instants relative to the last timestamp we're given, so we get an instant now and track
        // the last timestamp in the set of forwards.
        let start_ins = self.clock.now();

        // Run through history and create instants relative to the current time, we'll have two events per forward
        // so we can allocate accordingly.
        let mut bootstrap_events = Vec::with_capacity(bootstrap.forwards.len() * 2);
        for (i, h) in bootstrap.forwards.iter().enumerate() {
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
                        bootstrap
                            .last_timestamp_nanos
                            .checked_sub(h.added_ns)
                            .ok_or(format!(
                                "added ts: {} > last ts: {}",
                                bootstrap.last_timestamp_nanos, h.added_ns
                            ))?,
                    )),
                    incoming_endorsed: EndorsementSignal::Unendorsed,
                },
            }));

            bootstrap_events.push(BootstrapEvent::BootstrapResolve(HtlcResolve {
                outgoing_channel_id: h.channel_out_id,
                forwarding_node: h.forwarding_node,
                incoming_htlc: incoming_ref,
                resolved_ins: start_ins.sub(Duration::from_nanos(
                    bootstrap
                        .last_timestamp_nanos
                        .checked_sub(h.settled_ns)
                        .ok_or(format!(
                            "settled ts: {} > last ts: {}",
                            bootstrap.last_timestamp_nanos, h.settled_ns
                        ))?,
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
                    // Add to internal state but don't write to results.
                    if let Err(e) = self.inner_add_htlc(htlc_add.clone(), false).await? {
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
}

impl<R, M> ReputationInterceptor<R, M>
where
    R: ForwardReporter,
    M: ReputationManager,
{
    /// Adds a htlc forward to the jamming interceptor, performing forwarding checks and returning the decided
    /// forwarding outcome for the htlc. Callers should fail if the outer result is an error, because an unexpected
    /// error has occurred.
    async fn inner_add_htlc(
        &self,
        htlc_add: HtlcAdd,
        report: bool,
    ) -> Result<Result<HashMap<u64, Vec<u8>>, ForwardingError>, ReputationError> {
        // If the forwarding node can't be found, we've hit a critical error and can't proceed.
        let (allocation_check, alias) = match self
            .network_nodes
            .lock()
            .unwrap()
            .entry(htlc_add.forwarding_node)
        {
            Entry::Occupied(mut e) => {
                let node = e.get_mut();
                (
                    node.forward_manager.add_htlc(&htlc_add.htlc)?,
                    node.alias.to_string(),
                )
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

        if let Some(r) = &self.results {
            if report {
                r.lock()
                    .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
                    .report_forward(
                        htlc_add.forwarding_node,
                        allocation_check,
                        htlc_add.htlc.clone(),
                    )
                    .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;
            }
        }

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
            Entry::Occupied(mut e) => Ok(e.get_mut().forward_manager.resolve_htlc(
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
impl<R, M> ReputationMonitor for ReputationInterceptor<R, M>
where
    R: ForwardReporter,
    M: ReputationManager + Send,
{
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
            .forward_manager
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
            Entry::Occupied(e) => e
                .get()
                .forward_manager
                .get_forwarding_outcome(&htlc_add.htlc),
            Entry::Vacant(_) => Err(ReputationError::ErrUnrecoverable(format!(
                "node not found: {}",
                htlc_add.forwarding_node,
            ))),
        }
    }
}

#[async_trait]
impl<R, M> Interceptor for ReputationInterceptor<R, M>
where
    R: ForwardReporter,
    M: ReputationManager + Send + Sync,
{
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        // If the intercept has no outgoing channel, we can just exit early because there's no action to be taken.
        let outgoing_channel_id = match req.outgoing_channel_id {
            Some(c) => c.into(),
            None => {
                if let Err(e) = req
                    .response
                    .send(Ok(Ok(records_from_endorsement(
                        EndorsementSignal::Unendorsed,
                    ))))
                    .await
                {
                    log::error!("Failed to send response: {:?}", e);
                    self.shutdown.trigger();
                }
                return;
            }
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
            added_at: self.clock.now(),
            incoming_endorsed: endorsement_from_records(&req.incoming_custom_records),
        };

        let resp = self
            .inner_add_htlc(
                HtlcAdd {
                    forwarding_node: req.forwarding_node,
                    htlc,
                },
                true,
            )
            .await
            .map_err(|e| e.into()); // into maps error enum to erased Box<dyn Error>

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

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use ln_resource_mgr::forward_manager::{ForwardManager, ForwardManagerParams};
    use ln_resource_mgr::{
        AllocationCheck, EndorsementSignal, ForwardResolution, HtlcRef, ProposedForward,
        ReputationError, ReputationManager, ReputationParams, ReputationSnapshot,
    };
    use mockall::mock;
    use simln_lib::clock::SimulationClock;
    use simln_lib::sim_node::{ChannelPolicy, ForwardingError, InterceptResolution, Interceptor};
    use simln_lib::{NetworkParser, ShortChannelID};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::time::Instant;

    use crate::analysis::BatchForwardWriter;
    use crate::endorsement_from_records;
    use crate::reputation_interceptor::{BoostrapRecords, BootstrapForward};
    use crate::test_utils::{get_random_keypair, setup_test_request, test_allocation_check};

    use super::{Node, ReputationInterceptor, ReputationMonitor};

    mock! {
        ForwardManager{}

        #[async_trait]
        impl ReputationManager for ForwardManager{
            fn add_channel(
                &self,
                channel_id: u64,
                capacity_msat: u64,
                add_ins: Instant,
            ) -> Result<(), ln_resource_mgr::ReputationError>;

            fn remove_channel(&self, channel_id: u64) -> Result<(), ReputationError>;

            fn get_forwarding_outcome(
                &self,
                forward: &ProposedForward,
            ) -> Result<AllocationCheck, ReputationError>;

            fn add_htlc(
                &self,
                forward: &ProposedForward
            ) -> Result<AllocationCheck, ReputationError>;
            fn resolve_htlc(
                &self,
                outgoing_channel: u64,
                incoming_ref: HtlcRef,
                resolution: ForwardResolution,
                resolved_instant: Instant
            ) -> Result<(), ReputationError>;

            fn list_reputation(
                &self,
                access_ins: Instant
            ) -> Result<HashMap<u64, ReputationSnapshot>, ReputationError>;
        }
    }

    /// Creates a test interceptor with three nodes in the network and a vector of their public keys.
    fn setup_test_interceptor() -> (
        ReputationInterceptor<BatchForwardWriter, MockForwardManager>,
        Vec<PublicKey>,
    ) {
        let (shutdown, _) = triggered::trigger();
        let pubkeys = vec![
            get_random_keypair().1,
            get_random_keypair().1,
            get_random_keypair().1,
        ];

        let nodes = HashMap::from([
            (
                pubkeys[0],
                Node {
                    forward_manager: MockForwardManager::new(),
                    alias: "0".to_string(),
                },
            ),
            (
                pubkeys[1],
                Node {
                    forward_manager: MockForwardManager::new(),
                    alias: "1".to_string(),
                },
            ),
            (
                pubkeys[2],
                Node {
                    forward_manager: MockForwardManager::new(),
                    alias: "2".to_string(),
                },
            ),
        ]);

        (
            ReputationInterceptor {
                network_nodes: Arc::new(Mutex::new(nodes)),
                clock: Arc::new(SimulationClock::new(1).unwrap()),
                results: None,
                shutdown,
            },
            pubkeys,
        )
    }

    /// Tests that we do not intercept when the forwarding node is the recipient.
    #[tokio::test]
    async fn test_final_hop_intercept() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let (mut request, mut receiver) =
            setup_test_request(pubkeys[0], 0, 1, EndorsementSignal::Unendorsed);

        request.outgoing_channel_id = None;
        interceptor.intercept_htlc(request).await;

        assert!(matches!(
            endorsement_from_records(&receiver.recv().await.unwrap().unwrap().unwrap()),
            EndorsementSignal::Unendorsed
        ));
    }

    /// Tests failure if a forward from an unknown node is intercepted.
    #[tokio::test]
    async fn test_unknown_intercept_node() {
        let (interceptor, _) = setup_test_interceptor();
        let (request, mut receiver) =
            setup_test_request(get_random_keypair().1, 0, 1, EndorsementSignal::Unendorsed);

        interceptor.intercept_htlc(request).await;

        assert!(matches!(
            receiver
                .recv()
                .await
                .unwrap()
                .err()
                .unwrap()
                .downcast_ref::<ReputationError>()
                .unwrap(),
            ReputationError::ErrUnrecoverable(_),
        ));
    }

    /// Tests interception of a htlc that should be forwarded as endorsed.
    #[tokio::test]
    async fn test_forward_endorsed_htlc() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let (request, mut receiver) =
            setup_test_request(pubkeys[0], 0, 1, EndorsementSignal::Endorsed);

        interceptor
            .network_nodes
            .lock()
            .unwrap()
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_add_htlc()
            .return_once(|_| Ok(test_allocation_check(true)));

        interceptor.intercept_htlc(request).await;

        // should call add_htlc + return a reputation check that passes
        assert!(matches!(
            endorsement_from_records(&receiver.recv().await.unwrap().unwrap().unwrap()),
            EndorsementSignal::Endorsed
        ));
    }

    /// Tests interception of a htlc that should be forwarded as unendorsed.
    #[tokio::test]
    async fn test_forward_unendorsed_htlc() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let (request, mut receiver) =
            setup_test_request(pubkeys[0], 0, 1, EndorsementSignal::Unendorsed);

        interceptor
            .network_nodes
            .lock()
            .unwrap()
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_add_htlc()
            .return_once(|_| Ok(test_allocation_check(false)));

        interceptor.intercept_htlc(request).await;

        // should call add_htlc + return a reputation check that passes
        assert!(matches!(
            endorsement_from_records(&receiver.recv().await.unwrap().unwrap().unwrap()),
            EndorsementSignal::Unendorsed
        ));
    }

    /// Tests that we do not notify resolution of last hop htlcs.
    #[tokio::test]
    async fn test_final_hop_notify() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let (mut request, _) = setup_test_request(pubkeys[0], 0, 1, EndorsementSignal::Unendorsed);

        request.outgoing_channel_id = None;
        interceptor
            .notify_resolution(InterceptResolution {
                forwarding_node: pubkeys[0],
                incoming_htlc: simln_lib::sim_node::HtlcRef {
                    channel_id: ShortChannelID::from(0),
                    index: 0,
                },
                outgoing_channel_id: None,
                success: true,
            })
            .await
            .unwrap();
    }

    /// Tests that we error on notification of a resolution on an unknown node.
    #[tokio::test]
    async fn test_unknown_node_notify() {
        let (interceptor, _) = setup_test_interceptor();

        assert!(interceptor
            .notify_resolution(InterceptResolution {
                forwarding_node: get_random_keypair().1,
                incoming_htlc: simln_lib::sim_node::HtlcRef {
                    channel_id: ShortChannelID::from(0),
                    index: 0,
                },
                outgoing_channel_id: Some(ShortChannelID::from(1)),
                success: true,
            })
            .await
            .is_err());
    }

    /// Tests successful removal of a htlc from the reputation interceptor.
    #[tokio::test]
    async fn test_successful_notify() {
        let (interceptor, pubkeys) = setup_test_interceptor();

        interceptor
            .network_nodes
            .lock()
            .unwrap()
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_resolve_htlc()
            .return_once(|_, _, _, _| Ok(()));
    }

    fn setup_test_policy(node: PublicKey) -> ChannelPolicy {
        ChannelPolicy {
            pubkey: node,
            alias: "".to_string(),
            max_htlc_count: 483,
            max_in_flight_msat: 100_000,
            min_htlc_size_msat: 1,
            max_htlc_size_msat: 100_000,
            cltv_expiry_delta: 40,
            base_fee: 1000,
            fee_rate_prop: 2000,
        }
    }

    fn setup_test_edge(
        scid: ShortChannelID,
        node_1: PublicKey,
        node_2: PublicKey,
    ) -> NetworkParser {
        NetworkParser {
            scid,
            capacity_msat: 100_000,
            node_1: setup_test_policy(node_1),
            node_2: setup_test_policy(node_2),
            forward_only: false,
        }
    }

    /// Creates a reputation interceptor for a three hop network: Alice - Bob - Carol.
    fn setup_three_hop_network_edges() -> (ForwardManagerParams, Vec<NetworkParser>) {
        // Create a network with three channels
        let alice = get_random_keypair().1;
        let bob = get_random_keypair().1;
        let carol = get_random_keypair().1;

        let alice_bob = ShortChannelID::from(1);
        let bob_carol = ShortChannelID::from(2);

        let params = ForwardManagerParams {
            reputation_params: ReputationParams {
                revenue_window: Duration::from_secs(60),
                reputation_multiplier: 60,
                resolution_period: Duration::from_secs(90),
                expected_block_speed: None,
            },
            general_slot_portion: 30,
            general_liquidity_portion: 30,
            congestion_slot_portion: 20,
            congestion_liquidity_portion: 20,
        };

        let edges = vec![
            setup_test_edge(alice_bob, alice, bob),
            setup_test_edge(bob_carol, bob, carol),
        ];

        (params, edges)
    }

    /// Tests that nodes are appropriately set up when an interceptor is created from a set of edges.
    #[tokio::test]
    async fn test_new_for_network_node_creation() {
        let (shutdown, _) = triggered::trigger();
        let (params, edges) = setup_three_hop_network_edges();

        let interceptor: ReputationInterceptor<BatchForwardWriter, ForwardManager> =
            ReputationInterceptor::new_for_network(
                params,
                &edges,
                Arc::new(SimulationClock::new(1).unwrap()),
                None,
                shutdown,
            )
            .unwrap();

        // Alice has one channel, so will not have any reputation pairs.
        assert_eq!(
            interceptor
                .list_reputation_pairs(edges[0].node_1.pubkey, Instant::now())
                .await
                .unwrap()
                .len(),
            0
        );

        // Bob has two channels, so will have two pairs (one for each direction).
        assert_eq!(edges[0].node_2.pubkey, edges[1].node_1.pubkey);
        let bob_edges = interceptor
            .list_reputation_pairs(edges[1].node_1.pubkey, Instant::now())
            .await
            .unwrap();
        assert_eq!(bob_edges.len(), 2);

        // Assert that the pairs are for the two channels we expect.
        assert!(bob_edges.iter().all(|pair| {
            (pair.incoming_scid == edges[0].scid.into()
                || pair.incoming_scid == edges[1].scid.into())
                && (pair.outgoing_scid == edges[0].scid.into()
                    || pair.outgoing_scid == edges[1].scid.into())
        }));

        // Carol has one channel, so will not have any reputation pairs.
        assert_eq!(
            interceptor
                .list_reputation_pairs(edges[1].node_2.pubkey, Instant::now())
                .await
                .unwrap()
                .len(),
            0
        );
    }

    /// Tests that nodes marked to be general jammed appropriately have their general resources slashed, but are still
    /// able to bootstrap reputation.
    #[tokio::test]
    async fn test_bootstrap_and_general_jam() {
        let (shutdown, _) = triggered::trigger();
        let (params, edges) = setup_three_hop_network_edges();

        let bob_pk = edges[0].node_2.pubkey;
        let alice_to_bob: u64 = edges[0].scid.into();
        let bob_to_carol: u64 = edges[1].scid.into();

        // Create a bootstraped forward that'll be forwarded over the general jammed channel.
        let boostrap = vec![BootstrapForward {
            incoming_amt: 1000,
            outgoing_amt: 500,
            incoming_expiry: 100,
            outgoing_expiry: 50,
            added_ns: 900_000,
            settled_ns: 1_000_000,
            forwarding_node: bob_pk,
            channel_in_id: alice_to_bob,
            channel_out_id: bob_to_carol,
        }];

        // Create an interceptor that is intended to general jam payments on Bob -> Carol in the three hop network
        // Alice -> Bob -> Carol.
        let interceptor: ReputationInterceptor<BatchForwardWriter, ForwardManager> =
            ReputationInterceptor::new_with_bootstrap(
                params,
                &edges,
                &[(bob_to_carol, edges[1].node_1.pubkey)],
                &BoostrapRecords {
                    forwards: boostrap,
                    last_timestamp_nanos: 1_000_000,
                },
                Arc::new(SimulationClock::new(1).unwrap()),
                None,
                shutdown,
            )
            .await
            .unwrap();

        let bob_reputation = interceptor
            .network_nodes
            .lock()
            .unwrap()
            .get(&bob_pk)
            .unwrap()
            .forward_manager
            .list_reputation(Instant::now())
            .unwrap();

        assert!(bob_reputation.get(&alice_to_bob).unwrap().incoming_revenue != 0);
        assert!(
            bob_reputation
                .get(&bob_to_carol)
                .unwrap()
                .outgoing_reputation
                != 0
        );

        // An unendorsed payment in the non-jammed direction should be forwarded through unendorsed.
        let (request, mut receiver) = setup_test_request(
            edges[1].node_1.pubkey,
            bob_to_carol,
            alice_to_bob,
            EndorsementSignal::Unendorsed,
        );

        interceptor.intercept_htlc(request).await;
        assert!(matches!(
            endorsement_from_records(&receiver.recv().await.unwrap().unwrap().unwrap()),
            EndorsementSignal::Unendorsed,
        ));

        // An unendorsed htlc using the jammed channel should be failed because there are no resources.
        let (request, mut receiver) = setup_test_request(
            edges[1].node_1.pubkey,
            alice_to_bob,
            bob_to_carol,
            EndorsementSignal::Unendorsed,
        );

        interceptor.intercept_htlc(request).await;
        assert!(matches!(
            receiver.recv().await.unwrap().unwrap().err().unwrap(),
            ForwardingError::InterceptorError(_),
        ));
    }
}
