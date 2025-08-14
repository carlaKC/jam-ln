use crate::analysis::ForwardReporter;
use crate::clock::InstantClock;
use crate::{accountable_from_records, records_from_signal, upgradable_from_records, BoxError};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::forward_manager::{
    ForwardManager, ForwardManagerParams, SimulationDebugManager,
};
use ln_resource_mgr::{
    AccountableSignal, ChannelSnapshot, ForwardResolution, ForwardingOutcome, HtlcRef,
    ProposedForward, ReputationError, ReputationManager,
};
use serde::{Deserialize, Serialize};
use sim_cli::parsing::NetworkParser;
use simln_lib::sim_node::{
    CriticalError, CustomRecords, ForwardingError, InterceptRequest, InterceptResolution,
    Interceptor,
};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ops::Sub;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct HtlcAdd {
    pub forwarding_node: PublicKey,
    pub incoming_ref: HtlcRef,
    pub outgoing_channel_id: u64,
    pub amount_in_msat: u64,
    pub amount_out_msat: u64,
    pub expiry_in_height: u32,
    pub expiry_out_height: u32,
    pub incoming_accountable: AccountableSignal,
    pub upgradable_accountability: bool,
    /// Optional timestamp for the case where htlcs with existing timestamps are being replayed.
    /// Should be None otherwise.
    pub added_at: Option<Instant>,
}

struct HtlcResolve {
    outgoing_channel_id: u64,
    forwarding_node: PublicKey,
    incoming_htlc: HtlcRef,
    forward_resolution: ForwardResolution,
    /// Optional timestamp for the case where htlcs with existing timestamps are being replayed.
    /// Should be None otherwise.
    resolved_ins: Option<Instant>,
}

enum BootstrapEvent {
    BootstrapAdd(HtlcAdd),
    BootstrapResolve(HtlcResolve),
}

pub struct BootstrapRecords {
    pub forwards: Vec<BootstrapForward>,
    pub last_timestamp_nanos: u64,
}

/// Provides details of a htlc forward that is used to bootstrap reputation values for the network.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

/// Functionality to monitor reputation values in a network.
#[async_trait]
pub trait ReputationMonitor {
    /// Returns a snapshot of the state tracked for each of a node's channels at the instant provided.
    ///
    /// Note that this data tracks all reputation-related values for an individual channel. To create the pair that is
    /// used to assess reputation, two different channels must be cross-referenced.
    async fn list_channels(
        &self,
        node: PublicKey,
        access_ins: Instant,
    ) -> Result<HashMap<u64, ChannelSnapshot>, BoxError>;
}

struct Node<M>
where
    M: ReputationManager + SimulationDebugManager,
{
    forward_manager: M,
    alias: String,
}

impl<M> Node<M>
where
    M: ReputationManager + SimulationDebugManager,
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
pub struct ReputationInterceptor<R, M, C>
where
    R: ForwardReporter,
    M: ReputationManager + SimulationDebugManager,
    C: InstantClock + Send + Sync,
{
    network_nodes: Arc<Mutex<HashMap<PublicKey, Node<M>>>>,
    clock: Arc<C>,
    results: Option<Arc<Mutex<R>>>,
}

impl<R, C> ReputationInterceptor<R, ForwardManager, C>
where
    R: ForwardReporter,
    C: InstantClock + Send + Sync,
{
    pub fn new_for_network(
        params: ForwardManagerParams,
        edges: &[NetworkParser],
        clock: Arc<C>,
        results: Option<Arc<Mutex<R>>>,
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
                            None,
                        )?;

                        e.insert(Node::new(forward_manager, $node_alias));
                    }
                    Entry::Occupied(mut e) => {
                        let _ = e.get_mut().forward_manager.add_channel(
                            $channel.scid.into(),
                            $channel.capacity_msat,
                            clock.now(),
                            None,
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
        })
    }

    pub async fn new_from_snapshot(
        params: ForwardManagerParams,
        edges: &[NetworkParser],
        reputation_snapshot: HashMap<PublicKey, HashMap<u64, ChannelSnapshot>>,
        no_reputation: HashSet<PublicKey>,
        clock: Arc<C>,
        results: Option<Arc<Mutex<R>>>,
    ) -> Result<Self, BoxError> {
        let mut network_nodes = HashMap::with_capacity(reputation_snapshot.len());

        let add_ins = clock.now();
        macro_rules! add_node_to_network {
            ($channel:expr, $node:tt, $counterparty:tt) => {{
                let scid = $channel.scid.into();
                let pubkey = $channel.$node.pubkey;
                let alias = $channel.$node.alias.clone();

                let node_snapshot = reputation_snapshot
                    .get(&pubkey);
                let should_have_snapshot = no_reputation.get(&pubkey).is_none();

                if node_snapshot.is_some() != should_have_snapshot {
                    return Err(format!("node: {pubkey} should have snapshot: {should_have_snapshot}, has snapshot: {}",
                        node_snapshot.is_some()).into());
                }

                let snapshot = match node_snapshot {
                    Some(s) => {
                        // If our counterparty isn't expected to have a snapshot of its reputation,
                        // then any channel with the counterparty also isn't tracked.
                        if no_reputation.get(&$channel.$counterparty.pubkey).is_some() {
                            None
                        } else {
                            let snapshot = s.get(&scid).ok_or(
                                format!("channel:{} not found in snapshot for node: {}", scid, pubkey))?;

                            if snapshot.capacity_msat != $channel.capacity_msat {
                                return Err(format!("channel {} has different capacities {} - {}",
                                    scid, snapshot.capacity_msat, $channel.capacity_msat).into())
                            }
                            Some(snapshot.clone())
                        }
                    },
                    None => None,
                };

                match network_nodes.entry(pubkey) {
                    Entry::Vacant(e) => {
                        let forward_manager = ForwardManager::new(params);
                        forward_manager.add_channel(
                            scid,
                            $channel.capacity_msat,
                            add_ins,
                            snapshot,
                        )?;
                        e.insert(Node::new(forward_manager, alias));
                    }
                    Entry::Occupied(mut e) => {
                        e.get_mut().forward_manager.add_channel(
                            scid,
                            $channel.capacity_msat,
                            add_ins,
                            snapshot,
                        )?;
                    }
                }
            }};
        }

        for channel in edges {
            add_node_to_network!(channel, node_1, node_2);
            add_node_to_network!(channel, node_2, node_1);
        }

        Ok(Self {
            network_nodes: Arc::new(Mutex::new(network_nodes)),
            clock,
            results,
        })
    }

    /// Bootstraps the reputation of nodes in the interceptor network using the historical forwards provided.
    pub async fn bootstrap_network_history(
        &mut self,
        bootstrap: &BootstrapRecords,
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
                incoming_ref,
                outgoing_channel_id: h.channel_out_id,
                amount_in_msat: h.incoming_amt,
                amount_out_msat: h.outgoing_amt,
                expiry_in_height: h.incoming_expiry,
                expiry_out_height: h.outgoing_expiry,
                added_at: Some(
                    start_ins.sub(Duration::from_nanos(
                        bootstrap
                            .last_timestamp_nanos
                            .checked_sub(h.added_ns)
                            .ok_or(format!(
                                "added ts: {} > last ts: {}",
                                bootstrap.last_timestamp_nanos, h.added_ns
                            ))?,
                    )),
                ),
                incoming_accountable: AccountableSignal::Unaccountable,
                upgradable_accountability: true,
            }));

            bootstrap_events.push(BootstrapEvent::BootstrapResolve(HtlcResolve {
                outgoing_channel_id: h.channel_out_id,
                forwarding_node: h.forwarding_node,
                incoming_htlc: incoming_ref,
                resolved_ins: Some(
                    start_ins.sub(Duration::from_nanos(
                        bootstrap
                            .last_timestamp_nanos
                            .checked_sub(h.settled_ns)
                            .ok_or(format!(
                                "settled ts: {} > last ts: {}",
                                bootstrap.last_timestamp_nanos, h.settled_ns
                            ))?,
                    )),
                ),
                forward_resolution: ForwardResolution::Settled,
            }));
        }

        // Sort all events by timestamp so that we can replay them "live". Fail on any error because we expect all
        // htlcs to be able to replay through our bootstrapping network.
        //
        // TODO: queue?
        bootstrap_events.sort_by_key(|event| match event {
            // We know that the instants here must be Some, as we've just set it above so it's
            // okay to unwrap here.
            BootstrapEvent::BootstrapAdd(htlc_add) => htlc_add.added_at.unwrap(),
            BootstrapEvent::BootstrapResolve(htlc_resolve) => htlc_resolve.resolved_ins.unwrap(),
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
                        skipped_htlcs.insert(htlc_add.incoming_ref);
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

/// Simulation-specific helper trait for jamming resources on a channel in a specific direction.
///
/// The `pubkey` specifies the direction of the jamming operation. For a channel between nodes A
/// and B with channel ID 999:
/// - Passing `&A, 999` will jam resources in the B → A direction.
/// - Passing `&B, 999` will jam resources in the A → B direction.
#[async_trait]
pub trait ChannelJammer {
    /// Jam the general resources of the specified channel in the given direction.
    async fn jam_general_resources(&self, pubkey: &PublicKey, channel: u64)
        -> Result<(), BoxError>;

    /// Jam the congestion resources of the specified channel in the given direction.
    async fn jam_congestion_resources(
        &self,
        pubkey: &PublicKey,
        channel: u64,
    ) -> Result<(), BoxError>;
}

#[async_trait]
impl<R, M, C> ChannelJammer for ReputationInterceptor<R, M, C>
where
    R: ForwardReporter,
    M: ReputationManager + SimulationDebugManager + Send,
    C: InstantClock + Send + Sync,
{
    async fn jam_general_resources(
        &self,
        pubkey: &PublicKey,
        channel: u64,
    ) -> Result<(), BoxError> {
        self.network_nodes
            .lock()
            .await
            .get_mut(pubkey)
            .ok_or(format!("jammed node: {} not found", pubkey))?
            .forward_manager
            .general_jam_channel(channel)
            .map_err(|e| e.into())
    }

    async fn jam_congestion_resources(
        &self,
        pubkey: &PublicKey,
        channel: u64,
    ) -> Result<(), BoxError> {
        self.network_nodes
            .lock()
            .await
            .get_mut(pubkey)
            .ok_or(format!("jammed node: {} not found", pubkey))?
            .forward_manager
            .congestion_jam_channel(channel)
            .map_err(|e| e.into())
    }
}

impl<R, M, C> ReputationInterceptor<R, M, C>
where
    R: ForwardReporter,
    M: ReputationManager + SimulationDebugManager,
    C: InstantClock + Send + Sync,
{
    /// Adds a htlc forward to the jamming interceptor, performing forwarding checks and returning the decided
    /// forwarding outcome for the htlc. Callers should fail if the outer result is an error, because an unexpected
    /// error has occurred.
    async fn inner_add_htlc(
        &self,
        htlc_add: HtlcAdd,
        report: bool,
    ) -> Result<Result<CustomRecords, ForwardingError>, ReputationError> {
        // We want our main lock to be held when we get our timestamp, so it doesn't drift too much.
        let mut network_lock = self.network_nodes.lock().await;
        let htlc = ProposedForward {
            incoming_ref: htlc_add.incoming_ref,
            outgoing_channel_id: htlc_add.outgoing_channel_id,
            amount_in_msat: htlc_add.amount_in_msat,
            amount_out_msat: htlc_add.amount_out_msat,
            expiry_in_height: htlc_add.expiry_in_height,
            expiry_out_height: htlc_add.expiry_out_height,
            added_at: htlc_add.added_at.unwrap_or(self.clock.now()),
            incoming_accountable: htlc_add.incoming_accountable,
            upgradable_accountability: htlc_add.upgradable_accountability,
        };

        // If the forwarding node can't be found, we've hit a critical error and can't proceed.
        let (allocation_check, fwd_outcome, alias) =
            match network_lock.entry(htlc_add.forwarding_node) {
                Entry::Occupied(mut e) => {
                    let node = e.get_mut();
                    (
                        node.forward_manager.get_allocation_snapshot(&htlc)?,
                        node.forward_manager.add_htlc(&htlc)?,
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
        drop(network_lock);

        if let Some(r) = &self.results {
            if report {
                r.lock()
                    .await
                    .report_forward(htlc_add.forwarding_node, allocation_check, htlc.clone())
                    .await
                    .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;
            }
        }

        log::info!(
            "Node {} forwarding: {} with outcome {}",
            alias,
            htlc,
            fwd_outcome,
        );

        match fwd_outcome {
            ForwardingOutcome::Forward(accountable_signal) => {
                Ok(Ok(records_from_signal(accountable_signal)))
            }
            ForwardingOutcome::Fail(reason) => {
                Ok(Err(ForwardingError::InterceptorError(reason.to_string())))
            }
        }
    }

    /// Removes a htlc from the jamming interceptor, reporting its success/failure to the inner state machine.
    async fn inner_resolve_htlc(&self, resolved_htlc: HtlcResolve) -> Result<(), ReputationError> {
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
            .await
            .entry(resolved_htlc.forwarding_node)
        {
            Entry::Occupied(mut e) => Ok(e.get_mut().forward_manager.resolve_htlc(
                resolved_htlc.outgoing_channel_id,
                resolved_htlc.incoming_htlc,
                resolved_htlc.forward_resolution,
                resolved_htlc.resolved_ins.unwrap_or(self.clock.now()),
            )?),
            Entry::Vacant(_) => Err(ReputationError::ErrUnrecoverable(format!(
                "Node: {} not found",
                resolved_htlc.forwarding_node
            ))),
        }
    }
}

#[async_trait]
impl<R, M, C> ReputationMonitor for ReputationInterceptor<R, M, C>
where
    R: ForwardReporter,
    M: ReputationManager + Send + SimulationDebugManager,
    C: InstantClock + Send + Sync,
{
    async fn list_channels(
        &self,
        node: PublicKey,
        access_ins: Instant,
    ) -> Result<HashMap<u64, ChannelSnapshot>, BoxError> {
        self.network_nodes
            .lock()
            .await
            .get(&node)
            .ok_or(format!("node: {node} not found"))?
            .forward_manager
            .list_channels(access_ins)
            .map_err(|e| e.into())
    }
}

#[async_trait]
impl<R, M, C> Interceptor for ReputationInterceptor<R, M, C>
where
    R: ForwardReporter,
    M: ReputationManager + Send + Sync + SimulationDebugManager,
    C: InstantClock + Send + Sync,
{
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, CriticalError> {
        // If the intercept has no outgoing channel, we can just exit early because there's no action to be taken.
        let outgoing_channel_id = match req.outgoing_channel_id {
            Some(c) => c.into(),
            None => {
                return Ok(Ok(records_from_signal(AccountableSignal::Unaccountable)));
            }
        };

        self.inner_add_htlc(
            HtlcAdd {
                forwarding_node: req.forwarding_node,
                incoming_ref: HtlcRef {
                    channel_id: req.incoming_htlc.channel_id.into(),
                    htlc_index: req.incoming_htlc.index,
                },
                outgoing_channel_id,
                amount_in_msat: req.incoming_amount_msat,
                amount_out_msat: req.outgoing_amount_msat,
                expiry_in_height: req.incoming_expiry_height,
                expiry_out_height: req.outgoing_expiry_height,
                // We want to use our live clock to set the timestamp on this resolution.
                added_at: None,
                incoming_accountable: accountable_from_records(&req.incoming_custom_records),
                upgradable_accountability: upgradable_from_records(&req.incoming_custom_records),
            },
            true,
        )
        .await
        .map_err(|e| CriticalError::InterceptorError(e.to_string()))
    }

    async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), CriticalError> {
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
            // We want to use our live clock to set the timestamp on this resolution.
            resolved_ins: None,
        })
        .await
        .map_err(|e| CriticalError::InterceptorError(e.to_string()))
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
    use ln_resource_mgr::forward_manager::{
        ForwardManager, ForwardManagerParams, SimulationDebugManager,
    };
    use ln_resource_mgr::{
        AccountableSignal, AllocationCheck, ChannelSnapshot, ForwardResolution, ForwardingOutcome,
        HtlcRef, ProposedForward, ReputationError, ReputationManager, ReputationParams,
    };
    use mockall::mock;
    use sim_cli::parsing::NetworkParser;
    use simln_lib::clock::SimulationClock;
    use simln_lib::sim_node::{CriticalError, InterceptResolution, Interceptor};
    use simln_lib::ShortChannelID;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    use crate::analysis::BatchForwardWriter;
    use crate::clock::InstantClock;
    use crate::reputation_interceptor::{BootstrapForward, BootstrapRecords, ChannelJammer};
    use crate::test_utils::{
        get_random_keypair, setup_test_edge, setup_test_request, test_allocation_check,
    };
    use crate::{accountable_from_records, BoxError};

    use super::{Node, ReputationInterceptor, ReputationMonitor};

    mock! {
        ForwardManager{}

        impl SimulationDebugManager for ForwardManager {
            fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError>;
            fn congestion_jam_channel(&self, channel: u64) -> Result<(), ReputationError>;
        }

        #[async_trait]
        impl ReputationManager for ForwardManager{
            fn add_channel(
                &self,
                channel_id: u64,
                capacity_msat: u64,
                add_ins: Instant,
                channel_reputation: Option<ChannelSnapshot>
            ) -> Result<(), ln_resource_mgr::ReputationError>;

            fn remove_channel(&self, channel_id: u64) -> Result<(), ReputationError>;

            fn get_allocation_snapshot(
                &self,
                forward: &ProposedForward,
            ) -> Result<AllocationCheck, ReputationError>;

            fn add_htlc(
                &self,
                forward: &ProposedForward
            ) -> Result<ForwardingOutcome, ReputationError>;
            fn resolve_htlc(
                &self,
                outgoing_channel: u64,
                incoming_ref: HtlcRef,
                resolution: ForwardResolution,
                resolved_instant: Instant
            ) -> Result<(), ReputationError>;

            fn list_channels(
                &self,
                access_ins: Instant
            ) -> Result<HashMap<u64, ChannelSnapshot>, ReputationError>;
        }
    }

    /// Creates a test interceptor with three nodes in the network and a vector of their public keys.
    fn setup_test_interceptor() -> (
        ReputationInterceptor<BatchForwardWriter, MockForwardManager, SimulationClock>,
        Vec<PublicKey>,
    ) {
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
            },
            pubkeys,
        )
    }

    /// Tests that we do not intercept when the forwarding node is the recipient.
    #[tokio::test]
    async fn test_final_hop_intercept() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let mut request = setup_test_request(pubkeys[0], 0, 1, AccountableSignal::Unaccountable);

        request.outgoing_channel_id = None;
        let res = interceptor.intercept_htlc(request).await.unwrap().unwrap();

        assert!(matches!(
            accountable_from_records(&res),
            AccountableSignal::Unaccountable
        ));
    }

    /// Tests failure if a forward from an unknown node is intercepted.
    #[tokio::test]
    async fn test_unknown_intercept_node() {
        let (interceptor, _) = setup_test_interceptor();
        let request = setup_test_request(
            get_random_keypair().1,
            0,
            1,
            AccountableSignal::Unaccountable,
        );

        let err = interceptor.intercept_htlc(request).await.err().unwrap();
        assert!(matches!(err, CriticalError::InterceptorError(_),));
    }

    /// Tests interception of a htlc that should be forwarded as accountable.
    #[tokio::test]
    async fn test_forward_accountable_htlc() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let request = setup_test_request(pubkeys[0], 0, 1, AccountableSignal::Accountable);

        interceptor
            .network_nodes
            .lock()
            .await
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_get_allocation_snapshot()
            .return_once(|_| Ok(test_allocation_check(true)));

        interceptor
            .network_nodes
            .lock()
            .await
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_add_htlc()
            .return_once(|_| Ok(ForwardingOutcome::Forward(AccountableSignal::Accountable)));

        let res = interceptor.intercept_htlc(request).await.unwrap().unwrap();

        // Should call add_htlc + return a reputation check that passes.
        assert!(accountable_from_records(&res) == AccountableSignal::Accountable);

        // Test unaccountable htlc with sufficient reputation gets upgraded to accountable.
        let (interceptor, pubkeys) = setup_test_interceptor();
        let request = setup_test_request(pubkeys[0], 0, 1, AccountableSignal::Unaccountable);

        interceptor
            .network_nodes
            .lock()
            .await
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_get_allocation_snapshot()
            .return_once(|_| Ok(test_allocation_check(true)));

        interceptor
            .network_nodes
            .lock()
            .await
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_add_htlc()
            .return_once(|_| Ok(ForwardingOutcome::Forward(AccountableSignal::Accountable)));

        let res = interceptor.intercept_htlc(request).await.unwrap().unwrap();
        assert!(accountable_from_records(&res) == AccountableSignal::Accountable);
    }

    /// Tests interception of a htlc that should be forwarded as unaccountable.
    #[tokio::test]
    async fn test_forward_unaccountable_htlc() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let request = setup_test_request(pubkeys[0], 0, 1, AccountableSignal::Unaccountable);

        interceptor
            .network_nodes
            .lock()
            .await
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_get_allocation_snapshot()
            .return_once(|_| Ok(test_allocation_check(false)));

        interceptor
            .network_nodes
            .lock()
            .await
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_add_htlc()
            .return_once(|_| Ok(ForwardingOutcome::Forward(AccountableSignal::Unaccountable)));

        let res = interceptor.intercept_htlc(request).await.unwrap().unwrap();

        // should call add_htlc + return a reputation check that passes
        assert!(accountable_from_records(&res) == AccountableSignal::Unaccountable);
    }

    /// Tests that we do not notify resolution of last hop htlcs.
    #[tokio::test]
    async fn test_final_hop_notify() {
        let (interceptor, pubkeys) = setup_test_interceptor();
        let mut request = setup_test_request(pubkeys[0], 0, 1, AccountableSignal::Unaccountable);

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
            .await
            .get_mut(&pubkeys[0])
            .unwrap()
            .forward_manager
            .expect_resolve_htlc()
            .return_once(|_, _, _, _| Ok(()));
    }

    type ReputationSnapshot = HashMap<PublicKey, HashMap<u64, ChannelSnapshot>>;

    /// Creates a reputation interceptor for a three hop network: Alice - Bob - Carol.
    fn setup_three_hop_network_edges(
    ) -> (ForwardManagerParams, Vec<NetworkParser>, ReputationSnapshot) {
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

        let mut reputation_snapshot = HashMap::new();
        for edge in &edges {
            let node_1_snapshot = ChannelSnapshot {
                capacity_msat: edge.capacity_msat,
                outgoing_reputation: 0,
                bidirectional_revenue: 0,
            };
            let node_2_snapshot = ChannelSnapshot {
                capacity_msat: edge.capacity_msat,
                outgoing_reputation: 0,
                bidirectional_revenue: 0,
            };

            reputation_snapshot
                .entry(edge.node_1.pubkey)
                .or_insert_with(HashMap::new)
                .insert(edge.scid.into(), node_1_snapshot);
            reputation_snapshot
                .entry(edge.node_2.pubkey)
                .or_insert_with(HashMap::new)
                .insert(edge.scid.into(), node_2_snapshot);
        }

        (params, edges, reputation_snapshot)
    }

    /// Tests that nodes are appropriately set up when an interceptor is created from a set of edges.
    #[tokio::test]
    async fn test_new_for_network_node_creation() {
        let (params, edges, _) = setup_three_hop_network_edges();

        let interceptor: ReputationInterceptor<
            BatchForwardWriter,
            ForwardManager,
            SimulationClock,
        > = ReputationInterceptor::new_for_network(
            params,
            &edges,
            Arc::new(SimulationClock::new(1).unwrap()),
            None,
        )
        .unwrap();

        // Alice only has one channel tracked.
        let alice_channels = interceptor
            .list_channels(edges[0].node_1.pubkey, Instant::now())
            .await
            .unwrap();
        assert_eq!(alice_channels.len(), 1);
        assert!(alice_channels.contains_key(&edges[0].scid.into()));

        // Bob has two channels tracked.
        let bob_channels = interceptor
            .list_channels(edges[1].node_1.pubkey, Instant::now())
            .await
            .unwrap();

        assert_eq!(edges[0].node_2.pubkey, edges[1].node_1.pubkey);
        assert_eq!(bob_channels.len(), 2);
        assert!(bob_channels.contains_key(&edges[0].scid.into()));
        assert!(bob_channels.contains_key(&edges[1].scid.into()));

        // Carol has one channel tracked.
        let carol_channels = interceptor
            .list_channels(edges[1].node_2.pubkey, Instant::now())
            .await
            .unwrap();
        assert_eq!(carol_channels.len(), 1);
        assert!(carol_channels.contains_key(&edges[1].scid.into()));
    }

    /// Tests that nodes marked to be general jammed appropriately have their general resources slashed, but are still
    /// able to bootstrap reputation.
    #[tokio::test]
    async fn test_bootstrap_and_general_jam() {
        let (params, edges, _) = setup_three_hop_network_edges();

        let bob_pk = edges[0].node_2.pubkey;
        let alice_to_bob: u64 = edges[0].scid.into();
        let bob_to_carol: u64 = edges[1].scid.into();

        // Create a bootstraped forward that'll be forwarded over the general jammed channel.
        let bootstrap = vec![BootstrapForward {
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
        let mut interceptor: ReputationInterceptor<
            BatchForwardWriter,
            ForwardManager,
            SimulationClock,
        > = ReputationInterceptor::new_for_network(
            params,
            &edges,
            Arc::new(SimulationClock::new(1).unwrap()),
            None,
        )
        .unwrap();

        interceptor
            .bootstrap_network_history(&BootstrapRecords {
                forwards: bootstrap,
                last_timestamp_nanos: 1_000_000,
            })
            .await
            .unwrap();

        interceptor
            .jam_general_resources(&edges[1].node_1.pubkey, bob_to_carol)
            .await
            .unwrap();

        let bob_reputation = interceptor
            .network_nodes
            .lock()
            .await
            .get(&bob_pk)
            .unwrap()
            .forward_manager
            .list_channels(Instant::now())
            .unwrap();

        assert!(
            bob_reputation
                .get(&alice_to_bob)
                .unwrap()
                .bidirectional_revenue
                != 0
        );
        assert!(
            bob_reputation
                .get(&bob_to_carol)
                .unwrap()
                .outgoing_reputation
                != 0
        );

        // An unaccountable payment in the non-jammed direction should be forwarded through
        // unaccountable.
        let request = setup_test_request(
            edges[1].node_1.pubkey,
            alice_to_bob,
            bob_to_carol,
            AccountableSignal::Unaccountable,
        );

        let res = interceptor.intercept_htlc(request).await.unwrap().unwrap();
        assert!(accountable_from_records(&res) == AccountableSignal::Unaccountable,);

        // An unaccountable htlc using the jammed channel would get access to congestion bucket and
        // be upgraded to accountable.
        let request = setup_test_request(
            edges[1].node_1.pubkey,
            bob_to_carol,
            alice_to_bob,
            AccountableSignal::Unaccountable,
        );

        let res = interceptor
            .intercept_htlc(request.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(accountable_from_records(&res) == AccountableSignal::Accountable);

        // Resolve htlc occupying congestion bucket.
        let resolution = InterceptResolution {
            forwarding_node: request.forwarding_node,
            incoming_htlc: request.incoming_htlc,
            outgoing_channel_id: request.outgoing_channel_id,
            success: true,
        };
        interceptor.notify_resolution(resolution).await.unwrap();

        // With general and congestion jammed, unaccountable htlc should fail if no reputation.
        interceptor
            .jam_congestion_resources(&edges[1].node_1.pubkey, bob_to_carol)
            .await
            .unwrap();

        let request = setup_test_request(
            edges[1].node_1.pubkey,
            bob_to_carol,
            alice_to_bob,
            AccountableSignal::Unaccountable,
        );

        let res = interceptor.intercept_htlc(request).await.unwrap();
        assert!(res.is_err());
    }

    /// Tests starting interceptor from valid snapshot.
    #[tokio::test]
    async fn test_new_from_snapshot() {
        let (params, edges, reputation_snapshot) = setup_three_hop_network_edges();

        let clock = Arc::new(SimulationClock::new(1).unwrap());
        let interceptor: Result<
            ReputationInterceptor<BatchForwardWriter, ForwardManager, SimulationClock>,
            BoxError,
        > = ReputationInterceptor::new_from_snapshot(
            params,
            &edges,
            reputation_snapshot.clone(),
            HashSet::new(),
            clock.clone(),
            None,
        )
        .await;

        assert!(interceptor.is_ok());

        // Test channels in network nodes of interceptor match the channels in edges.
        let interceptor = interceptor.unwrap();
        for edge in edges {
            let node_1_channels = interceptor
                .network_nodes
                .lock()
                .await
                .get(&edge.node_1.pubkey)
                .unwrap()
                .forward_manager
                .list_channels(InstantClock::now(&*clock))
                .unwrap();
            let snapshot_channels_1 = reputation_snapshot.get(&edge.node_1.pubkey).unwrap();
            assert_eq!(&node_1_channels, snapshot_channels_1);

            let node_2_channels = interceptor
                .network_nodes
                .lock()
                .await
                .get(&edge.node_2.pubkey)
                .unwrap()
                .forward_manager
                .list_channels(InstantClock::now(&*clock))
                .unwrap();
            let snapshot_channels_2 = reputation_snapshot.get(&edge.node_2.pubkey).unwrap();
            assert_eq!(&node_2_channels, snapshot_channels_2)
        }
    }

    /// Tests that an error is returned when the snapshot is missing a node.
    #[tokio::test]
    async fn test_new_from_snapshot_missing_node() {
        let (params, edges, _) = setup_three_hop_network_edges();

        let mut reputation_snapshot: HashMap<PublicKey, HashMap<u64, ChannelSnapshot>> =
            HashMap::new();

        // Only include one node in the snapshot.
        let edge = &edges[0];
        let node_1_snapshot = ChannelSnapshot {
            capacity_msat: edge.capacity_msat,
            outgoing_reputation: 0,
            bidirectional_revenue: 0,
        };
        reputation_snapshot
            .entry(edge.node_1.pubkey)
            .or_default()
            .insert(edge.scid.into(), node_1_snapshot);

        let interceptor: Result<
            ReputationInterceptor<BatchForwardWriter, ForwardManager, SimulationClock>,
            BoxError,
        > = ReputationInterceptor::new_from_snapshot(
            params,
            &edges,
            reputation_snapshot,
            HashSet::new(),
            Arc::new(SimulationClock::new(1).unwrap()),
            None,
        )
        .await;

        assert!(interceptor.is_err());
    }

    /// Tests that an error is returned when the snapshot is missing a channel for a node.
    #[tokio::test]
    async fn test_new_from_snapshot_missing_channel() {
        let (params, edges, _) = setup_three_hop_network_edges();

        let mut reputation_snapshot: HashMap<PublicKey, HashMap<u64, ChannelSnapshot>> =
            HashMap::new();

        // Include node but do not include channel for node.
        let edge = &edges[0];
        reputation_snapshot.entry(edge.node_1.pubkey).or_default();

        let interceptor: Result<
            ReputationInterceptor<BatchForwardWriter, ForwardManager, SimulationClock>,
            BoxError,
        > = ReputationInterceptor::new_from_snapshot(
            params,
            &edges,
            reputation_snapshot,
            HashSet::new(),
            Arc::new(SimulationClock::new(1).unwrap()),
            None,
        )
        .await;

        assert!(interceptor.is_err());
    }

    /// Tests that an error is returned when the snapshot has mismatched channel capacities.
    #[tokio::test]
    async fn test_new_from_snapshot_mismatched_capacity() {
        let (params, edges, mut reputation_snapshot) = setup_three_hop_network_edges();

        // Modify the channel capacity to make it have a different value.
        let channel_snapshot = reputation_snapshot
            .get_mut(&edges[0].node_1.pubkey)
            .unwrap()
            .get_mut(&edges[0].scid.into())
            .unwrap();
        channel_snapshot.capacity_msat = 1000;

        let interceptor: Result<
            ReputationInterceptor<BatchForwardWriter, ForwardManager, SimulationClock>,
            BoxError,
        > = ReputationInterceptor::new_from_snapshot(
            params,
            &edges,
            reputation_snapshot,
            HashSet::new(),
            Arc::new(SimulationClock::new(1).unwrap()),
            None,
        )
        .await;

        assert!(interceptor.is_err());
    }

    /// Tests that an error is returned when the snapshot has a mismatched number of channels.
    #[tokio::test]
    async fn test_new_from_snapshot_mismatched_channel_count() {
        let (params, edges, mut reputation_snapshot) = setup_three_hop_network_edges();

        // Remove a channel to make them have mismatched number of channels.
        let channels = reputation_snapshot
            .get_mut(&edges[0].node_1.pubkey)
            .unwrap();
        channels.remove(&edges[0].scid.into()).unwrap();

        let interceptor: Result<
            ReputationInterceptor<BatchForwardWriter, ForwardManager, SimulationClock>,
            BoxError,
        > = ReputationInterceptor::new_from_snapshot(
            params,
            &edges,
            reputation_snapshot,
            HashSet::new(),
            Arc::new(SimulationClock::new(1).unwrap()),
            None,
        )
        .await;

        assert!(interceptor.is_err());
    }
}
