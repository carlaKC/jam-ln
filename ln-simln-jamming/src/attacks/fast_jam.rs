use crate::{
    attacks::JammingAttack,
    clock::InstantClock,
    print_request,
    reputation_interceptor::{ChannelJammer, ReputationMonitor},
    revenue_interceptor::PeacetimeRevenueMonitor,
    BoxError, NetworkReputation,
};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::{ln::PaymentHash, routing::gossip::NetworkGraph};
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use sim_cli::parsing::NetworkParser;
use simln_lib::{
    clock::Clock,
    sim_node::{CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode, WrappedLog},
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{
    select,
    sync::{oneshot::Sender, Mutex},
};
use triggered::{trigger, Listener};

use super::utils::{build_custom_route, build_reputation, BuildReputationParams};

// Idea: Have a graph with [attacker_sender (A1)] -> [target_peer] -> [target_node] -> [attacker_2 (A2)]
// and jam channel between [target_peer] <-> [target_node].

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

pub struct FastJam<C, R, M, J>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    clock: Arc<C>,
    target_pubkey: PublicKey,
    attacker: (String, PublicKey),
    attacker_sender: (String, PublicKey),
    target_channels: HashMap<u64, PublicKey>,
    channel_to_jam: (PublicKey, u64),
    reputation_monitor: Arc<Mutex<R>>,
    revenue_monitor: Arc<M>,
    general_jammer: Arc<Mutex<J>>,
    network_graph: Arc<LdkNetworkGraph>,
    // Used to track payments used for fast-jamming protected resources. This is to
    // differentiate between other payments that we don't want to fast-jam (for building
    // reputation).
    jamming_payments: Mutex<HashSet<PaymentHash>>,
    reputation_params: ForwardManagerParams,
    risk_margin: u64,
}

impl<C, R, M, J> FastJam<C, R, M, J>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<C>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        attacker_sender: (String, PublicKey),
        attacker: (String, PublicKey),
        channel_to_jam: (PublicKey, u64),
        reputation_monitor: Arc<Mutex<R>>,
        revenue_monitor: Arc<M>,
        general_jammer: Arc<Mutex<J>>,
        network_graph: Arc<LdkNetworkGraph>,
        risk_margin: u64,
    ) -> Self {
        Self {
            clock,
            target_pubkey,
            attacker_sender,
            attacker,
            target_channels: HashMap::from_iter(network.iter().filter_map(|channel| {
                if channel.node_1.pubkey == target_pubkey {
                    Some((channel.scid.into(), channel.node_2.pubkey))
                } else if channel.node_2.pubkey == target_pubkey {
                    Some((channel.scid.into(), channel.node_1.pubkey))
                } else {
                    None
                }
            })),
            channel_to_jam,
            reputation_monitor,
            revenue_monitor,
            general_jammer,
            network_graph,
            jamming_payments: Mutex::new(HashSet::new()),
            reputation_params: ForwardManagerParams::default(),
            risk_margin,
        }
    }

    pub async fn build_reputation(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
    ) -> Result<u64, BoxError> {
        // Route for payment that will build reputation:
        //  [attacker_sender] -> [target_node] -> [attacker_receiver]
        //  Note that this does not include the target_channel that we want to jam because we don't
        //  want to bump the revenue for that channel.
        let hops = vec![self.target_pubkey, self.attacker.1];
        let target_channel = (self.target_pubkey, self.channel_to_jam.1);

        let attacker_node_sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;

        let build_rep_params = BuildReputationParams {
            attacker_node: Arc::clone(attacker_node_sender),
            hops: &hops,
            network_graph: &self.network_graph,
            // This needs to build reputation for:
            // HTLC slots in protected bucket = 0.4 * 483 = 193
            // of 1_000 msat amount
            htlcs: vec![1_000; 193],
            target_channel,
            reputation_monitor: Arc::clone(&self.reputation_monitor),
            payment_hash: PaymentHash(rand::random()),
            reputation_params: self.reputation_params,
            clock: Arc::clone(&self.clock),
            shutdown_listener: trigger().1,
        };
        let fees_paid = build_reputation(build_rep_params).await?;
        Ok(fees_paid)
    }

    async fn sufficient_reputation(&self) -> Result<bool, BoxError> {
        let to_attacker_channel = self
            .target_channels
            .iter()
            .find(|chan| self.attacker.1 == *chan.1)
            .ok_or(format!(
                "Target does not have a channel with {}",
                self.attacker.1
            ))?
            .0;

        let target_channel_snapshots = self
            .reputation_monitor
            .lock()
            .await
            .list_channels(self.target_pubkey, InstantClock::now(&*self.clock))
            .await?;

        let attacker_reputation = target_channel_snapshots
            .get(to_attacker_channel)
            .ok_or(format!("Channel {} not found", to_attacker_channel))?
            .outgoing_reputation;

        let target_revenue = target_channel_snapshots
            .get(&self.channel_to_jam.1)
            .ok_or(format!("Channel {} not found", self.channel_to_jam.1))?
            .bidirectional_revenue;

        let sufficient_reputation =
            attacker_reputation > (target_revenue + self.risk_margin as i64);

        Ok(sufficient_reputation)
    }

    async fn fast_jam_channel(
        &self,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        // At this point, we should already have built reputation and have access to protected
        // resources. Attack channel [target_peer] <-> [target] through:
        // [attacker_sender] -> [target_peer] -> [target] -> [attacker_2]
        let attacker_node_sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;

        // Jam resources with low-value htlcs to occupy as many slots as possible while trying not
        // to affect reputation negatively.
        let hops = vec![self.channel_to_jam.0, self.target_pubkey, self.attacker.1];
        let route = build_custom_route(&self.attacker_sender.1, 1_000, &hops, &self.network_graph)
            .map_err(|e| e.err)?;

        loop {
            select! {
                _ = shutdown_listener.clone() => {
                    break;
                }
                mut attacker_node = attacker_node_sender.lock() => {
                    // NOTE: This will keep sending payments even if all protected slots are taken.
                    // This could instead check if we are already full and don't send until the
                    // HTLCs being held are released.
                    // let jamming_payments_lock = self.jamming_payments.lock().await;
                    // if jamming_payments_lock.len() > 190 {
                    //     continue;
                    // }

                    let payment_hash = PaymentHash(rand::random());
                    if let Err(e) = attacker_node.send_to_route(route.clone(), payment_hash, None).await {
                        return Err(e.to_string().into());
                    }
                    self.jamming_payments.lock().await.insert(payment_hash);

                    // NOTE: These fast failing payments should not affect its reputation with the peer but
                    // it will decay with time. Perhaps if it detects it is close to not having enough then
                    // it could build_reputation again.
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<C, R, M, J> JammingAttack for FastJam<C, R, M, J>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    /// We generate two types of payments where we are the receivers:
    /// - To build reputation. In this case we let the payment succeed.
    /// - When fast-jamming from [`Self::fast_jam_channel`]. In this case we hold it for 80s to jam
    /// the channel but not affect reputation negatively (by failing before the 90s window).
    async fn intercept_attacker_receive(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        let mut jamming_payments_lock = self.jamming_payments.lock().await;
        // If this is not a jamming payment then let it go through since it is most likely one
        // where we are trying to build reputation.
        if !jamming_payments_lock.contains(&req.payment_hash) {
            Ok(Ok(req.incoming_custom_records))
        } else {
            let hold_time = Duration::from_secs(80);
            log::info!(
                "Jamming HTLC from target -> attacker accountable, holding for {:?}: {}",
                hold_time,
                print_request(&req),
            );

            // If this is one of our jamming payments, hold it for 80s to not affect reputation
            // negatively and then fail it.
            select! {
                //_ = self.listener.clone() => Err(ForwardingError::InterceptorError("shutdown signal received".to_string())),
                _ = req.shutdown_listener.clone() => Ok(Err(ForwardingError::InterceptorError("shutdown signal received".to_string()))),
                _ = self.clock.sleep(hold_time) => {
                    jamming_payments_lock.remove(&req.payment_hash);
                    Ok(Err(ForwardingError::InterceptorError(
                        "failing from jamming interceptor".into(),
                    )))
                }
            }
        }
    }

    async fn run_custom_actions(
        &self,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
        simulation_completed_check: Sender<()>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        // - Build reputation to start attacking channel.
        // - Jam the general and congestion resources with jammer helper. This will require extra
        // calculation of cost of these.
        // - With sufficient reputation, continuously jam protected resources by sending slow (80s)
        //  resolving payments that don't slash reputation.

        let _ = self.build_reputation(&attacker_nodes).await?;

        // If reputation building was successful, send signal that `simulation_completed` check can
        // start.
        simulation_completed_check
            .send(())
            .map_err(|_| "Could not send simulation_completed signal")?;

        self.general_jammer
            .lock()
            .await
            .jam_general_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        self.general_jammer
            .lock()
            .await
            .jam_congestion_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        // After building reputation and jamming general resources, jam protected resources.
        self.fast_jam_channel(attacker_nodes, shutdown_listener)
            .await?;

        Ok(())
    }

    async fn simulation_completed(
        &self,
        _start_reputation: NetworkReputation,
    ) -> Result<bool, BoxError> {
        let snapshot = self.revenue_monitor.get_revenue_difference().await;
        if snapshot.peacetime_revenue_msat > snapshot.simulation_revenue_msat {
            log::error!(
                "Peacetime revenue: {} exceeds simulation revenue: {} after: {:?}",
                snapshot.peacetime_revenue_msat,
                snapshot.simulation_revenue_msat,
                snapshot.runtime
            );

            return Ok(true);
        }

        log::trace!(
            "Peacetime revenue: {} less than simulation revenue: {} after: {:?}",
            snapshot.peacetime_revenue_msat,
            snapshot.simulation_revenue_msat,
            snapshot.runtime
        );

        // If attacker has no more reputation with the target, end simulation.
        if !self.sufficient_reputation().await? {
            log::info!("Attacker has lost reputation to continue with attack.");
            return Ok(true);
        }

        Ok(false)
    }
}
