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
    clock::{Clock, SimulationClock},
    sim_node::{CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode, WrappedLog},
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{select, sync::Mutex};
use triggered::{trigger, Listener};

use super::{
    utils::{build_custom_route, build_reputation, sufficient_reputation, BuildReputationParams},
    NetworkSetup,
};

// Idea: Have a graph with [attacker_sender (A1)] -> [target_peer] -> [target_node] -> [attacker_2 (A2)]
// and jam channel between [target_peer] <-> [target_node].

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

#[derive(Clone)]
pub struct FastJam<R, M, J>
where
    R: ReputationMonitor + Send + Sync + 'static,
    M: PeacetimeRevenueMonitor + Send + Sync + 'static,
    J: ChannelJammer + Send + Sync + 'static,
{
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    attacker: (String, PublicKey),
    attacker_sender: (String, PublicKey),
    target_channels: HashMap<u64, PublicKey>,
    channel_to_jam: (PublicKey, u64),
    reputation_monitor: Arc<R>,
    revenue_monitor: Arc<M>,
    channel_jammer: Arc<J>,
    network_graph: Arc<LdkNetworkGraph>,
    // Used to track payments used for fast-jamming protected resources. This is to
    // differentiate between other payments that we don't want to fast-jam (for building
    // reputation).
    jamming_payments: Arc<Mutex<HashSet<PaymentHash>>>,
    reputation_params: ForwardManagerParams,
    risk_margin: u64,
}

impl<R, M, J> FastJam<R, M, J>
where
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<SimulationClock>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        attacker_sender: (String, PublicKey),
        attacker: (String, PublicKey),
        channel_to_jam: (PublicKey, u64),
        reputation_monitor: Arc<R>,
        revenue_monitor: Arc<M>,
        channel_jammer: Arc<J>,
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
            channel_jammer,
            network_graph,
            jamming_payments: Arc::new(Mutex::new(HashSet::new())),
            reputation_params: ForwardManagerParams::default(),
            risk_margin,
        }
    }

    pub async fn build_reputation(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
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

    async fn fast_jam_channel(
        &self,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
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
impl<R, M, J> JammingAttack for FastJam<R, M, J>
where
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    fn setup_for_network(&self) -> Result<NetworkSetup, BoxError> {
        // Validate that attacker receiver has channel with target.
        self.target_channels
            .iter()
            .find(|chan| self.attacker.1 == *chan.1)
            .ok_or(format!(
                "Target does not have a channel with {}",
                self.attacker.1
            ))?;

        Ok(NetworkSetup {
            general_jammed_nodes: vec![],
        })
    }

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

    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        // - Build reputation to start attacking channel.
        // - Task to check if attack is finished. This includes:
        //      - Check if revenue during attacks dips below peacetime revenue.
        //      - Check if attacker has reputation to continue with attack.
        // - Jam the general and congestion resources with jammer helper. This will require extra
        // calculation of cost of these.
        // - With sufficient reputation, continuously jam protected resources by sending slow (80s)
        //  resolving payments that don't slash reputation.

        let _ = self.build_reputation(&attacker_nodes).await?;

        // Setup for task to check if attack is complete
        let (attack_completed_sender, attack_completed_listener) = trigger();
        let attack_check_clock = Arc::clone(&self.clock);
        let revenue_monitor_check = Arc::clone(&self.revenue_monitor);
        let reputation_monitor_check = Arc::clone(&self.reputation_monitor);
        let to_attacker_channel = *self
            .target_channels
            .iter()
            .find(|chan| self.attacker.1 == *chan.1)
            // We validate that this channel exists in `setup_for_network` so this unwrap is safe.
            .unwrap()
            .0;

        let target_pubkey = self.target_pubkey;
        let channel_to_jam = self.channel_to_jam.1;
        let risk_margin = self.risk_margin;
        tokio::spawn(async move {
            let interval = Duration::from_secs(300);
            loop {
                select! {
                    _ = shutdown_listener.clone() => {
                        attack_completed_sender.trigger();
                        break
                    },
                    _ = attack_check_clock.sleep(interval) => {
                        let snapshot = revenue_monitor_check.get_revenue_difference().await;
                        if snapshot.peacetime_revenue_msat > snapshot.simulation_revenue_msat {
                            log::error!(
                                "Peacetime revenue: {} exceeds simulation revenue: {} after: {:?}",
                                snapshot.peacetime_revenue_msat,
                                snapshot.simulation_revenue_msat,
                                snapshot.runtime
                            );
                            attack_completed_sender.trigger();
                            break
                        }

                        log::trace!(
                            "Peacetime revenue: {} less than simulation revenue: {} after: {:?}",
                            snapshot.peacetime_revenue_msat,
                            snapshot.simulation_revenue_msat,
                            snapshot.runtime
                        );

                        let instant = InstantClock::now(&*attack_check_clock);
                        if !sufficient_reputation(
                            Arc::clone(&reputation_monitor_check),
                            to_attacker_channel,
                            (target_pubkey, channel_to_jam),
                            risk_margin,
                            instant,
                        ).await? {
                            log::info!("Attacker has lost reputation to continue with attack.");
                            attack_completed_sender.trigger();
                            break
                        }

                    }
                }
            }
            Ok::<(), BoxError>(())
        });

        self.channel_jammer
            .jam_general_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        self.channel_jammer
            .jam_congestion_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        // After building reputation and jamming general resources, jam protected resources.
        self.fast_jam_channel(attacker_nodes, attack_completed_listener)
            .await?;

        Ok(())
    }
}
