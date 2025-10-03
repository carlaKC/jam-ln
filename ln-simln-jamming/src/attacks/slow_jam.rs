use crate::{
    attacks::JammingAttack,
    print_request,
    reputation_interceptor::{ChannelJammer, ReputationMonitor},
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
    LightningNode, PaymentOutcome,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{select, sync::Mutex};
use triggered::{trigger, Listener, Trigger};

use super::{
    utils::{build_custom_route, build_reputation, BuildReputationParams},
    NetworkSetup,
};

// Idea: Have a graph with [attacker_sender (A1)] -> [target_peer] -> [target_node] -> [attacker_2 (A2)]
// and jam channel between [target_peer] <-> [target_node].

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

pub struct SlowJam<R, J>
where
    R: ReputationMonitor + Send + Sync + 'static,
    J: ChannelJammer + Send + Sync + 'static,
{
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    attacker_sender: (String, PublicKey),
    attacker_receiver: (String, PublicKey),
    // honest sender and receiver are used after jamming the target channel to make an "honest"
    // payment through the target channel and check that it fails.
    honest_sender: (String, PublicKey),
    honest_receiver: (String, PublicKey),
    target_channels: HashMap<u64, PublicKey>,
    channel_to_jam: (PublicKey, u64),
    reputation_monitor: Arc<R>,
    channel_jammer: Arc<J>,
    network_graph: Arc<LdkNetworkGraph>,
    // Used to track payments used for jamming protected resources. This is to
    // differentiate between other payments that we don't want to jam (for building
    // reputation).
    jamming_payments: Arc<Mutex<HashSet<PaymentHash>>>,
    reputation_params: ForwardManagerParams,
    payment_trigger: (Trigger, Listener),
}

impl<R, J> SlowJam<R, J>
where
    R: ReputationMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<SimulationClock>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        attacker_sender: (String, PublicKey),
        attacker_receiver: (String, PublicKey),
        honest_sender: (String, PublicKey),
        honest_receiver: (String, PublicKey),
        channel_to_jam: (PublicKey, u64),
        reputation_monitor: Arc<R>,
        channel_jammer: Arc<J>,
        network_graph: Arc<LdkNetworkGraph>,
    ) -> Self {
        Self {
            clock,
            target_pubkey,
            attacker_sender,
            attacker_receiver,
            honest_sender,
            honest_receiver,
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
            channel_jammer,
            network_graph,
            jamming_payments: Arc::new(Mutex::new(HashSet::new())),
            reputation_params: ForwardManagerParams::default(),
            payment_trigger: trigger(),
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
        let hops = &[self.target_pubkey, self.attacker_receiver.1];
        let target_channel = (self.target_pubkey, self.channel_to_jam.1);

        let attacker_node_sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;

        let build_rep_params = BuildReputationParams {
            attacker_node: Arc::clone(attacker_node_sender),
            hops,
            network_graph: &self.network_graph,
            // Build reputation for this amount which is slightly above the liquidity available in
            // the protected bucket of the channel we are trying to jam. Note that this is a
            // specific value set based on the target channel used.
            htlcs: vec![900_000_000; 1],
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

    async fn slow_jam_channel(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
    ) -> Result<(), BoxError> {
        // At this point we should:
        // - Have general and congestion resources jammed.
        // - Already have built reputation and have access to protected resources.
        let attacker_node_sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;

        // Jam the protected resources of our target channel by sending a payment for the entire
        // amount of the protected bucket. This will be accepted over the incoming channel because
        // we have set a channel such that the general slots will accomodate this value.
        let hops_1 = vec![
            self.channel_to_jam.0,
            self.target_pubkey,
            self.attacker_receiver.1,
        ];
        let route = build_custom_route(
            &self.attacker_sender.1,
            798_799_000,
            &hops_1,
            &self.network_graph,
        )
        .map_err(|e| e.err)?;

        // Here attacker receiver must have enough reputation to jam the entire protected bucket.
        // So that a subsequent honest payment going to an honest receiver can't use the channel
        // even if it has reputation because all protected resources are taken.
        let payment_hash = PaymentHash(rand::random());
        self.jamming_payments.lock().await.insert(payment_hash);
        if let Err(e) = attacker_node_sender
            .lock()
            .await
            .send_to_route(route, payment_hash, None)
            .await
        {
            self.jamming_payments.lock().await.remove(&payment_hash);
            return Err(e.to_string().into());
        }

        Ok(())
    }
}

#[async_trait]
impl<R, J> JammingAttack for SlowJam<R, J>
where
    R: ReputationMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    fn setup_for_network(&self) -> Result<NetworkSetup, BoxError> {
        // Validate that attacker receiver has channel with target.
        self.target_channels
            .iter()
            .find(|chan| self.attacker_receiver.1 == *chan.1)
            .ok_or(format!(
                "Target does not have a channel with attacker receiver {}",
                self.attacker_receiver.1
            ))?;

        // Validate that honest receiver has channel with target.
        self.target_channels
            .iter()
            .find(|chan| self.honest_receiver.1 == *chan.1)
            .ok_or(format!(
                "Target does not have a channel with honest receiver {}",
                self.honest_receiver.1
            ))?;

        // Validate that our channel that we want to jam is part of the target's channel list.
        let target_peer_pubkey =
            self.target_channels
                .get(&self.channel_to_jam.1)
                .ok_or(format!(
                    "channel {} to jam is not part of target's channels",
                    self.channel_to_jam.1
                ))?;

        if *target_peer_pubkey != self.channel_to_jam.0 {
            return Err("peer in channel to jam does not match".into());
        }

        Ok(NetworkSetup {
            general_jammed_nodes: vec![],
        })
    }

    /// We generate two types of payments where we are the receivers:
    /// - To build reputation. In this case we let the payment succeed.
    /// - When slow jamming from [`Self::slow_jam_channel`]. In this case we hold it for the
    /// entire expiry time.
    async fn intercept_attacker_receive(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        // If this is not a jamming payment then let it go through since it is most likely one
        // where we are trying to build reputation.
        if !self
            .jamming_payments
            .lock()
            .await
            .contains(&req.payment_hash)
        {
            Ok(Ok(req.incoming_custom_records))
        } else {
            let hold_time = Duration::from_secs((req.incoming_expiry_height * 10 * 60).into());

            log::info!(
                "Jamming HTLC from target -> attacker accountable, holding for {:?}: {}",
                hold_time,
                print_request(&req),
            );

            self.payment_trigger.0.trigger();

            // If this is one of our jamming payments, hold it
            select! {
                _ = req.shutdown_listener.clone() => Ok(Err(ForwardingError::InterceptorError("shutdown signal received".to_string()))),
                _ = self.clock.sleep(hold_time) => {
                    self.jamming_payments.lock().await.remove(&req.payment_hash);
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
        // - Jam the general and congestion resources with jammer helper. This will require extra
        // calculation of cost of these.
        // - With sufficient reputation, slow jam protected resources by holding payment for the
        // entire expiry time.

        // Before running attack, make an "honest" payment over route with our target channel to
        // jam. At this point it should succeed. We then check that after jamming the channel, a
        // payment over this same route should fail.
        let test_hops = vec![
            self.channel_to_jam.0,
            self.target_pubkey,
            self.honest_receiver.1,
        ];

        let sender = attacker_nodes.get(&self.honest_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.honest_sender.0
        ))?;

        let check_payment = async |expect_succeed: bool| -> Result<(), BoxError> {
            let sanity_check_route = build_custom_route(
                &self.honest_sender.1,
                100_000,
                &test_hops,
                &self.network_graph,
            )
            .map_err(|e| e.err)?;

            let payment_hash = PaymentHash(rand::random());
            if let Err(e) = sender
                .lock()
                .await
                .send_to_route(sanity_check_route, payment_hash, None)
                .await
            {
                return Err(e.to_string().into());
            }

            let payment_result = sender
                .lock()
                .await
                .track_payment(&payment_hash, shutdown_listener.clone())
                .await?;

            match payment_result.payment_outcome {
                PaymentOutcome::Success => {
                    if expect_succeed {
                        log::info!("Test payment before jamming the channel succeeded as expected");
                    } else {
                        return Err("Test payment after jamming the channel did not fail".into());
                    }
                }
                _ => {
                    if expect_succeed {
                        return Err("Test payment before jamming failed.".into());
                    } else {
                        log::info!("Test payment after jamming the channel failed as expected.");
                    }
                }
            }
            Ok(())
        };

        check_payment(true).await?;

        let _ = self.build_reputation(&attacker_nodes).await?;

        self.channel_jammer
            .jam_general_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        self.channel_jammer
            .jam_congestion_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        // After building reputation and jamming general resources, jam protected resources.
        self.slow_jam_channel(&attacker_nodes).await?;

        // Wait for signal that our jamming payment is being held to then send our test payment to
        // check it fails.
        self.payment_trigger.1.clone().await;

        // With protected resources jammed, check that test payment fails.
        check_payment(false).await?;

        // Return when we are finished holding the payment.
        loop {
            let jamming_payments_lock = self.jamming_payments.lock().await;
            if jamming_payments_lock.is_empty() {
                break;
            }

            self.clock.sleep(Duration::from_secs(60 * 5)).await;
        }

        Ok(())
    }
}
