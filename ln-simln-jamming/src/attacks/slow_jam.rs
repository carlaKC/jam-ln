use crate::{
    attacks::JammingAttack,
    clock::InstantClock,
    reputation_interceptor::{GeneralChannelJammer, ReputationMonitor},
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
    thread,
    time::Duration,
};
use tokio::sync::Mutex;
use triggered::{trigger, Listener};

use super::utils::{build_custom_route, build_reputation, BuildReputationParams};

// idea: attacker1 -> peer1 -> target -> attacker2
// build reputation on attacker2 and jam channel peer1 <-> target

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

pub struct SlowJam<C, J, R>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    J: GeneralChannelJammer + Send + Sync,
{
    clock: Arc<C>,
    target_pubkey: PublicKey,
    attacker_sender: (String, PublicKey),
    attacker: (String, PublicKey),
    target_channels: HashMap<u64, PublicKey>,
    channel_to_jam: (PublicKey, u64),
    risk_margin: u64,
    reputation_monitor: Arc<Mutex<R>>,
    general_jammer: Arc<Mutex<J>>,
    network_graph: Arc<LdkNetworkGraph>,
    jamming_payments: Mutex<HashSet<PaymentHash>>,
}

impl<C, J, R> SlowJam<C, J, R>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    J: GeneralChannelJammer + Send + Sync,
{
    pub fn new(
        clock: Arc<C>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        attacker_sender: (String, PublicKey),
        attacker: (String, PublicKey),
        channel_to_jam: (PublicKey, u64),
        risk_margin: u64,
        reputation_monitor: Arc<Mutex<R>>,
        general_jammer: Arc<Mutex<J>>,
        network_graph: Arc<LdkNetworkGraph>,
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
            risk_margin,
            reputation_monitor,
            general_jammer,
            network_graph,
            jamming_payments: Mutex::new(HashSet::new()),
        }
    }

    pub async fn build_reputation(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
    ) -> Result<u64, BoxError> {
        let hops = vec![self.target_pubkey, self.attacker.1];
        // let target_channel = self.channel_to_jam;
        let target_channel = (self.target_pubkey, self.channel_to_jam.1);

        let attacker_node_sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;

        let build_rep_params = BuildReputationParams {
            attacker_node: Arc::clone(attacker_node_sender),
            hops: &hops,
            network_graph: &self.network_graph,
            htlcs: vec![30_000_000],
            target_channel,
            reputation_monitor: Arc::clone(&self.reputation_monitor),
            payment_hash: PaymentHash(rand::random()),
            reputation_params: ForwardManagerParams::default(),
            clock: Arc::clone(&self.clock),
            shutdown_listener: trigger().1,
        };
        let fees_paid = build_reputation(build_rep_params).await?;

        if self.sufficient_reputation().await? {
            return Ok(fees_paid);
        } else {
            Err("could not build reputation".into())
        }
    }

    // Checks if the attacker has sufficient reputation on its channel with the target node to keep
    // jamming it
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

        let to_attacker_channel_snapshot = target_channel_snapshots
            .get(to_attacker_channel)
            .ok_or(format!("Channel {} not found", to_attacker_channel))?; // this shouldn't happen

        let peer_target_channel = target_channel_snapshots
            .get(&self.channel_to_jam.1)
            .ok_or(format!("Channel {} not found", self.channel_to_jam.1))?;

        let sufficient_reputation = to_attacker_channel_snapshot.outgoing_reputation
            >= peer_target_channel.bidirectional_revenue + self.risk_margin as i64;

        return Ok(sufficient_reputation);
    }

    async fn fast_jam_channel(
        &self,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
        channel_to_jam: (PublicKey, u64),
    ) -> Result<(), BoxError> {
        // at this point, we should already have built reputation and have access to protected
        // resources. Attack channel peer1 <-> target through attacker1 -> peer1 -> target -> attacker2

        let attacker_node_sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;

        // Jam resources with low-value htlcs to occupy as many slots as possible while trying not
        // to affect reputation negatively?
        let hops = vec![channel_to_jam.0, self.target_pubkey, self.attacker.1];
        let route = build_custom_route(&self.attacker_sender.1, 1_000, &hops, &self.network_graph)
            .map_err(|e| e.err)?;

        loop {
            let payment_hash = PaymentHash(rand::random());
            if let Err(e) = attacker_node_sender
                .lock()
                .await
                .send_to_route(route.clone(), payment_hash, None)
                .await
            {
                return Err(e.to_string().into());
            }
            self.jamming_payments.lock().await.insert(payment_hash);

            thread::sleep(Duration::from_millis(200));

            // do this until no more reputation
            if !self.sufficient_reputation().await? {
                break;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<C, J, R> JammingAttack for SlowJam<C, J, R>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    J: GeneralChannelJammer + Send + Sync,
{
    /// Payments where we are the receiver are most likely the ones initiated by us from [`Self::fast_jam_channel`]. Fast-jamming
    /// here so fail them immediately while trying to continuously take up protected resources on
    /// the channel we are trying to jam.
    async fn intercept_attacker_receive(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        let mut jamming_payments_lock = self.jamming_payments.lock().await;
        // If this is not a jamming payment (generated from fast_jam_channel) then let it go
        // through since it must be one where we are trying to build reputation.
        if !jamming_payments_lock.contains(&req.payment_hash) {
            Ok(Ok(req.incoming_custom_records))
        } else {
            // If we are trying to fast jam the channel, fail the payment immediately.
            jamming_payments_lock.remove(&req.payment_hash);
            Ok(Err(ForwardingError::InterceptorError(
                "failing from jamming interceptor".into(),
            )))
        }
    }

    async fn run_custom_actions(
        &self,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
        _shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        // - Build reputation with helper
        // - after building reputation, jam general resources.
        // - use congestion
        // - with sufficient reputation, continuously jam protected resources by sending slow (80s)
        //  resolving payments that don't slash reputation.

        let fees_paid = self.build_reputation(&attacker_nodes).await?;
        println!(
            "Finished building reputation. It cost {} in fees",
            fees_paid
        );

        // after building reputation, jam general resources.
        self.general_jammer
            .lock()
            .await
            .jam_channel(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        // TODO: to jam congestion, would need many channels where each will occupy one slot in
        // congestion bucket until full.

        // after building reputation and jamming general resources, jam protected resources with
        // continuous fast-failing payments.
        // NOTE: prob better to occupy protected slots with low-value htlcs.
        self.fast_jam_channel(attacker_nodes, self.channel_to_jam)
            .await?;

        Ok(())
    }

    async fn simulation_completed(
        &self,
        _start_reputation: NetworkReputation,
    ) -> Result<bool, BoxError> {
        // If attacker has no more reputation with the target, end simulation.
        if !self.sufficient_reputation().await? {
            return Ok(true);
        }

        // TODO: shutdown conditions for revenue.

        Ok(false)
    }
}
