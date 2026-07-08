//! Protected-bucket jamming attacks that fill the target's protected resources and hold them,
//! topping up reputation as it decays so the jam can be sustained.
//!
//! One configurable implementation covers three scenarios (the slow liquidity variant is already
//! served by [`super::slow_jam`]):
//! - **slow slot**: exhaust the protected *slot count* with many tiny HTLCs, held for the full
//!   duration (~2 weeks).
//! - **fast slot**: same slot fill, but held ~85s and repeated for up to 2 weeks (staying out of
//!   the >90s zone where opportunity-cost penalties bite).
//! - **fast liquidity**: exhaust the protected *liquidity* with a few large HTLCs (each bounded so
//!   it stays individually admittable), held ~85s and repeated.
//!
//! All variants congest the general bucket first, then fill protected, and refill reputation only
//! when it has decayed below the target's revenue threshold (paying exactly the deficit), tracking
//! the fees paid so the attack's cost is reported.

use crate::{
    attacks::{
        utils::{build_custom_route, build_reputation},
        AttackStatisitcs, JammingAttack,
    },
    clock::InstantClock,
    reputation_interceptor::{ChannelJammer, ReputationMonitor},
    BoxError, NetworkReputation,
};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::{ln::PaymentHash, routing::gossip::NetworkGraph};
use ln_resource_mgr::forward_manager::{ForwardManagerParams, MAX_HTLC_SLOTS};
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
use triggered::Listener;

use super::utils::BuildReputationParams;

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

/// How the protected bucket is filled.
#[derive(Clone, Copy, Debug)]
pub enum FillMode {
    /// Exhaust the protected *slot count*: send one HTLC of `htlc_msat` per protected slot (derived
    /// from the reputation params, not hardcoded). Use a tiny amount, e.g. 1 sat, so slots run out
    /// long before liquidity does.
    Slots { htlc_msat: u64 },
    /// Exhaust the protected *liquidity* with a single HTLC sized to the jammed channel's protected
    /// liquidity bucket (derived from its capacity and the bucket portions, not hardcoded).
    Liquidity,
}

/// Configuration that distinguishes the slot/liquidity and slow/fast variants.
#[derive(Clone, Copy, Debug)]
pub struct JamConfig {
    pub fill: FillMode,
    /// How long each fill is held in flight.
    pub hold_time: Duration,
    /// If true, release after `hold_time` and re-fill, repeating until `total_duration` elapses.
    /// If false, a single fill is held for `hold_time` (the slow variant).
    pub repeat: bool,
    /// Overall attack window (only used when `repeat` is true).
    pub total_duration: Duration,
}

/// Number of attempts to build the initial reputation (it can fall just short due to the random
/// CLTV offset in route building; each attempt still settles a paying payment, so retrying
/// converges).
const BUILD_ATTEMPTS: usize = 8;

/// Maximum size of a single HTLC used by the liquidity fill. The protected bucket is exhausted with
/// several of these rather than one giant HTLC, so each stays individually admittable.
const LIQ_HTLC_CHUNK_MSAT: u64 = 1_000_000_000;

pub struct SlotLiqJam<R, J>
where
    R: ReputationMonitor + Send + Sync + 'static,
    J: ChannelJammer + Send + Sync + 'static,
{
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    attacker_sender: (String, PublicKey),
    attacker_receiver: (String, PublicKey),
    target_channels: HashMap<u64, PublicKey>,
    channel_to_jam: (PublicKey, u64),
    reputation_monitor: Arc<R>,
    channel_jammer: Arc<J>,
    network_graph: Arc<LdkNetworkGraph>,
    jamming_payments: Arc<Mutex<HashSet<PaymentHash>>>,
    reputation_params: ForwardManagerParams,
    /// Capacity (msat) of the channel being jammed, used to size the liquidity fill.
    jammed_capacity_msat: u64,
    config: JamConfig,
    // Stats. Entry is the one-time cost to gain protected access; sustaining is the recurring
    // decay-driven maintenance — splitting them makes the "pay once, hold cheaply" economics
    // visible in the results.
    entry_fees: AtomicU64,
    sustaining_fees: AtomicU64,
    refill_count: AtomicU64,
}

impl<R, J> SlotLiqJam<R, J>
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
        channel_to_jam: (PublicKey, u64),
        reputation_monitor: Arc<R>,
        channel_jammer: Arc<J>,
        network_graph: Arc<LdkNetworkGraph>,
        config: JamConfig,
    ) -> Self {
        let jammed_capacity_msat = network
            .iter()
            .find(|channel| u64::from(channel.scid) == channel_to_jam.1)
            .map(|channel| channel.capacity_msat)
            .unwrap_or(0);
        Self {
            clock,
            target_pubkey,
            attacker_sender,
            attacker_receiver,
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
            jammed_capacity_msat,
            config,
            entry_fees: AtomicU64::new(0),
            sustaining_fees: AtomicU64::new(0),
            refill_count: AtomicU64::new(0),
        }
    }

    /// Number of protected-bucket slots on the jammed channel, derived from the reputation params:
    /// `MAX_HTLC_SLOTS * (100 − general_portion − congestion_portion) / 100`. The slot jam aims to
    /// occupy exactly this many, so it adapts to whatever bucket split the algo under test uses.
    fn protected_slot_count(&self) -> usize {
        let g = self.reputation_params.general_slot_portion as u16;
        let c = self.reputation_params.congestion_slot_portion as u16;
        (MAX_HTLC_SLOTS * (100 - g - c) / 100) as usize
    }

    /// Liquidity (msat) allocated to the protected bucket on the jammed channel:
    /// `capacity × (100 − general_liquidity_portion − congestion_liquidity_portion) / 100`. Filling
    /// this exhausts the protected liquidity, so it adapts to the channel under attack rather than
    /// relying on a hardcoded amount.
    fn protected_liquidity_msat(&self) -> u64 {
        let g = self.reputation_params.general_liquidity_portion as u64;
        let c = self.reputation_params.congestion_liquidity_portion as u64;
        self.jammed_capacity_msat * (100 - g - c) / 100
    }

    /// The protected liquidity split into a handful of large HTLCs. A single HTLC big enough to fill
    /// the whole bucket would need a prohibitive amount of reputation to admit, so the fill is spread
    /// over several bounded HTLCs (each [`LIQ_HTLC_CHUNK_MSAT`] at most) that together exhaust the
    /// bucket while staying within the protected slot count.
    fn liquidity_htlcs(&self) -> Vec<u64> {
        let total = self.protected_liquidity_msat();
        if total == 0 {
            return vec![];
        }
        let count = total
            .div_ceil(LIQ_HTLC_CHUNK_MSAT)
            .max(1)
            .min(self.protected_slot_count() as u64);
        let each = total / count;
        vec![each; count as usize]
    }

    /// The protected-bucket HTLC amounts the attacker wants to keep alive (drives htlc_risk).
    fn protected_htlcs(&self) -> Vec<u64> {
        match self.config.fill {
            FillMode::Slots { htlc_msat } => vec![htlc_msat; self.protected_slot_count()],
            FillMode::Liquidity => self.liquidity_htlcs(),
        }
    }

    /// Route used to build/refill reputation: target -> attacker_receiver (sender prepended by the
    /// build helper). Does not traverse the channel being jammed, so it doesn't bump that channel's
    /// revenue.
    fn build_hops(&self) -> [PublicKey; 2] {
        [self.target_pubkey, self.attacker_receiver.1]
    }

    /// Builds the attacker's initial reputation, retrying a few times since the one-shot fee can
    /// fall just short of the sufficiency check.
    async fn build_initial_reputation(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
    ) -> Result<(), BoxError> {
        let attacker_node = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;
        let hops = self.build_hops();
        let mut last_err = None;
        for attempt in 0..BUILD_ATTEMPTS {
            let params = BuildReputationParams {
                attacker_node: Arc::clone(attacker_node),
                hops: &hops,
                network_graph: &self.network_graph,
                htlcs: self.protected_htlcs(),
                target_channel: (self.target_pubkey, self.channel_to_jam.1),
                reputation_monitor: Arc::clone(&self.reputation_monitor),
                payment_hash: PaymentHash(rand::random()),
                reputation_params: self.reputation_params,
                clock: Arc::clone(&self.clock),
                shutdown_listener: triggered::trigger().1,
                fee_buffer: 5000,
            };
            match build_reputation(params).await {
                Ok(fees) => {
                    self.entry_fees.fetch_add(fees, Ordering::Relaxed);
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("build_reputation attempt {attempt} did not reach threshold ({e})");
                    last_err = Some(e);
                }
            }
        }
        Err(format!(
            "could not build attacker reputation after {BUILD_ATTEMPTS} attempts: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )
        .into())
    }

    /// Maintains the attacker's reputation against the decaying average eroding it. Delegates to
    /// [`build_reputation`], which reads the live reputation and pays exactly the deficit needed to
    /// stay above `revenue + htlc_risk` (or only a small carrier fee when reputation is already
    /// sufficient) — so the accumulated fees are the true decay-driven sustaining cost, with no
    /// margin guesswork. Each maintenance cycle is counted in `refill_count`.
    async fn refill(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        let attacker_node = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;
        let hops = self.build_hops();
        let params = BuildReputationParams {
            attacker_node: Arc::clone(attacker_node),
            hops: &hops,
            network_graph: &self.network_graph,
            htlcs: self.protected_htlcs(),
            target_channel: (self.target_pubkey, self.channel_to_jam.1),
            reputation_monitor: Arc::clone(&self.reputation_monitor),
            payment_hash: PaymentHash(rand::random()),
            reputation_params: self.reputation_params,
            clock: Arc::clone(&self.clock),
            shutdown_listener,
            // Exact: build only the deficit, and only when reputation has actually fallen below the
            // threshold (build_reputation returns 0 without paying when it is still sufficient).
            fee_buffer: 0,
        };
        let fees = build_reputation(params).await?;
        // Only a refill that actually paid counts: reputation often still covers the threshold, in
        // which case build_reputation returns 0 without sending anything.
        if fees > 0 {
            self.sustaining_fees.fetch_add(fees, Ordering::Relaxed);
            self.refill_count.fetch_add(1, Ordering::Relaxed);
            log::info!("reputation maintenance cycle: paid {fees} msat");
        }
        Ok(())
    }

    /// Sends one round of protected-bucket fill payments (held by `intercept_attacker_receive`).
    /// Returns the number of HTLCs successfully sent.
    async fn send_fill(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
    ) -> Result<usize, BoxError> {
        let sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;
        let hops = vec![
            self.channel_to_jam.0,
            self.target_pubkey,
            self.attacker_receiver.1,
        ];
        let (count, amt) = match self.config.fill {
            FillMode::Slots { htlc_msat } => (self.protected_slot_count(), htlc_msat),
            FillMode::Liquidity => {
                let htlcs = self.liquidity_htlcs();
                (htlcs.len(), htlcs.first().copied().unwrap_or(0))
            }
        };

        let mut sent = 0;
        for _ in 0..count {
            let route = match build_custom_route(
                &self.attacker_sender.1,
                amt,
                &hops,
                &self.network_graph,
            ) {
                Ok(route) => route,
                Err(e) => {
                    log::warn!("could not build fill route: {}", e.err);
                    continue;
                }
            };
            let payment_hash = PaymentHash(rand::random());
            self.jamming_payments.lock().await.insert(payment_hash);
            match sender
                .lock()
                .await
                .send_to_route(route, payment_hash, None)
                .await
            {
                Ok(_) => sent += 1,
                Err(e) => {
                    self.jamming_payments.lock().await.remove(&payment_hash);
                    log::warn!("fill payment send failed (slot/liquidity likely full): {e}");
                }
            }
        }
        Ok(sent)
    }
}

#[async_trait]
impl<R, J> JammingAttack for SlotLiqJam<R, J>
where
    R: ReputationMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    fn validate(&self) -> Result<(), BoxError> {
        // Attacker receiver must have a channel with the target.
        self.target_channels
            .iter()
            .find(|chan| self.attacker_receiver.1 == *chan.1)
            .ok_or(format!(
                "Target does not have a channel with attacker receiver {}",
                self.attacker_receiver.1
            ))?;

        // The channel we want to jam must belong to the target's channel set.
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

        Ok(())
    }

    /// Reputation-building/refill payments (not in `jamming_payments`) are forwarded so they
    /// settle; fill payments are held for `hold_time` then failed.
    async fn intercept_attacker_receive(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        if !self
            .jamming_payments
            .lock()
            .await
            .contains(&req.payment_hash)
        {
            return Ok(Ok(req.incoming_custom_records));
        }

        select! {
            _ = req.shutdown_listener.clone() => Ok(Err(ForwardingError::InterceptorError(
                "shutdown signal received".to_string(),
            ))),
            _ = self.clock.sleep(self.config.hold_time) => {
                self.jamming_payments.lock().await.remove(&req.payment_hash);
                Ok(Err(ForwardingError::InterceptorError(
                    "failing from jamming interceptor".into(),
                )))
            }
        }
    }

    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        let start = InstantClock::now(&*self.clock);

        // Gain protected access, then congest the cheaper buckets.
        self.build_initial_reputation(&attacker_nodes).await?;
        self.channel_jammer
            .jam_general_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;
        self.channel_jammer
            .jam_congestion_resources(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        let mut round = 0u64;
        loop {
            // Keep reputation above the threshold before (re)filling.
            if let Err(e) = self
                .refill(&attacker_nodes, shutdown_listener.clone())
                .await
            {
                log::warn!("refill on round {round} failed (continuing): {e}");
            }

            let sent = self.send_fill(&attacker_nodes).await?;
            log::info!(
                "round {round}: sent {sent} jamming HTLC(s), holding for {:?}",
                self.config.hold_time
            );

            // Hold for the configured time, refilling reputation periodically as the decaying
            // average erodes it. The revenue threshold decays too (the jammed channel earns
            // nothing), but we top up whenever reputation would fall within the margin so the jam
            // is never evicted — this is the decay-driven sustaining cost. +10s buffer so the
            // interceptor releases before the next round.
            let hold_end =
                InstantClock::now(&*self.clock) + self.config.hold_time + Duration::from_secs(10);
            let check_interval = (self.reputation_params.reputation_params.revenue_window / 4)
                .max(Duration::from_secs(1));
            let mut interrupted = false;
            loop {
                let now = InstantClock::now(&*self.clock);
                if now >= hold_end {
                    break;
                }
                let nap = (hold_end - now).min(check_interval);
                select! {
                    _ = shutdown_listener.clone() => { interrupted = true; break; }
                    _ = self.clock.sleep(nap) => {}
                }
                if let Err(e) = self
                    .refill(&attacker_nodes, shutdown_listener.clone())
                    .await
                {
                    log::warn!("decay refill on round {round} failed (continuing): {e}");
                }
            }
            if interrupted {
                break;
            }

            round += 1;
            if !self.config.repeat {
                break;
            }
            if InstantClock::now(&*self.clock).duration_since(start) >= self.config.total_duration {
                log::info!("reached total attack duration after {round} round(s)");
                break;
            }
        }

        Ok(())
    }

    fn attack_statistics(&self) -> Result<AttackStatisitcs, BoxError> {
        let entry = self.entry_fees.load(Ordering::Relaxed);
        let sustaining = self.sustaining_fees.load(Ordering::Relaxed);
        Ok(AttackStatisitcs {
            general_jammed_channels: 1,
            congestion_jammed_channels: 1,
            entry_fees_paid_msat: entry,
            sustaining_fees_paid_msat: sustaining,
            total_fees_paid_msat: entry + sustaining,
            refill_count: self.refill_count.load(Ordering::Relaxed),
        })
    }
}
