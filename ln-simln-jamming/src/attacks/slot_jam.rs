use crate::{
    attacks::JammingAttack,
    reputation_interceptor::ReputationMonitor,
    BoxError, NetworkReputation,
};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::{
    ln::PaymentHash,
    routing::gossip::NetworkGraph,
};
use simln_lib::{
    clock::{Clock, SimulationClock},
    sim_node::{CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode, WrappedLog},
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{select, sync::Mutex};
use triggered::Listener;

use super::{
    utils::{build_custom_route, dispatch_attacker_payment},
    AttackCost, AttackStatisitcs,
};

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

/// Default duration the jam is held for, in seconds (30 days), matching the peacetime baseline.
const DEFAULT_JAM_SECS: u64 = 30 * 24 * 60 * 60;
const JAM_SECS_ENV: &str = "BASELINE_SECS";

/// The *real* version of the `general`-bucket jam GeneralJam fakes with the `ChannelJammer` helper.
///
/// The general bucket assigns each *(incoming channel I, outgoing channel O)* pair a fixed set of
/// `ASSIGNED_SLOTS` (20) slots, and an HTLC forwarding I→O consumes `ceil(amount / slot_size)` of
/// them. So to deny the target's honest I→O traffic we do not need to "jam a channel" abstractly —
/// we just need to occupy O's assigned slots in I's bucket with our own **held** HTLCs. We route
/// tiny unaccountable HTLCs `attacker_sender → peer_I → target → peer_O → attacker_receiver` and
/// hold them at the receiver: each pins one slot of the (peer_I→target, target→peer_O) pair until
/// the run ends. A tiny amount consumes a single slot, so the capital locked is negligible; the
/// only real costs are the attacker's channels to the target's peers and the 1% unconditional fee
/// paid once per held HTLC.
///
/// This is what makes the general jam a *measurable, cheap* attack rather than the ~140-channel
/// estimate the helper implies: occupancy is bounded per channel *pair*, and held HTLCs genuinely
/// occupy slots (unlike FastJam's fast-failed ones, which resolve before they accumulate).
pub struct SlotJam<R>
where
    R: ReputationMonitor + Send + Sync,
{
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    /// (alias, pubkey) of the attacker node that originates the held HTLCs.
    attacker_sender: (String, PublicKey),
    /// pubkey of the attacker node that receives and holds them.
    attacker_receiver: PublicKey,
    /// The target's honest peers; we jam every ordered pair of distinct peers.
    target_peers: Vec<PublicKey>,
    network_graph: Arc<LdkNetworkGraph>,
    /// Payment hashes of our jamming HTLCs, so `intercept_attacker_receive` knows to hold them.
    jamming_payments: Arc<Mutex<HashSet<PaymentHash>>>,
    attack_cost: Arc<AttackCost>,
    /// Reputation monitor kept for symmetry with the other attacks (unused directly here).
    _reputation_monitor: Arc<R>,
    /// How many held HTLCs to send per (I, O) pair. ~ASSIGNED_SLOTS with a little headroom.
    htlcs_per_pair: usize,
    /// Cap on how many (I, O) pairs to jam (the highest-capacity pairs first).
    max_pairs: usize,
    /// Amount per jamming HTLC — small enough to consume a single slot, large enough to clear
    /// honest channels' min-htlc policies.
    htlc_amount_msat: u64,
    run_for: Duration,
    /// Number of (I, O) pairs we actually filled, for the statistics summary.
    pairs_jammed: StdMutex<usize>,
}

impl<R> SlotJam<R>
where
    R: ReputationMonitor + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<SimulationClock>,
        target_pubkey: PublicKey,
        attacker_sender: (String, PublicKey),
        attacker_receiver: PublicKey,
        target_peers: Vec<PublicKey>,
        network_graph: Arc<LdkNetworkGraph>,
        reputation_monitor: Arc<R>,
        attack_cost: Arc<AttackCost>,
    ) -> Self {
        let secs = std::env::var(JAM_SECS_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_JAM_SECS);
        // Tunable via env: how many held HTLCs per pair (≈ ASSIGNED_SLOTS to fill it) and how many
        // (I,O) pairs to jam. Jamming every pair pins hundreds of HTLCs in flight, which the sim's
        // per-forward in-flight bookkeeping makes quadratically slow, so we jam the highest-value
        // pairs (target_peers is pre-sorted by channel capacity descending).
        let htlcs_per_pair = std::env::var("SLOTJAM_HTLCS_PER_PAIR")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(22);
        let max_pairs = std::env::var("SLOTJAM_MAX_PAIRS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(6);

        Self {
            clock,
            target_pubkey,
            attacker_sender,
            attacker_receiver,
            target_peers,
            network_graph,
            jamming_payments: Arc::new(Mutex::new(HashSet::new())),
            attack_cost,
            _reputation_monitor: reputation_monitor,
            htlcs_per_pair,
            max_pairs,
            htlc_amount_msat: 10_000,
            run_for: Duration::from_secs(secs),
            pairs_jammed: StdMutex::new(0),
        }
    }
}

#[async_trait]
impl<R> JammingAttack for SlotJam<R>
where
    R: ReputationMonitor + Send + Sync,
{
    fn validate(&self) -> Result<(), BoxError> {
        if self.target_peers.len() < 2 {
            return Err("SlotJam needs the target to have at least two peers".into());
        }
        Ok(())
    }

    /// For every ordered pair of distinct target peers (I, O), fire a batch of held HTLCs that
    /// forward in on I and out on O so they occupy O's assigned general slots in I's bucket. Then
    /// hold until the run ends.
    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        let sender_node = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "attacker sender {} not found in attacker nodes",
            self.attacker_sender.0
        ))?;

        let dispatch_start = Clock::now(&*self.clock);
        let mut pairs = 0;
        'outer: for &peer_out in self.target_peers.iter() {
            for &peer_in in self.target_peers.iter() {
                if peer_in == peer_out {
                    continue;
                }
                if pairs >= self.max_pairs {
                    break 'outer;
                }

                // Route: sender -> peer_in -> target -> peer_out -> receiver. The forward at the
                // target is (peer_in->target incoming, target->peer_out outgoing), so it consumes
                // the (target->peer_out) channel's slots in the (peer_in->target) general bucket.
                let hops = vec![
                    peer_in,
                    self.target_pubkey,
                    peer_out,
                    self.attacker_receiver,
                ];
                let route = match build_custom_route(
                    &self.attacker_sender.1,
                    self.htlc_amount_msat,
                    &hops,
                    &self.network_graph,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        log::warn!(
                            "SlotJam: could not build route for pair ({peer_in} -> {peer_out}): {}",
                            e.err
                        );
                        continue;
                    }
                };

                // Fire a batch of held HTLCs to fill this pair's assigned slots. Extras beyond the
                // slot cap simply fail to be admitted (and pay only the unconditional fee).
                for _ in 0..self.htlcs_per_pair {
                    let payment_hash = PaymentHash(rand::random());
                    self.jamming_payments.lock().await.insert(payment_hash);

                    // Non-blocking: the payment goes in flight and is tracked on a background task.
                    // We drop the handle; the HTLC stays in flight (occupying its slot) until we
                    // fail it on shutdown in intercept_attacker_receive.
                    if let Err(e) = dispatch_attacker_payment(
                        sender_node,
                        route.clone(),
                        payment_hash,
                        None,
                        Arc::clone(&self.attack_cost),
                        shutdown_listener.clone(),
                    )
                    .await
                    {
                        self.jamming_payments.lock().await.remove(&payment_hash);
                        log::warn!("SlotJam: dispatch failed for ({peer_in} -> {peer_out}): {e}");
                    }
                }
                pairs += 1;
            }
        }

        *self.pairs_jammed.lock().unwrap() = pairs;
        let dispatch_secs = Clock::now(&*self.clock)
            .duration_since(dispatch_start)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        log::info!(
            "SlotJam: fired {} held HTLCs across {} (incoming, outgoing) pairs in {} virtual seconds; holding until shutdown",
            pairs * self.htlcs_per_pair,
            pairs,
            dispatch_secs,
        );

        // Hold the jam in place for the run, then return to trigger shutdown.
        select! {
            _ = shutdown_listener => {},
            _ = self.clock.sleep(self.run_for) => {},
        }

        Ok(())
    }

    /// Hold every jamming HTLC in flight (so it keeps occupying its general slot) until the
    /// simulation shuts down, then fail it.
    async fn intercept_attacker_receive(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        if !self.jamming_payments.lock().await.contains(&req.payment_hash) {
            return Ok(Ok(req.incoming_custom_records));
        }

        // Hold the HTLC in flight until the simulation shuts down, keeping its slot occupied the
        // whole run, then fail it. (A real attacker refreshes the HTLC every ~2 weeks, the max the
        // general bucket allows a single HTLC to be held; here we simply hold to the run's end.)
        req.shutdown_listener.clone().await;

        self.jamming_payments.lock().await.remove(&req.payment_hash);
        Ok(Err(ForwardingError::InterceptorError(
            "SlotJam releasing held htlc".to_string(),
        )))
    }

    fn attack_statistics(&self) -> Result<AttackStatisitcs, BoxError> {
        Ok(AttackStatisitcs {
            // Report the number of (incoming, outgoing) pairs we pinned; the general jam here is
            // done with real held HTLCs, not the ChannelJammer helper.
            general_jammed_channels: *self.pairs_jammed.lock().unwrap(),
            congestion_jammed_channels: 0,
            // real held HTLCs, not the helper; the channels used are graph channels.
            estimated_jam_channels: 0,
        })
    }
}
