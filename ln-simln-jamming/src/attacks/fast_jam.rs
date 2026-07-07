use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::PaymentHash;
use lightning::routing::gossip::NetworkGraph;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::sim_node::{
    CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode, WrappedLog,
};
use simln_lib::LightningNode;
use tokio::select;
use tokio::sync::Mutex;
use triggered::Listener;

use crate::BoxError;
use crate::NetworkReputation;

use super::utils::{build_custom_route, dispatch_attacker_payment};
use super::{AttackCost, AttackStatisitcs, JammingAttack};

/// Default duration the fast jam runs for, in seconds (30 days), matching the peacetime baseline
/// window so the co-simulated peacetime and attack revenue cover the same span. The engine's
/// revenue-drop monitor will usually stop the run earlier if the jam succeeds.
const DEFAULT_RUN_SECS: u64 = 30 * 24 * 60 * 60;
const RUN_SECS_ENV: &str = "BASELINE_SECS";

/// Number of HTLC slots in a channel's *general* bucket. `ForwardManagerParams::default` gives the
/// general bucket 40% of the protocol-max 483 slots (= 193). To make an incoming channel reject
/// honest unaccountable HTLCs with `no general resources`, the attacker must keep this many of its
/// own unaccountable HTLCs simultaneously in flight over that channel, so the bucket's `slots_used`
/// reaches `slots_available` and no free slot remains for an honest payment.
const GENERAL_BUCKET_SLOTS: usize = 193;

/// Size of each jamming HTLC. Tiny, so that (a) the binding constraint on the target's general
/// bucket is its *slot* count (193), not its liquidity, letting us jam with minimal committed
/// capital, and (b) the routing fee — and therefore the 1% unconditional fee we pay on every
/// attempt — is as small as possible (dominated by the honest hops' base fee).
const JAM_HTLC_MSAT: u64 = 1_000;

/// Virtual time to advance between refill passes. Each pass tops every jammed channel back up to
/// `GENERAL_BUCKET_SLOTS` in-flight HTLCs; sleeping lets the ~150ms-per-hop latencies elapse so the
/// previous batch resolves (fast-fails) and frees slots for us to refill. Small relative to a
/// payment's round trip so occupancy stays high.
const REFILL_INTERVAL: Duration = Duration::from_millis(100);

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

/// A single incoming channel of the target that we keep jammed, together with the in-flight
/// accounting used to hold it exactly full.
struct JammedChannel {
    /// The target's honest peer on this channel. Our jamming HTLCs are routed *in* through this
    /// peer so that they arrive at the target over the (honest) peer -> target channel, consuming
    /// that channel's general-bucket slots at the target.
    peer_pubkey: PublicKey,
    /// Number of our HTLCs currently in flight over this channel. Kept at `GENERAL_BUCKET_SLOTS`
    /// so the target's general bucket for this channel stays full. Decremented when a payment
    /// resolves (fast-fails) and its slot frees, so the refill loop redispatches. Shared (`Arc`)
    /// with the per-payment resolution task that does the decrement.
    in_flight: Arc<AtomicUsize>,
}

/// FastJam mounts a *fast* channel jam: an endless stream of small, fast-failing HTLCs the attacker
/// pushes through the target to keep its channels' general-bucket HTLC slots full, so honest
/// unaccountable payments the target would otherwise forward are rejected with `no general
/// resources`.
///
/// # Mechanism (why this moves the target's revenue)
///
/// The mitigation checks resources on the *incoming* channel of a forward. Each jammed channel is
/// therefore driven by routing HTLCs
///
/// ```text
///   attacker_sender -> honest_peer -> target -> attacker_receiver
/// ```
///
/// so that at the target the HTLC arrives over the honest `honest_peer -> target` channel and
/// occupies a slot in *that* channel's general bucket. Hold `GENERAL_BUCKET_SLOTS` (193) of these
/// in flight and the bucket is full: any honest, reputation-less unaccountable payment that would
/// enter the target over `honest_peer` is failed back with `no general resources` instead of being
/// forwarded, so the target never earns that forwarding fee. Do this on the target's busiest
/// incoming channels and its settled routing revenue falls below the co-simulated peacetime
/// network's.
///
/// The HTLCs are *not held*: they are failed the instant they reach the attacker's receiver
/// (`intercept_attacker_receive`). Each one therefore occupies its slot only for its network
/// round-trip latency, so keeping the bucket full requires a continuous high dispatch rate. The
/// mitigation's defence against exactly this is the **unconditional fee**: every attempt — success
/// or fast-fail — pays 1% of its routing fee. The attack is only worthwhile if the target's
/// revenue loss exceeds the total of those unconditional fees; both are measured and reported.
pub struct FastJam {
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    /// Alias of the attacker node that originates the jamming payments; looked up in the node map
    /// handed to `run_attack`.
    sender_alias: String,
    /// The attacker node that receives (and immediately fails) the jamming payments; the last hop
    /// of every jamming route.
    receiver_pubkey: PublicKey,
    /// The target's channels we keep jammed, one per honest peer we route in through.
    jammed_channels: Vec<JammedChannel>,
    network_graph: Arc<LdkNetworkGraph>,
    run_for: Duration,
    attack_cost: Arc<AttackCost>,
}

impl FastJam {
    pub fn new(
        clock: Arc<SimulationClock>,
        target_pubkey: PublicKey,
        sender_alias: String,
        receiver_pubkey: PublicKey,
        peers_to_jam: Vec<PublicKey>,
        network_graph: Arc<LdkNetworkGraph>,
        attack_cost: Arc<AttackCost>,
    ) -> Self {
        let secs = std::env::var(RUN_SECS_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RUN_SECS);

        let jammed_channels = peers_to_jam
            .into_iter()
            .map(|peer_pubkey| JammedChannel {
                peer_pubkey,
                in_flight: Arc::new(AtomicUsize::new(0)),
            })
            .collect();

        Self {
            clock,
            target_pubkey,
            sender_alias,
            receiver_pubkey,
            jammed_channels,
            network_graph,
            run_for: Duration::from_secs(secs),
            attack_cost,
        }
    }
}

#[async_trait]
impl JammingAttack for FastJam {
    fn validate(&self) -> Result<(), BoxError> {
        if self.jammed_channels.is_empty() {
            return Err("fast jam has no target channels to jam".into());
        }
        Ok(())
    }

    /// Any HTLC that an attacker node is asked to *forward* is honest traffic trying to use our
    /// channels as a relay. We fail it so the attacker never adds routing capacity to the graph:
    /// our own jamming payments originate at the sender and terminate at the receiver, so they are
    /// never forwarded by an attacker node and never reach this path. Failing here keeps the
    /// peacetime-vs-attack comparison clean (the attacker gifts the target no extra routing).
    async fn intercept_attacker_htlc(
        &self,
        _req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        Ok(Err(ForwardingError::InterceptorError(
            "fast jam attacker does not relay honest traffic".into(),
        )))
    }

    /// Fail every received HTLC immediately. All receives here are our own jamming payments
    /// arriving at the attacker's receiver; failing them at once (rather than holding them) is what
    /// makes this a *fast* jam — each HTLC occupies its slot only for the round-trip latency, and
    /// the failure propagates back to free the slot so the refill loop can redispatch.
    ///
    /// A diagnostic `FASTJAM_HOLD_MS` env var can add a fixed hold before failing. It defaults to 0
    /// (pure fast-fail). It exists only to probe slot occupancy: a pure fast-fail HTLC occupies the
    /// target's general-bucket slot for only its (near-zero, in this sim) round-trip latency, so a
    /// non-zero hold is a way to check that the jamming route itself is correct by forcing the
    /// bucket to fill. The committed attack leaves it at 0.
    async fn intercept_attacker_receive(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        let hold_ms = std::env::var("FASTJAM_HOLD_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        if hold_ms > 0 {
            select! {
                _ = req.shutdown_listener.clone() => {},
                _ = self.clock.sleep(Duration::from_millis(hold_ms)) => {},
            }
        }

        Ok(Err(ForwardingError::InterceptorError(
            "fast jam fast-fail".into(),
        )))
    }

    /// Keep every jammed channel's general bucket full for the configured duration by continuously
    /// topping its in-flight jamming HTLCs back up to `GENERAL_BUCKET_SLOTS`. Returns (ending the
    /// sim) when the run duration elapses or a shutdown is signalled — including by the engine's
    /// revenue-drop monitor once the jam has pushed the target below peacetime.
    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        let sender = attacker_nodes
            .get(&self.sender_alias)
            .ok_or(format!(
                "fast jam sender {} not found in attacker nodes",
                self.sender_alias
            ))?
            .clone();

        let sender_pubkey = sender.lock().await.get_info().pubkey;

        log::info!(
            "FastJam: jamming {} of the target's incoming channels, holding {} HTLCs in flight each, for {:?}",
            self.jammed_channels.len(),
            GENERAL_BUCKET_SLOTS,
            self.run_for,
        );

        // Precompute the (static) jamming route for each channel once. The route is identical on
        // every attempt — only the payment hash changes — so building it once and cloning avoids
        // rerunning LDK pathfinding (the dominant per-dispatch cost) on every HTLC.
        let mut routes = Vec::with_capacity(self.jammed_channels.len());
        for channel in &self.jammed_channels {
            // Route: attacker_sender -> honest_peer -> target -> attacker_receiver. The HTLC
            // arrives at the target over the honest peer -> target channel, so it consumes a slot
            // in that channel's general bucket at the target.
            let hops = [channel.peer_pubkey, self.target_pubkey, self.receiver_pubkey];
            let route = build_custom_route(&sender_pubkey, JAM_HTLC_MSAT, &hops, &self.network_graph)
                .map_err(|e| e.err)?;
            routes.push(route);
        }

        let deadline = self.clock.now() + self.run_for;

        loop {
            // Stop if we've been shut down (e.g. the revenue-drop monitor fired) or reached the
            // fixed run duration that matches the peacetime window.
            if shutdown_listener.is_triggered() || self.clock.now() >= deadline {
                break;
            }

            // One refill pass: for every jammed channel, dispatch enough new HTLCs to bring its
            // in-flight count back up to a full general bucket. Slots freed by HTLCs that have
            // fast-failed since the last pass are refilled here.
            for (channel, route) in self.jammed_channels.iter().zip(routes.iter()) {
                loop {
                    let in_flight = channel.in_flight.load(Ordering::Relaxed);
                    if in_flight >= GENERAL_BUCKET_SLOTS {
                        break;
                    }

                    let route = route.clone();
                    let payment_hash = PaymentHash(rand::random());

                    // Dispatch through the shared helper so the unconditional fee (and, if it ever
                    // succeeded, the success-case fee) is charged to the attack cost accumulator.
                    // Sent unaccountable (no custom records) so the HTLC lands in the general
                    // bucket.
                    match dispatch_attacker_payment(
                        &sender,
                        route,
                        payment_hash,
                        None,
                        Arc::clone(&self.attack_cost),
                        shutdown_listener.clone(),
                    )
                    .await
                    {
                        Ok(handle) => {
                            channel.in_flight.fetch_add(1, Ordering::Relaxed);

                            // Decrement this channel's in-flight count when the payment resolves
                            // (it will fast-fail), so the next refill pass redispatches into the
                            // freed slot. Awaits the tracking handle the dispatch helper already
                            // spawned, adding no cost accounting of its own.
                            let counter = Arc::clone(&channel.in_flight);
                            tokio::spawn(async move {
                                let _ = handle.await;
                                counter.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        // A dispatch that never entered the network incurs no cost; just stop
                        // topping up this channel for now and try again next pass.
                        Err(e) => {
                            log::debug!("FastJam dispatch failed, backing off: {e}");
                            break;
                        }
                    }
                }
            }

            // Advance virtual time so the in-flight HTLCs' latencies elapse and they resolve,
            // freeing slots for the next refill pass. Exit promptly on shutdown.
            select! {
                _ = shutdown_listener.clone() => break,
                _ = self.clock.sleep(REFILL_INTERVAL) => {},
            }
        }

        // Wait for outstanding jamming payments to resolve so their cost is finalised before the
        // summary is written.
        self.attack_cost.wait_for_pending_payments().await;

        Ok(())
    }

    fn attack_statistics(&self) -> Result<AttackStatisitcs, BoxError> {
        Ok(AttackStatisitcs {
            // We jam the target's incoming general buckets by driving real HTLCs, not via the
            // ChannelJammer helper, so we report zero helper-jammed channels here; the channels we
            // keep full are reflected in the attacker's committed channels and payment fees.
            general_jammed_channels: 0,
            congestion_jammed_channels: 0,
            // real HTLCs, not the helper.
            estimated_jam_channels: 0,
        })
    }
}
