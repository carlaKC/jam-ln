//! Looped / circular HTLC attack for maximum reputation damage per committed sat.
//!
//! # Mechanism
//!
//! The local-resource-conservation mitigation grants an *outgoing* channel access to the
//! `protected` bucket only when
//! `outgoing_channel_reputation − in_flight_risk ≥ incoming_revenue_threshold`. Reputation on an
//! outgoing channel is *lost* when the node forwards an `accountable` HTLC out over it that then
//! resolves slowly (held past the `resolution_period`): the resolution books a negative "effective
//! fee" proportional to how long the HTLC was held (see
//! `ln_resource_mgr::outgoing_channel::remove_outgoing_htlc`). While the HTLC is merely *in flight*
//! it already docks the channel's usable reputation by its worst-case opportunity cost.
//!
//! So if the attacker can make the target forward an `accountable` HTLC out over one of its
//! *honest* channels and then hold that HTLC, the target's reputation on that honest channel is
//! driven down. A single held HTLC that the target forwards out over several of its channels in
//! turn damages all of them at once — hence a *loop* that threads the target across multiple of its
//! channels.
//!
//! ## Why the loop has to end on an attacker channel with reputation
//!
//! An `accountable` HTLC is *dropped* by any hop whose outgoing channel lacks reputation
//! (`FailureReason::NoReputation`). A freshly-opened attacker channel has zero reputation, so an
//! `accountable` HTLC can never be forwarded *out* to a fresh attacker node through an honest peer —
//! it would be failed fast (no reputation damage). The one place the target *will* forward an
//! `accountable` HTLC to the attacker is a channel **the attacker has built reputation on**. We
//! therefore give the attacker a channel directly to the target and build its reputation up front
//! (exactly as `slow_jam` does), then make that channel the final hop of the loop:
//!
//! ```text
//!   attacker --> entry_peer --> target --> mid_peer --> target --> attacker
//!            (1)            (2)         (3)          (4)         (5)
//! ```
//!
//! The target crosses itself twice:
//! - hop (3) forwards out over the **honest** channel `target -> mid_peer`;
//! - hop (5) forwards out over the **attacker** channel `target -> attacker` (reputation pre-built,
//!   so the `accountable` HTLC is admitted to `protected` and reaches the attacker).
//!
//! The attacker holds the received HTLC. Because the whole route stays pending until the final hop
//! resolves, hop (3)'s in-flight HTLC on `target -> mid_peer` is held for the entire duration, and
//! when the attacker finally fails it, `target -> mid_peer` books a large negative effective fee.
//! Repeating with a different `mid_peer` each time damages several of the target's honest channels.
//!
//! ## Why damaged reputation moves revenue
//!
//! Reputation damage on its own does nothing: in peacetime everything rides the open `general`
//! bucket regardless of reputation. So we *also* jam the target's `general` buckets (via the
//! `ChannelJammer` helper). Once `general` is full, honest unaccountable traffic can only get
//! through by being *upgraded* to `protected`, which needs the outgoing channel to have reputation.
//! By destroying that reputation on the target's highest-reputation channels — the ones that would
//! otherwise rescue honest forwards under the jam — we deny the upgrade, and the honest forwards
//! fail. The target earns less than it does in the co-simulated peacetime network.
//!
//! The `ChannelJammer` helper does not charge for the (~20-per-jammed-channel) channels a real
//! attacker would need to hold the `general` buckets full; that cost is called out in the write-up.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::PaymentHash;
use lightning::routing::gossip::NetworkGraph;
use ln_resource_mgr::AccountableSignal;
use sim_cli::parsing::NetworkParser;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::sim_node::{
    CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode, WrappedLog,
};
use simln_lib::PaymentOutcome;
use tokio::select;
use tokio::sync::Mutex as TokioMutex;
use triggered::Listener;

use crate::records_from_signal;
use crate::reputation_interceptor::ChannelJammer;
use crate::{print_request, BoxError, NetworkReputation};

use super::utils::{build_custom_route, dispatch_attacker_payment};
use super::{AttackCost, AttackStatisitcs, JammingAttack};

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

/// Default duration the loop HTLCs are held / the jam is sustained, in seconds (30 days), matching
/// the peacetime baseline window so a comparable span of honest traffic flows.
const DEFAULT_HOLD_SECS: u64 = 30 * 24 * 60 * 60;
const HOLD_SECS_ENV: &str = "BASELINE_SECS";

/// Configuration for the looped attack.
pub struct LoopedHtlc<J>
where
    J: ChannelJammer + Send + Sync + 'static,
{
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    /// The attacker node that originates the loop payments (and the reputation-building payment).
    attacker_sender: (String, PublicKey),
    /// The attacker node that receives (and holds) the loop's final hop. Must differ from the
    /// sender: LDK will not build a route back to its own origin.
    attacker_receiver: (String, PublicKey),
    /// Honest peer of the target used to inject the loop into the target. Chosen for low
    /// target-incoming-revenue so the first crossing clears the reputation check.
    entry_peer: PublicKey,
    /// Honest peer used only to *prime* the receiver's reputation: settled forwards
    /// `sender -> prime_peer -> target -> receiver` book the target's (deliberately large) receive
    /// -channel fee as positive reputation on `target -> receiver`, admitting the loop's final hop.
    /// A high-revenue peer is used so the fees credited to its channel don't shift the loop's own
    /// (low-revenue) entry threshold.
    prime_peer: PublicKey,
    /// (pubkey, scid) of the honest target channels we want to damage: the loop threads the target
    /// out over each of these in turn.
    mid_peers: Vec<(PublicKey, u64)>,
    /// Every channel the target is an endpoint of; general-jammed to apply bucket pressure.
    target_channels: Vec<u64>,
    /// Amount (msat) sent around the loop. Larger amounts make the target's per-hop fee — and hence
    /// the reputation damage — larger, at the cost of more locked capital and a larger in-flight
    /// risk that honest hops must be willing to forward.
    loop_amount_msat: u64,
    /// Number of priming payments used to build the receiver's reputation.
    prime_count: usize,
    /// Amount (msat) of each priming payment.
    prime_amount_msat: u64,
    channel_jammer: Arc<J>,
    network_graph: Arc<LdkNetworkGraph>,
    attack_cost: Arc<AttackCost>,
    hold_for: Duration,
    /// Number of honest target channels general-jammed, recorded for the statistics summary.
    jammed_channels: Mutex<usize>,
    /// Payment hashes of the loop HTLCs the receiver must hold. The reputation-building payment is
    /// *not* in this set, so it is let through to settle (and build reputation) instead of held.
    loop_payments: Mutex<HashSet<PaymentHash>>,
}

impl<J> LoopedHtlc<J>
where
    J: ChannelJammer + Send + Sync,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<SimulationClock>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        attacker_sender: (String, PublicKey),
        attacker_receiver: (String, PublicKey),
        entry_peer: PublicKey,
        prime_peer: PublicKey,
        mid_peers: Vec<(PublicKey, u64)>,
        loop_amount_msat: u64,
        prime_count: usize,
        prime_amount_msat: u64,
        channel_jammer: Arc<J>,
        network_graph: Arc<LdkNetworkGraph>,
        attack_cost: Arc<AttackCost>,
    ) -> Self {
        let target_channels = network
            .iter()
            .filter_map(|channel| {
                if channel.node_1.pubkey == target_pubkey || channel.node_2.pubkey == target_pubkey {
                    Some(channel.scid.into())
                } else {
                    None
                }
            })
            .collect();

        let secs = std::env::var(HOLD_SECS_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_HOLD_SECS);

        Self {
            clock,
            target_pubkey,
            attacker_sender,
            attacker_receiver,
            entry_peer,
            prime_peer,
            mid_peers,
            target_channels,
            loop_amount_msat,
            prime_count,
            prime_amount_msat,
            channel_jammer,
            network_graph,
            attack_cost,
            hold_for: Duration::from_secs(secs),
            jammed_channels: Mutex::new(0),
            loop_payments: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl<J> JammingAttack for LoopedHtlc<J>
where
    J: ChannelJammer + Send + Sync,
{
    fn validate(&self) -> Result<(), BoxError> {
        if self.mid_peers.is_empty() {
            return Err("looped attack needs at least one mid peer to damage".into());
        }
        if self.target_channels.is_empty() {
            return Err("target has no channels".into());
        }
        Ok(())
    }

    /// Every HTLC the attacker receives here is the final hop of a loop. Hold it well past the
    /// `resolution_period` so the target's in-flight `accountable` HTLCs on the honest channels the
    /// loop crossed are held too, then fail it. Holding-then-failing an `accountable` HTLC books a
    /// large negative effective fee against each `target -> mid_peer` channel it was forwarded over.
    async fn intercept_attacker_receive(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        // Only hold loop HTLCs. Anything else the receiver gets (notably the reputation-building
        // payment) must be allowed to settle immediately so it actually builds reputation.
        if !self.loop_payments.lock().unwrap().contains(&req.payment_hash) {
            return Ok(Ok(CustomRecords::default()));
        }

        log::info!(
            "LoopedHtlc: holding received loop HTLC for {:?}: {}",
            self.hold_for,
            print_request(&req),
        );

        select! {
            _ = req.shutdown_listener.clone() => Ok(Err(ForwardingError::InterceptorError(
                "shutdown while holding loop htlc".to_string(),
            ))),
            _ = self.clock.sleep(self.hold_for) => {
                // Fail the held HTLC. The failure propagates back up the loop, resolving every
                // in-flight forward the target made for it as Failed after a long hold — booking the
                // negative effective fee that trashes the crossed channels' reputation.
                Ok(Err(ForwardingError::InterceptorError(
                    "failing held loop htlc".to_string(),
                )))
            }
        }
    }

    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        attacker_nodes: HashMap<String, Arc<TokioMutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        let sender_node = attacker_nodes
            .get(&self.attacker_sender.0)
            .ok_or(format!("attacker sender {} not found", self.attacker_sender.0))?;

        // 1) Prime the receiver's reputation on its channel with the target so that the loop's
        //    final `accountable` hop (target -> receiver) is admitted to the protected bucket and
        //    actually reaches us to be held. Without this the target would drop it (NoReputation),
        //    it would resolve fast, and no damage would be done.
        //
        //    We send a handful of small, *settling* unaccountable payments
        //    `sender -> prime_peer -> target -> receiver`. Each one earns the target its
        //    deliberately-large receive-channel fee, which — booked as a positive effective fee on a
        //    fast settle — accrues as reputation on `target -> receiver`. The fee is credited as
        //    revenue to the prime_peer's channel (not the loop's entry channel), and prime_peer is
        //    chosen to already have high revenue, so this does not raise the loop's own entry
        //    threshold. Priming is done before the general jam so the payments can still ride
        //    `general`.
        let prime_hops = [self.prime_peer, self.target_pubkey, self.attacker_receiver.1];
        for i in 0..self.prime_count {
            let route = match build_custom_route(
                &self.attacker_sender.1,
                self.prime_amount_msat,
                &prime_hops,
                &self.network_graph,
            ) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("LoopedHtlc: could not build prime route: {}", e.err);
                    break;
                }
            };
            match dispatch_attacker_payment(
                sender_node,
                route,
                PaymentHash(rand::random()),
                None,
                Arc::clone(&self.attack_cost),
                shutdown_listener.clone(),
            )
            .await
            {
                Ok(handle) => match handle.await {
                    Ok(Ok(res)) if matches!(res.payment_outcome, PaymentOutcome::Success) => {
                        log::info!("LoopedHtlc: prime payment {i} settled, receiver reputation grows")
                    }
                    other => log::error!("LoopedHtlc: prime payment {i} did not settle: {other:?}"),
                },
                Err(e) => log::error!("LoopedHtlc: could not dispatch prime payment {i}: {e}"),
            }
        }

        // 2) Apply bucket pressure: jam the general resources of every one of the target's channels
        //    so honest unaccountable traffic can no longer ride `general` and must be upgraded to
        //    `protected` (which needs the outgoing channel to have reputation — reputation we are
        //    about to destroy).
        let mut jammed = 0;
        for scid in &self.target_channels {
            self.channel_jammer
                .jam_general_resources(&self.target_pubkey, *scid)
                .await?;
            jammed += 1;
        }
        *self.jammed_channels.lock().unwrap() = jammed;
        log::info!("LoopedHtlc: general-jammed {jammed} target channels");

        // 3) Fire one looped, accountable, held HTLC per mid peer we want to damage:
        //       attacker -> entry_peer -> target -> mid_peer -> target -> attacker
        //    Each is held (in intercept_attacker_receive) for the whole run, so the target's
        //    forward over `target -> mid_peer` stays in flight (docking that channel's usable
        //    reputation) and is finally failed slowly (booking the negative effective fee).
        let accountable = records_from_signal(AccountableSignal::Accountable);
        for (mid_pubkey, _mid_scid) in &self.mid_peers {
            let route_hops = vec![
                self.entry_peer,
                self.target_pubkey,
                *mid_pubkey,
                self.target_pubkey,
                self.attacker_receiver.1,
            ];

            let route = match build_custom_route(
                &self.attacker_sender.1,
                self.loop_amount_msat,
                &route_hops,
                &self.network_graph,
            ) {
                Ok(r) => r,
                Err(e) => {
                    log::error!(
                        "LoopedHtlc: could not build loop route via mid peer {mid_pubkey}: {}",
                        e.err
                    );
                    continue;
                }
            };

            log::info!(
                "LoopedHtlc: dispatching loop HTLC of {} msat via mid peer {}",
                self.loop_amount_msat,
                mid_pubkey,
            );

            // Mark this payment so the receiver holds it (rather than settling it).
            let payment_hash = PaymentHash(rand::random());
            self.loop_payments.lock().unwrap().insert(payment_hash);

            // Dispatch through the shared helper so its cost is accounted for. We do not await the
            // handle: the payment is meant to hang (we hold its final hop), so tracking runs on the
            // cost accumulator's background tracker.
            if let Err(e) = dispatch_attacker_payment(
                sender_node,
                route,
                payment_hash,
                Some(accountable.clone()),
                Arc::clone(&self.attack_cost),
                shutdown_listener.clone(),
            )
            .await
            {
                self.loop_payments.lock().unwrap().remove(&payment_hash);
                log::error!("LoopedHtlc: could not dispatch loop HTLC via {mid_pubkey}: {e}");
            }
        }

        // 4) Hold the whole configuration open for the baseline window so a comparable span of
        //    honest traffic flows and the revenue-drop monitor can measure the loss. Exit early if
        //    the simulation is already shutting down.
        select! {
            _ = shutdown_listener => {},
            _ = self.clock.sleep(self.hold_for) => {},
        }

        Ok(())
    }

    fn attack_statistics(&self) -> Result<AttackStatisitcs, BoxError> {
        Ok(AttackStatisitcs {
            general_jammed_channels: *self.jammed_channels.lock().unwrap(),
            congestion_jammed_channels: 0,
            estimated_jam_channels: 0,
        })
    }
}
