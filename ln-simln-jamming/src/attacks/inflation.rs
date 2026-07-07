use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::PaymentHash;
use lightning::routing::gossip::NetworkGraph;
use sim_cli::parsing::NetworkParser;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::sim_node::{
    CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode, WrappedLog,
};
use tokio::select;
use tokio::sync::Mutex;
use triggered::Listener;

use crate::clock::InstantClock;
use crate::reputation_interceptor::{ChannelJammer, ReputationMonitor};
use crate::revenue_interceptor::PeacetimeRevenueMonitor;
use crate::{BoxError, NetworkReputation};

use super::utils::{build_custom_route, dispatch_attacker_payment};
use super::{AttackCost, AttackStatisitcs, JammingAttack};

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

/// Default total duration the simulation is held open for (30 days), matching the peacetime
/// baseline window so the attack and the co-simulated peacetime network cover the same span of
/// generated honest traffic.
const DEFAULT_BASELINE_SECS: u64 = 30 * 24 * 60 * 60;
const BASELINE_SECS_ENV: &str = "BASELINE_SECS";

/// Amount (msat) of each genuine inflation payment routed through the target. Must stay under the
/// general bucket's per-peer-pair liquidity cap on the *smallest* honest channel on the route (the
/// general bucket hands each candidate channel only ~20 slots of `liquidity/slot_count` each, i.e.
/// roughly 4% of the channel capacity), otherwise the forward is rejected with "no general
/// resources". Overridable for tuning.
const INFLATION_PAYMENT_MSAT_ENV: &str = "INFLATION_PAYMENT_MSAT";
const DEFAULT_INFLATION_PAYMENT_MSAT: u64 = 30_000_000;

/// Maximum number of inflation payments to push through *each* inject channel during phase 1. We
/// stop early once the route can no longer be built (attacker/honest channel liquidity exhausted),
/// so this is just an upper bound. Overridable for tuning.
const INFLATION_COUNT_ENV: &str = "INFLATION_COUNT";
const DEFAULT_INFLATION_COUNT: u64 = 400;

/// The inflation attack — the "reverse lever" against local resource conservation.
///
/// # Mechanism
///
/// A forwarding node upgrades an otherwise-unaccountable HTLC to the `protected` bucket (its only
/// escape once `general`/`congestion` are congested) only when the *outgoing* channel's reputation
/// clears the *incoming* channel's revenue threshold:
///
/// ```text
///     outgoing_reputation - in_flight_risk - htlc_risk  >  incoming_revenue_threshold
/// ```
///
/// (`ReputationCheck::sufficient_reputation` in `ln-resource-mgr`). The `incoming_revenue_threshold`
/// is exactly the decaying-average revenue the target has earned on the channel the HTLC *arrives*
/// on: every time a forward that entered on channel `I` settles, the target's fee is added to
/// `I`'s incoming revenue (`ForwardManager::resolve_htlc`).
///
/// So we, the attacker, route a burst of genuine, fast-settling payments **inward** across the
/// target's channel with an honest peer `P`:
///
/// ```text
///     attacker_sender -> P -> target -> exit_peer -> attacker_receiver
/// ```
///
/// Each such payment settles and credits the target's fee to `incoming_revenue(target<->P)`,
/// *raising the reputation bar* that any HTLC arriving from `P` must clear to win protected access.
/// We pump it above the reputation the target's honest peers have built.
///
/// Then we stop paying and **congest**: we jam the `general` and `congestion` buckets on the
/// target's channels. Now an honest unaccountable HTLC arriving from `P` finds `general` full,
/// cannot fall back to the one-shot `congestion` bucket, and cannot be upgraded to `protected`
/// because the inflated threshold prices out its outgoing peer's reputation. The HTLC is dropped
/// and the target loses that honest forwarding revenue.
///
/// # The metric trap (why this is structured in phases)
///
/// Our inflation payments in phase 1 are *successful forwards* that ADD to the target's settled
/// revenue. That gift is counted in `simulation_revenue` and never decays out of the cumulative
/// total, whereas the threshold we buy with it is a decaying average that fades over the revenue
/// window. The attack only nets a loss if the honest revenue denied in phase 2 outweighs the
/// revenue gifted in phase 1 plus the fees paid. We therefore (1) inflate, then (2) lock out and
/// hold, and measure the NET against peacetime after the honest-revenue collapse. See the run
/// write-up for whether the net comes out negative on this network.
pub struct InflationAttack<R, M, J>
where
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    /// Attacker node that originates the inflation payments.
    sender: (String, PublicKey),
    /// Attacker node that receives the inflation payments (so they settle and credit the target).
    receiver: (String, PublicKey),
    /// Honest peers of the target whose incoming channel we inflate by routing payments *in*
    /// through them. Locking these out denies their honest incoming traffic once buckets congest.
    inject_peers: Vec<PublicKey>,
    /// Honest peer of the target we route the inflation payments *out* through. The target's fee is
    /// set by this channel's (high) outgoing policy, so a high-fee exit maximises revenue credited
    /// to the inject channels per unit of volume pushed.
    exit_peer: PublicKey,
    /// All of the target's channels: scid -> peer pubkey. Used to look up thresholds and to jam.
    target_channels: HashMap<u64, PublicKey>,
    reputation_monitor: Arc<R>,
    peacetime_revenue: Arc<M>,
    channel_jammer: Arc<J>,
    network_graph: Arc<LdkNetworkGraph>,
    attack_cost: Arc<AttackCost>,
    run_for: Duration,
    inflation_payment_msat: u64,
    inflation_count: u64,
    /// Number of channels jammed, recorded for the statistics summary.
    jammed_channels: std::sync::Mutex<usize>,
}

impl<R, M, J> InflationAttack<R, M, J>
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
        sender: (String, PublicKey),
        receiver: (String, PublicKey),
        inject_peers: Vec<PublicKey>,
        exit_peer: PublicKey,
        reputation_monitor: Arc<R>,
        peacetime_revenue: Arc<M>,
        channel_jammer: Arc<J>,
        network_graph: Arc<LdkNetworkGraph>,
        attack_cost: Arc<AttackCost>,
    ) -> Self {
        let target_channels = HashMap::from_iter(network.iter().filter_map(|channel| {
            if channel.node_1.pubkey == target_pubkey {
                Some((channel.scid.into(), channel.node_2.pubkey))
            } else if channel.node_2.pubkey == target_pubkey {
                Some((channel.scid.into(), channel.node_1.pubkey))
            } else {
                None
            }
        }));

        let run_for = Duration::from_secs(
            std::env::var(BASELINE_SECS_ENV)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_BASELINE_SECS),
        );
        let inflation_payment_msat = std::env::var(INFLATION_PAYMENT_MSAT_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_INFLATION_PAYMENT_MSAT);
        let inflation_count = std::env::var(INFLATION_COUNT_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_INFLATION_COUNT);

        Self {
            clock,
            target_pubkey,
            sender,
            receiver,
            inject_peers,
            exit_peer,
            target_channels,
            reputation_monitor,
            peacetime_revenue,
            channel_jammer,
            network_graph,
            attack_cost,
            run_for,
            inflation_payment_msat,
            inflation_count,
            jammed_channels: std::sync::Mutex::new(0),
        }
    }

    /// Returns scid of the target's channel with `peer`, if any.
    fn channel_with(&self, peer: &PublicKey) -> Option<u64> {
        self.target_channels
            .iter()
            .find_map(|(scid, pk)| if pk == peer { Some(*scid) } else { None })
    }

    /// Logs the target's per-channel incoming revenue (the reputation threshold) for the inject
    /// channels, so the threshold inflation is visible in the run logs.
    async fn log_inject_thresholds(&self, label: &str) -> Result<(), BoxError> {
        let channels = self
            .reputation_monitor
            .list_channels(self.target_pubkey, InstantClock::now(&*self.clock))
            .await?;
        for peer in &self.inject_peers {
            if let Some(scid) = self.channel_with(peer) {
                if let Some(snapshot) = channels.get(&scid) {
                    log::info!(
                        "Inflation [{label}]: target<->{} (scid {}) incoming_revenue threshold = {} msat",
                        peer,
                        scid,
                        snapshot.incoming_revenue,
                    );
                }
            }
        }
        Ok(())
    }

    /// Phase 1: route `inflation_count` genuine, fast-settling payments in through each inject peer
    /// and out through the exit peer, pumping the target's incoming-revenue threshold on each inject
    /// channel. Each payment is dispatched through the cost-tracked helper and awaited to settlement
    /// so the revenue is credited (and the next payment has liquidity) before we continue.
    async fn inflate(
        &self,
        attacker_nodes: &HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        let sender_node = attacker_nodes
            .get(&self.sender.0)
            .ok_or(format!("attacker sender {} not found", self.sender.0))?;

        for peer in &self.inject_peers {
            let hops = vec![*peer, self.target_pubkey, self.exit_peer, self.receiver.1];
            for i in 0..self.inflation_count {
                // Bail out promptly if the simulation is shutting down.
                if shutdown_listener.is_triggered() {
                    return Ok(());
                }

                let route = match build_custom_route(
                    &self.sender.1,
                    self.inflation_payment_msat,
                    &hops,
                    &self.network_graph,
                ) {
                    Ok(route) => route,
                    Err(e) => {
                        // Liquidity on the inject channel is likely exhausted; move on to the next
                        // inject peer rather than aborting the whole attack.
                        log::info!(
                            "Inflation: stopping payments through peer {} after {} payments: {}",
                            peer,
                            i,
                            e.err
                        );
                        break;
                    }
                };

                let payment_hash = PaymentHash(rand::random());
                // Unaccountable, genuine payment: rides the (still open) general buckets in phase 1
                // and settles, crediting the target's fee to incoming_revenue(target<->peer).
                let handle = dispatch_attacker_payment(
                    sender_node,
                    route,
                    payment_hash,
                    None,
                    Arc::clone(&self.attack_cost),
                    shutdown_listener.clone(),
                )
                .await?;

                // Await settlement so the revenue is credited before the next payment (and so the
                // inject channel's liquidity has moved on before we build the next route).
                match handle.await {
                    Ok(Ok(result)) => {
                        if !matches!(
                            result.payment_outcome,
                            simln_lib::PaymentOutcome::Success
                        ) {
                            log::info!(
                                "Inflation: payment {} through peer {} did not settle ({:?}); moving on",
                                i,
                                peer,
                                result.payment_outcome
                            );
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<R, M, J> JammingAttack for InflationAttack<R, M, J>
where
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
    J: ChannelJammer + Send + Sync,
{
    /// Assert the topology the attack needs: the attacker's sender must reach each inject peer, and
    /// each inject peer plus the exit peer must be channels of the target.
    fn validate(&self) -> Result<(), BoxError> {
        if self.inject_peers.is_empty() {
            return Err("inflation attack needs at least one inject peer".into());
        }
        for peer in &self.inject_peers {
            self.channel_with(peer)
                .ok_or(format!("target has no channel with inject peer {}", peer))?;
        }
        self.channel_with(&self.exit_peer)
            .ok_or(format!("target has no channel with exit peer {}", self.exit_peer))?;
        Ok(())
    }

    /// The inflation payments terminate at the attacker's receiver node; accept them so they settle
    /// (crediting the target). We never hold these — holding would defeat the inflation.
    async fn intercept_attacker_receive(
        &self,
        _req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        Ok(Ok(CustomRecords::default()))
    }

    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        // ---- Phase 1: inflate the target's per-channel incoming-revenue thresholds. ----
        self.log_inject_thresholds("before").await?;
        log::info!(
            "Inflation: phase 1 - pushing up to {} payments of {} msat through each of {} inject peers",
            self.inflation_count,
            self.inflation_payment_msat,
            self.inject_peers.len(),
        );
        self.inflate(&attacker_nodes, shutdown_listener.clone())
            .await?;
        self.log_inject_thresholds("after").await?;

        // ---- Phase 2: lock out honest traffic and congest the buckets. ----
        // With the thresholds raised, jam the general and congestion buckets on every one of the
        // target's channels. Honest unaccountable traffic can no longer ride general, cannot fall
        // back to congestion, and (on the inflated incoming channels) cannot be upgraded to
        // protected - so it is dropped and the target loses the honest forwarding revenue.
        let mut jammed = 0;
        for scid in self.target_channels.keys() {
            self.channel_jammer
                .jam_general_resources(&self.target_pubkey, *scid)
                .await?;
            self.channel_jammer
                .jam_congestion_resources(&self.target_pubkey, *scid)
                .await?;
            jammed += 1;
        }
        *self.jammed_channels.lock().unwrap() = jammed;
        log::info!(
            "Inflation: phase 2 - jammed general+congestion on {} target channels; holding for the rest of the window",
            jammed,
        );

        // Hold the simulation open for the remainder of the baseline window so the honest-revenue
        // collapse accumulates, polling the live peacetime comparison. Exit early if we have driven
        // the target materially below peacetime (attack succeeded) or on shutdown.
        let interval = Duration::from_secs(300);
        loop {
            select! {
                _ = shutdown_listener.clone() => break,
                _ = self.clock.sleep(interval) => {
                    let snapshot = self.peacetime_revenue.get_revenue_difference().await;
                    if snapshot.runtime >= self.run_for {
                        log::info!("Inflation: reached baseline window, stopping");
                        break;
                    }
                    // 5% below peacetime is the harness's materiality bar.
                    if snapshot.simulation_revenue_msat * 100 < snapshot.peacetime_revenue_msat * 95 {
                        log::error!(
                            "Inflation: simulation revenue {} is >5% below peacetime {} after {:?}",
                            snapshot.simulation_revenue_msat,
                            snapshot.peacetime_revenue_msat,
                            snapshot.runtime,
                        );
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn attack_statistics(&self) -> Result<AttackStatisitcs, BoxError> {
        let jammed = *self.jammed_channels.lock().unwrap();
        Ok(AttackStatisitcs {
            general_jammed_channels: jammed,
            congestion_jammed_channels: jammed,
            // helper jam cost is dwarfed by the inflation fees; left uncharged here.
            estimated_jam_channels: 0,
        })
    }
}
