use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::HtlcRef;
use simln_lib::clock::SimulationClock;
use simln_lib::sim_node::{
    CriticalError, CustomRecords, ForwardingError, InterceptRequest, InterceptResolution,
    Interceptor,
};
use tokio::sync::Mutex;

use crate::clock::InstantClock;

/// Tracks the settled forwarding revenue earned by a target node within a single simulated
/// network. The same tracker type is attached to both the attack network and the co-simulated
/// peacetime network so the two can be compared live, at identical virtual timestamps (Common
/// Random Numbers): because both networks are driven by the same seed, their honest traffic is
/// identical and any difference in the target's settled revenue is caused by the attacker.
///
/// Revenue is credited only when a forward *settles* (`notify_resolution` with `success`), so it
/// measures money the target actually earned end-to-end — unlike the peacetime CSV replay, which
/// counted every forward at HTLC-add time regardless of downstream outcome.
pub struct RevenueTracker {
    target_node: PublicKey,
    revenue: Mutex<NodeRevenue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeRevenue {
    revenue_total: u64,
    /// Number of forwards the target settled (for diagnostics: distinguishing "fewer forwards"
    /// from "smaller fees per forward").
    settled_count: u64,
    /// Fees of htlcs currently in flight on the target, keyed by incoming htlc so we can credit
    /// them once we learn how they resolved.
    pending_htlcs: HashMap<HtlcRef, u64>,
}

impl RevenueTracker {
    pub fn new(target_node: PublicKey) -> Self {
        Self {
            target_node,
            revenue: Mutex::new(NodeRevenue {
                revenue_total: 0,
                settled_count: 0,
                pending_htlcs: HashMap::new(),
            }),
        }
    }

    /// The target's cumulative settled forwarding revenue so far, in msat.
    pub async fn revenue_msat(&self) -> u64 {
        self.revenue.lock().await.revenue_total
    }

    /// The number of forwards the target has settled so far.
    pub async fn settled_count(&self) -> u64 {
        self.revenue.lock().await.settled_count
    }
}

#[async_trait]
impl Interceptor for RevenueTracker {
    /// Record the fee of every htlc the target forwards so we can credit it on resolution.
    async fn intercept_htlc(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, CriticalError> {
        if req.forwarding_node == self.target_node {
            match self.revenue.lock().await.pending_htlcs.entry(HtlcRef {
                channel_id: req.incoming_htlc.channel_id.into(),
                htlc_index: req.incoming_htlc.index,
            }) {
                Entry::Occupied(_) => Err(CriticalError::InterceptorError(format!(
                    "duplicate incoming htlc index: {:?}",
                    req.incoming_htlc
                ))),
                Entry::Vacant(e) => {
                    e.insert(req.incoming_amount_msat - req.outgoing_amount_msat);
                    Ok(Ok(CustomRecords::new()))
                }
            }
        } else {
            Ok(Ok(CustomRecords::new()))
        }
    }

    /// Credit the target's revenue only when the forward settled successfully.
    async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), CriticalError> {
        if res.forwarding_node == self.target_node {
            let mut revenue = self.revenue.lock().await;
            match revenue.pending_htlcs.remove_entry(&HtlcRef {
                channel_id: res.incoming_htlc.channel_id.into(),
                htlc_index: res.incoming_htlc.index,
            }) {
                Some((_, fee)) => {
                    if res.success {
                        revenue.revenue_total += fee;
                        revenue.settled_count += 1;
                    }
                    Ok(())
                }
                None => Err(CriticalError::InterceptorError(format!(
                    "resolved htlc not found: {:?}",
                    res.incoming_htlc
                ))),
            }
        } else {
            Ok(())
        }
    }

    fn name(&self) -> String {
        "revenue tracker".to_string()
    }
}

/// A point-in-time comparison of the target's settled revenue in the attack network versus the
/// co-simulated peacetime network.
#[derive(Clone, Debug)]
pub struct RevenueSnapshot {
    pub peacetime_revenue_msat: u64,
    pub simulation_revenue_msat: u64,
    pub runtime: Duration,
}

/// Reads the live difference between the target's revenue under attack and in peacetime. Attacks
/// use this to decide when they have driven the target below its peacetime earnings; the summary
/// reads it at the end of the run.
#[async_trait]
pub trait PeacetimeRevenueMonitor {
    async fn get_revenue_difference(&self) -> RevenueSnapshot;
}

/// Compares the target's live settled revenue between the attack network and the peacetime network
/// that is co-simulated alongside it on the same virtual clock. Because both networks advance on
/// the same clock, `get_revenue_difference` reads both revenues at the *same* virtual instant.
pub struct RevenueComparator {
    clock: Arc<SimulationClock>,
    start_ins: Instant,
    simulation: Arc<RevenueTracker>,
    peacetime: Arc<RevenueTracker>,
}

impl RevenueComparator {
    pub fn new(
        clock: Arc<SimulationClock>,
        simulation: Arc<RevenueTracker>,
        peacetime: Arc<RevenueTracker>,
    ) -> Self {
        let start_ins = InstantClock::now(&*clock);
        Self {
            clock,
            start_ins,
            simulation,
            peacetime,
        }
    }
}

#[async_trait]
impl PeacetimeRevenueMonitor for RevenueComparator {
    async fn get_revenue_difference(&self) -> RevenueSnapshot {
        RevenueSnapshot {
            simulation_revenue_msat: self.simulation.revenue_msat().await,
            peacetime_revenue_msat: self.peacetime.revenue_msat().await,
            runtime: InstantClock::now(&*self.clock).duration_since(self.start_ins),
        }
    }
}
