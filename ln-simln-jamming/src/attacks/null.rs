use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::sim_node::{SimGraph, SimNode};
use tokio::select;
use tokio::sync::Mutex;
use triggered::Listener;

use crate::{BoxError, NetworkReputation};

use super::{AttackStatisitcs, JammingAttack};

/// Default duration the baseline holds the simulation open for, in seconds (30 days). Chosen to
/// match the 30-day attacker bootstrap window so a baseline run and an attack run cover comparable
/// spans of generated honest traffic.
const DEFAULT_BASELINE_SECS: u64 = 30 * 24 * 60 * 60;

/// Environment variable used to override [`DEFAULT_BASELINE_SECS`]. An attack that wants its
/// active run compared against this baseline should hold the simulation open for the *same*
/// duration, so set this var identically for both runs.
const BASELINE_SECS_ENV: &str = "BASELINE_SECS";

/// A do-nothing attacker used to establish a measurement baseline.
///
/// The printed "Revenue loss / Revenue gain" line is **not** a reliable measure of an attack's
/// impact on its own:
/// - In `--attacker-bootstrap` mode the simulation's revenue is *seeded* with the builder's
///   `revenue_<secs>.csv` value while the peacetime side is seeded from the replayed
///   `peacetime_traffic.csv` window. These two seeds disagree (observed ~6x), so the headline is
///   dominated by the seeding gap, not by the attack.
/// - The simulation's honest traffic is generated live (seeded by `SIM_SEED`) whereas the
///   peacetime comparison is a *different* realisation replayed from CSV, so the two are not a
///   like-for-like counterfactual.
///
/// The sound counterfactual available in this harness is Common Random Numbers: run the *same*
/// attacker graph twice under the same `SIM_SEED` and the same fixed duration — once with the
/// attacker inert (this attack) and once with it active. Because the generated honest traffic is
/// identical between the two runs, the difference in the target's `simulation_revenue` is the
/// attack's true causal effect, with the generated-vs-replayed mismatch cancelled out.
///
/// `NullAttack` is the inert arm: it adds nothing to the graph's behaviour, holds the simulation
/// open for a fixed duration so a comparable span of honest traffic flows, then returns to shut
/// the simulation down. It relies only on the default interceptor behaviour (forward every HTLC
/// immediately), so the target earns exactly what the unperturbed generated traffic gives it.
pub struct NullAttack {
    clock: Arc<SimulationClock>,
    run_for: Duration,
}

impl NullAttack {
    pub fn new(clock: Arc<SimulationClock>) -> Self {
        let secs = std::env::var(BASELINE_SECS_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_BASELINE_SECS);

        Self {
            clock,
            run_for: Duration::from_secs(secs),
        }
    }
}

#[async_trait]
impl JammingAttack for NullAttack {
    /// Hold the simulation open for the configured duration so that a comparable span of honest
    /// traffic is generated, then return to trigger shutdown. Exit early if the simulation is
    /// shutting down for any other reason so we never block its teardown.
    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        _attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        log::info!(
            "NullAttack baseline: holding simulation open for {:?} with an inert attacker",
            self.run_for,
        );

        select! {
            _ = shutdown_listener => {},
            _ = self.clock.sleep(self.run_for) => {},
        }

        Ok(())
    }

    fn attack_statistics(&self) -> Result<AttackStatisitcs, BoxError> {
        Ok(AttackStatisitcs {
            general_jammed_channels: 0,
            congestion_jammed_channels: 0,
            // no jamming.
            estimated_jam_channels: 0,
        })
    }
}
