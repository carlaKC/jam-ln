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

/// A do-nothing attacker used as the Common-Random-Numbers baseline.
///
/// It adds the attacker's (isolated, non-perturbing) channels to the graph but takes no action,
/// relying only on the default interceptor behaviour (forward every HTLC immediately). Held open
/// for a fixed duration so a comparable span of honest traffic flows, it lets the target earn
/// exactly what the unperturbed generated traffic gives it. Because the co-simulated peacetime
/// network is driven by the same seed, an inert run is the standing check that both networks
/// produce identical honest traffic: equal settled counts and settled revenue on the target.
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
        })
    }
}
