use simln_lib::clock::SimulationClock;
use std::time::Instant;

pub trait InstantClock {
    fn now(&self) -> Instant;
}

impl InstantClock for SimulationClock {
    /// Reads the current instant from tokio's clock, which tracks virtual time when the runtime is paused. The
    /// returned instant is only meaningful for relative duration arithmetic, never compare it to a wall-clock
    /// `Instant::now()`.
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
