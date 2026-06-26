use simln_lib::clock::SimulationClock;
use std::time::Instant;

pub trait InstantClock {
    fn now(&self) -> Instant;
}

impl InstantClock for SimulationClock {
    /// Reads the current instant from Tokio's clock. On the paused runtime that drives a virtual-time simulation this
    /// is virtual time, so differences between the returned instants reflect simulated (not wall-clock) elapsed time.
    /// `into_std` is sound here because all callers run on that runtime; the resulting `std::time::Instant` is only ever
    /// used for relative duration arithmetic, never compared against a wall-clock `Instant::now()`.
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
