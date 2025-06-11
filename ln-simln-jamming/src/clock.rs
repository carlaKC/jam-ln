use simln_lib::clock::SimulationClock;
use std::ops::Add;
use std::time::Instant;

pub trait InstantClock {
    fn now(&self) -> Instant;
}

impl InstantClock for SimulationClock {
    fn now(&self) -> Instant {
        let start_instant_std = self.get_start_instant().into();
        let elapsed = Instant::now().duration_since(start_instant_std);

        start_instant_std.add(elapsed * self.get_speedup_multiplier().into())
    }
}
