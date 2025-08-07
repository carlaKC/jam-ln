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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use ln_resource_mgr::decaying_average::DecayingAverage;
    use simln_lib::clock::{Clock, SimulationClock};
    use tokio::sync::Mutex;
    use tokio::task::JoinSet;
    use tokio::{select, time};

    use super::InstantClock;

    macro_rules! spawn_value_checker {
        ($tasks:expr, $shutdown:expr, $listener:expr, $avg:expr, $clock:expr, $i:expr) => {{
            let shutdown = $shutdown.clone();
            let listener = $listener.clone();
            let avg = $avg.clone();
            let clock = $clock.clone();
            $tasks.spawn(async move {
                loop {
                    let now = InstantClock::now(&*clock);
                    println!("Task {}: picked now: {:?}", $i, now);
                    if let Err(e) = avg.lock().await.value_at_instant(now) {
                        println!("Task {}: Err: {e}", $i);
                        shutdown.trigger();
                    } else {
                        println!("Task {}: updated avg to {:?}", $i, now);
                    }

                    if listener.is_triggered() {
                        println!("Task {}: triggered for shutdown", $i);
                        break;
                    }
                }
            })
        }};
    }

    #[tokio::test]
    async fn test_replicate_last_updated_in_past() {
        // Tries to replicate a bug for very fast simulated clock times that our decaying average's
        // last updated time may be greater than the currently queried time. We'll run the test
        // for 5 minutes to try find the flake, then fail if we can't find it.
        let avg = Arc::new(Mutex::new(DecayingAverage::new(Duration::from_secs(
            60 * 60 * 24 * 14,
        ))));
        let clock = Arc::new(SimulationClock::new(1000).unwrap());
        let mut tasks = JoinSet::new();

        let (shutdown, listener) = triggered::trigger();

        spawn_value_checker!(tasks, shutdown, listener, avg, clock, 1);
        spawn_value_checker!(tasks, shutdown, listener, avg, clock, 2);

        let timeout = Duration::from_secs(60 * 5);
        select! {
            _ = listener => assert!(false, "test exited due to race in average"),
            _ = time::sleep(timeout) => {},
        }
    }
}
