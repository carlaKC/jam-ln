use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::{AllocationCheck, ProposedForward};
use ln_simln_jamming::analysis::ForwardReporter;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{
    parse_window, AttackType, NetworkParams, NetworkType, ReputationParams,
};
use ln_simln_jamming::reputation_interceptor::{BootstrapForward, ReputationInterceptor};
use ln_simln_jamming::{BoxError, ACCOUNTABLE_TYPE, UPGRADABLE_TYPE};
use log::LevelFilter;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sim_cli::parsing::{create_simulation_with_network, SimParams};
use simln_lib::batched_writer::BatchedWriter;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::latency_interceptor::LatencyIntercepor;
use simln_lib::sim_node::CustomRecords;
use simln_lib::SimulationCfg;
use simple_logger::SimpleLogger;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

// The default amount of time data will be generated for.
pub const DEFAULT_RUNTIME: &str = "6months";

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    network: NetworkParams,

    /// The amount of time to generate forwarding history for. Accepts `Xd` (days) and `Xm`
    /// (months); generate a short window (eg `7d`) and loop it at import with the reputation
    /// builder's `--allow-boost` to cover the full reputation window without a large file.
    #[arg(long, value_parser = parse_window, default_value = DEFAULT_RUNTIME)]
    pub duration: Duration,

    #[command(flatten)]
    pub reputation_params: ReputationParams,

    /// The attack that we're interested in running.
    #[arg(long, value_enum)]
    pub attack_type: Option<AttackType>,

    /// Mean number of payment attempts per successful forward, modelling failed retries that
    /// precede a success. Each real (routed) forward is recorded as settled, then a geometric
    /// number of failed copies is synthesised on the same channel pair (retry-until-success with
    /// per-attempt success probability 1/payment_attempts), so the mean attempts equals this value
    /// with natural retry spread. Failed copies are replayed as failed during bootstrapping and
    /// contribute no fee to reputation. Defaults to 4.0 (~75% of forwards failed, i.e. 3 failed
    /// tries per success) while leaving settle volume untouched. Set to 1.0 for all-settle.
    #[arg(long, default_value_t = 4.0)]
    pub payment_attempts: f64,

    /// sim-ln activity multiplier: scales total payment volume (each source sends
    /// multiplier * capacity per month). Controls the number of *successful* forwards; failed
    /// retries are synthesised separately via payment_attempts, so this no longer needs to be
    /// raised to compensate for failures.
    #[arg(long, default_value_t = 2.0)]
    pub activity_multiplier: f64,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        // Lower logging from sim-ln so that we can focus on our own logs.
        .with_module_level("simln_lib", LevelFilter::Info)
        .with_module_level("sim_cli", LevelFilter::Off)
        // Debug so that we can read interceptor-related logging.
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    let cli = Cli::parse();

    let network = NetworkType::new(&cli.network, cli.attack_type, None)?;
    if matches!(network, NetworkType::BootstrapAttackTime(_, _, _)) {
        return Err("cannot run forward builder in bootstrap mode".into());
    }

    let sim_network = network.active_network();
    let clock = Arc::new(SimulationClock::new(1000)?);
    let tasks = TaskTracker::new();

    // Create a reputation interceptor without any bootstrap (since here we're creating the
    // bootstrap itself, we just want to run with reputation active).
    let traffic_file = network.traffic_file();
    let reputation_interceptor = Arc::new(ReputationInterceptor::new_for_network(
        cli.reputation_params.into(),
        sim_network,
        clock.clone(),
        Some(Arc::new(Mutex::new(BootstrapWriter::new(
            clock.clone(),
            // TODO: change API in SimLN so that we can just pass a path in here.
            traffic_file
                .parent()
                .ok_or("could not get traffic file directory")?
                .to_path_buf(),
            traffic_file
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            cli.payment_attempts,
        )?))),
    )?);
    let latency_interceptor = Arc::new(LatencyIntercepor::new_poisson(300.0)?);

    let sim_cfg = SimulationCfg::new(
        Some(cli.duration.as_secs() as u32),
        3_800_000,
        cli.activity_multiplier,
        None,
        Some(13995354354227336701),
    );

    let exclude_pubkeys = [network.target().1]
        .into_iter()
        .chain(network.attackers().iter().map(|a| a.1))
        .collect();

    let custom_records =
        CustomRecords::from([(UPGRADABLE_TYPE, vec![1]), (ACCOUNTABLE_TYPE, vec![0])]);

    let sim_params = SimParams {
        nodes: vec![],
        sim_network: sim_network.to_vec(),
        activity: vec![],
        exclude: exclude_pubkeys,
    };

    let (simulation, validated_activities, _sim_nodes) = create_simulation_with_network(
        sim_cfg,
        &sim_params,
        clock,
        tasks,
        vec![reputation_interceptor, latency_interceptor],
        custom_records,
    )
    .await?;

    simulation.run(&validated_activities).await?;

    Ok(())
}

// Writes all forwards to disk in batches.
struct BootstrapWriter {
    clock: Arc<SimulationClock>,
    batch_writer: Mutex<BatchedWriter>,
    /// Per-attempt success probability, derived as 1/payment_attempts. The number of failed retries
    /// synthesised before each recorded success is geometric with this probability.
    success_prob: f64,
    rng: Mutex<StdRng>,
}

/// Hard cap on synthesised failed retries per forward, so an unlucky geometric draw can't blow up.
const MAX_SYNTHETIC_FAILURES: u32 = 100;

impl BootstrapWriter {
    fn new(
        clock: Arc<SimulationClock>,
        dir: PathBuf,
        filename: String,
        payment_attempts: f64,
    ) -> Result<Self, BoxError> {
        if !payment_attempts.is_finite() || payment_attempts < 1.0 {
            return Err(format!("payment_attempts must be >= 1.0, got {payment_attempts}").into());
        }
        Ok(BootstrapWriter {
            clock,
            batch_writer: Mutex::new(BatchedWriter::new(dir, filename, 500)?),
            success_prob: 1.0 / payment_attempts,
            // Seeded for reproducibility across runs with the same parameters.
            rng: Mutex::new(StdRng::seed_from_u64(13995354354227336701)),
        })
    }
}

/// Counts failed retries before a success: Bernoulli(`success_prob`) trials until the first
/// success, returning the number of failures (geometric, mean = `1/success_prob - 1`, i.e.
/// `payment_attempts - 1`). Capped at [`MAX_SYNTHETIC_FAILURES`].
fn sample_failed_retries(success_prob: f64, rng: &mut StdRng) -> u32 {
    let mut failures = 0;
    while failures < MAX_SYNTHETIC_FAILURES && rng.random::<f64>() >= success_prob {
        failures += 1;
    }
    failures
}

#[async_trait]
impl ForwardReporter for BootstrapWriter {
    async fn report_forward(
        &mut self,
        forwarding_node: PublicKey,
        _: AllocationCheck,
        forward: ProposedForward,
    ) -> Result<(), BoxError> {
        let settled_ns = Clock::now(&*self.clock)
            .duration_since(UNIX_EPOCH)?
            .as_nanos() as u64;

        let nanos_since_added = InstantClock::now(&*self.clock)
            .duration_since(forward.added_at)
            .as_nanos() as u64;

        // The real, routed forward always settles; synthesised retries on the same channel pair
        // model the failed attempts that preceded it, staggered back in time so they read as a
        // time-ordered retry sequence ending in the success rather than simultaneous duplicates.
        let failed_retries = sample_failed_retries(self.success_prob, &mut *self.rng.lock().await);
        let make = |added_ns: u64, settled_ns: u64, settled: bool| BootstrapForward {
            incoming_amt: forward.amount_in_msat,
            outgoing_amt: forward.amount_out_msat,
            incoming_expiry: forward.expiry_in_height,
            outgoing_expiry: forward.expiry_out_height,
            added_ns,
            settled_ns,
            forwarding_node,
            channel_in_id: forward.incoming_ref.channel_id,
            channel_out_id: forward.outgoing_channel_id,
            settled,
        };

        let mut batch_writer = self.batch_writer.lock().await;
        for (added_ns, settled_ns, settled) in
            retry_timeline(settled_ns, nanos_since_added, failed_retries)
        {
            batch_writer.queue(make(added_ns, settled_ns, settled))?;
        }
        Ok(())
    }
}

/// Builds the chronological `(added_ns, settled_ns, settled)` timeline for one forward:
/// `failed_retries` contiguous failed attempts, each of duration `gap` (= `hold`, or 1ns when
/// `hold` is 0 so attempts stay distinct), immediately preceding the settled forward
/// `[settled_ns - hold, settled_ns]`. The retries are shifted backward in time so the sequence
/// reads fail, fail, …, success — never overlapping. All timestamps are <= `settled_ns`, so they
/// stay within the bootstrap window's upper bound.
fn retry_timeline(settled_ns: u64, hold: u64, failed_retries: u32) -> Vec<(u64, u64, bool)> {
    let gap = hold.max(1);
    let success_added = settled_ns.saturating_sub(hold);
    let mut timeline = Vec::with_capacity(failed_retries as usize + 1);
    // Earliest attempt first (largest step back), so the returned vec is chronological.
    for r in (1..=failed_retries).rev() {
        let f_settled = success_added.saturating_sub((r as u64 - 1) * gap);
        let f_added = f_settled.saturating_sub(gap);
        timeline.push((f_added, f_settled, false));
    }
    timeline.push((success_added, settled_ns, true));
    timeline
}

#[cfg(test)]
mod tests {
    use super::{retry_timeline, sample_failed_retries, MAX_SYNTHETIC_FAILURES};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_retry_timeline() {
        let settled_ns = 1_000_000;
        let hold = 300;

        // No failures -> just the success, occupying [settled - hold, settled].
        assert_eq!(
            retry_timeline(settled_ns, hold, 0),
            vec![(settled_ns - hold, settled_ns, true)]
        );

        // Three failures: chronological, contiguous, non-overlapping, ending in the success.
        let tl = retry_timeline(settled_ns, hold, 3);
        assert_eq!(tl.len(), 4);
        // Last entry is the unchanged success.
        assert_eq!(tl[3], (settled_ns - hold, settled_ns, true));
        // Earlier entries are failures.
        assert!(tl[..3].iter().all(|&(_, _, settled)| !settled));
        // Strictly increasing added_ns, and each attempt's end == the next attempt's start.
        for w in tl.windows(2) {
            assert!(w[0].0 < w[1].0, "added_ns not increasing");
            assert_eq!(w[0].1, w[1].0, "attempts should be contiguous");
        }
        // Every timestamp stays within the window's upper bound.
        assert!(tl
            .iter()
            .all(|&(a, s, _)| a <= settled_ns && s <= settled_ns));

        // Zero hold still yields distinct, ordered timestamps (1ns spacing).
        let z = retry_timeline(settled_ns, 0, 2);
        assert!(z[0].0 < z[1].0 && z[1].0 < z[2].0);
    }

    #[test]
    fn test_sample_failed_retries() {
        let mut rng = StdRng::seed_from_u64(42);

        // payment_attempts = 1 (success_prob 1.0) -> never any failed retries (all-settle).
        for _ in 0..1000 {
            assert_eq!(sample_failed_retries(1.0, &mut rng), 0);
        }

        // payment_attempts = 4 (success_prob 0.25) -> mean failures ~3 over many samples.
        let n = 200_000;
        let total: u64 = (0..n)
            .map(|_| sample_failed_retries(0.25, &mut rng) as u64)
            .sum();
        let mean = total as f64 / n as f64;
        assert!(
            (mean - 3.0).abs() < 0.1,
            "mean failed retries {mean} != ~3.0"
        );

        // Never exceeds the cap, even with a near-zero success probability.
        for _ in 0..1000 {
            assert!(sample_failed_retries(1e-9, &mut rng) <= MAX_SYNTHETIC_FAILURES);
        }
    }
}
