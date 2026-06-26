use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::{AllocationCheck, ProposedForward};
use ln_simln_jamming::analysis::ForwardReporter;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{
    parse_duration, AttackType, NetworkParams, NetworkType, ReputationParams,
};
use ln_simln_jamming::reputation_interceptor::{BootstrapForward, ReputationInterceptor};
use ln_simln_jamming::{BoxError, ACCOUNTABLE_TYPE, UPGRADABLE_TYPE};
use log::LevelFilter;
use sim_cli::parsing::{create_simulation_with_network, SimParams};
use simln_lib::batched_writer::BatchedWriter;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::latency_interceptor::LatencyIntercepor;
use simln_lib::runtime::block_on_virtual_time;
use simln_lib::sim_node::CustomRecords;
use simln_lib::SimulationCfg;
use simple_logger::SimpleLogger;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

// The default amount of time data will be generated for.
pub const DEFAULT_RUNTIME: &str = "6months";

/// Seed shared by the simulation config and the latency interceptor so that generated bootstrap data is reproducible.
const SIM_SEED: u64 = 13995354354227336701;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    network: NetworkParams,

    /// The amount of time to generate forwarding history for.
    #[arg(long, value_parser = parse_duration, default_value = DEFAULT_RUNTIME)]
    pub duration: Duration,

    #[command(flatten)]
    pub reputation_params: ReputationParams,

    /// The attack that we're interested in running.
    #[arg(long, value_enum)]
    pub attack_type: Option<AttackType>,
}

fn main() -> Result<(), BoxError> {
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

    // Run on sim-ln's paused, single-threaded virtual-time runtime so the (potentially months-long) bootstrap
    // generates instantly. Anchor virtual time at the real wall clock because the routing graph rejects channel
    // updates whose timestamps are far from real time.
    let start_time = SystemTime::now();
    block_on_virtual_time(start_time, |clock| run(clock, cli))??;

    Ok(())
}

async fn run(clock: Arc<SimulationClock>, cli: Cli) -> Result<(), BoxError> {
    let network = NetworkType::new(&cli.network, cli.attack_type, None)?;
    if matches!(network, NetworkType::BootstrapAttackTime(_, _, _)) {
        return Err("cannot run forward builder in bootstrap mode".into());
    }

    let sim_network = network.active_network();
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
        )?))),
    )?);
    let latency_interceptor = Arc::new(LatencyIntercepor::new_poisson(300.0, Some(SIM_SEED))?);

    let sim_cfg = SimulationCfg::new(
        Some(cli.duration.as_secs() as u32),
        3_800_000,
        2.0,
        None,
        Some(SIM_SEED),
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
}

impl BootstrapWriter {
    fn new(clock: Arc<SimulationClock>, dir: PathBuf, filename: String) -> Result<Self, BoxError> {
        Ok(BootstrapWriter {
            clock,
            batch_writer: Mutex::new(BatchedWriter::new(dir, filename, 500)?),
        })
    }
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

        self.batch_writer
            .lock()
            .await
            .queue(BootstrapForward {
                incoming_amt: forward.amount_in_msat,
                outgoing_amt: forward.amount_out_msat,
                incoming_expiry: forward.expiry_in_height,
                outgoing_expiry: forward.expiry_out_height,
                added_ns: settled_ns - nanos_since_added,
                settled_ns,
                forwarding_node,
                channel_in_id: forward.incoming_ref.channel_id,
                channel_out_id: forward.outgoing_channel_id,
            })
            .map_err(|e| e.into())
    }
}
