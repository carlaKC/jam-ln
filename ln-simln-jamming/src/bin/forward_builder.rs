use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::{AllocationCheck, ProposedForward};
use ln_simln_jamming::analysis::ForwardReporter;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{
    find_pubkey_by_alias, parse_duration, SimNetwork, DEFAULT_REPUTATION_DIR, DEFAULT_SIM_FILE,
};
use ln_simln_jamming::reputation_interceptor::{BootstrapForward, ReputationInterceptor};
use ln_simln_jamming::{BoxError, ACCOUNTABLE_TYPE, UPGRADABLE_TYPE};
use log::LevelFilter;
use sim_cli::parsing::{create_simulation_with_network, SimParams};
use simln_lib::batched_writer::BatchedWriter;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::latency_interceptor::LatencyIntercepor;
use simln_lib::sim_node::CustomRecords;
use simln_lib::SimulationCfg;
use simple_logger::SimpleLogger;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

// The default filename for the output.
pub const DEFAULT_FWD_FILE: &str = "forwards.csv";

// The default amount of time data will be generated for.
pub const DEFAULT_RUNTIME: &str = "6months";

#[derive(Parser)]
struct Cli {
    /// A json file describing the lightning channels being simulated.
    #[arg(long, short, default_value = DEFAULT_SIM_FILE)]
    sim_file: PathBuf,

    // The directory to write the output to.
    #[arg(long, short, default_value = DEFAULT_REPUTATION_DIR)]
    output_dir: PathBuf,

    // The amount of time to generate forwarding history for.
    #[arg(long, value_parser = parse_duration, default_value = DEFAULT_RUNTIME)]
    pub duration: (String, Duration),

    /// The alias of the target node.
    #[arg(long)]
    pub target_alias: String,

    /// The alias of the attacking node.
    #[arg(long)]
    pub attacker_alias: String,
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
    let SimNetwork { sim_network } =
        serde_json::from_str(&fs::read_to_string(cli.sim_file.as_path())?)?;

    log::info!("Generating history for: {}", cli.duration.0);

    let target_pubkey = find_pubkey_by_alias(&cli.target_alias, &sim_network)?;
    let attacker_pubkey = find_pubkey_by_alias(&cli.attacker_alias, &sim_network)?;

    let clock = Arc::new(SimulationClock::new(500)?);
    let tasks = TaskTracker::new();

    // Create a reputation interceptor without any bootstrap (since here we're creating the
    // bootstrap itself, we just want to run with reputation active).
    let reputation_interceptor = Arc::new(ReputationInterceptor::new_for_network(
        ForwardManagerParams::default(),
        &sim_network,
        clock.clone(),
        Some(Arc::new(Mutex::new(BootstrapWriter::new(
            clock.clone(),
            cli.output_dir,
        )?))),
    )?);
    let latency_interceptor = Arc::new(LatencyIntercepor::new_poisson(300.0)?);

    let sim_cfg = SimulationCfg::new(
        Some(cli.duration.1.as_secs() as u32),
        3_800_000,
        2.0,
        None,
        Some(13995354354227336701),
    );

    let custom_records =
        CustomRecords::from([(UPGRADABLE_TYPE, vec![1]), (ACCOUNTABLE_TYPE, vec![0])]);

    let sim_params = SimParams {
        nodes: vec![],
        sim_network,
        activity: vec![],
        exclude: vec![attacker_pubkey, target_pubkey],
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
struct BootstrapWriter<C> {
    clock: Arc<C>,
    batch_writer: Mutex<BatchedWriter>,
}

impl<C> BootstrapWriter<C>
where
    C: Clock + InstantClock + Send + Sync,
{
    fn new(clock: Arc<C>, dir: PathBuf) -> Result<Self, BoxError> {
        Ok(BootstrapWriter {
            clock,
            batch_writer: Mutex::new(BatchedWriter::new(dir, DEFAULT_FWD_FILE.into(), 500)?),
        })
    }
}

#[async_trait]
impl<C> ForwardReporter for BootstrapWriter<C>
where
    C: Clock + InstantClock + Send + Sync,
{
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
