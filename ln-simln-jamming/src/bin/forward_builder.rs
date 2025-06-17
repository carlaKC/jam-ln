use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::forward_manager::{ForwardManager, ForwardManagerParams};
use ln_resource_mgr::HtlcRef;
use ln_simln_jamming::analysis::BatchForwardWriter;
use ln_simln_jamming::parsing::{
    parse_duration, SimNetwork, DEFAULT_REPUTATION_DIR, DEFAULT_SIM_FILE,
};
use ln_simln_jamming::reputation_interceptor::{BootstrapForward, ReputationInterceptor};
use ln_simln_jamming::{BoxError, ACCOUNTABLE_TYPE, UPGRADABLE_TYPE};
use log::LevelFilter;
use simln_lib::batched_writer::BatchedWriter;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::sim_node::{
    ln_node_from_graph, populate_network_graph, CriticalError, CustomRecords, ForwardingError,
    InterceptRequest, InterceptResolution, Interceptor, SimGraph, SimulatedChannel,
};
use simln_lib::{Simulation, SimulationCfg};
use simple_logger::SimpleLogger;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
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

    // TODO: pull this out into a helper (also needed in #77 which is in-flight).
    let channels = sim_network
        .clone()
        .into_iter()
        .map(SimulatedChannel::from)
        .collect::<Vec<SimulatedChannel>>();

    let mut nodes_info = HashMap::new();
    for channel in &channels {
        let (node_1_info, node_2_info) = channel.create_simulated_nodes();
        nodes_info.insert(node_1_info.pubkey, node_1_info);
        nodes_info.insert(node_2_info.pubkey, node_2_info);
    }

    let clock = Arc::new(SimulationClock::new(500)?);
    let (shutdown_trigger, shutdown_listener) = triggered::trigger();
    let tasks = TaskTracker::new();

    // Create a reputation interceptor without any bootstrap (since here we're creating the
    // bootstrap itself, we just want to run with reputation active).
    let reputation_interceptor = Arc::new(ReputationInterceptor::<
        BatchForwardWriter,
        ForwardManager,
    >::new_for_network(
        ForwardManagerParams::default(),
        &sim_network,
        clock.clone(),
        None,
    )?);

    let writer_interceptor = Arc::new(ForwardWriter::new(clock.clone(), cli.output_dir)?);
    let simulation_graph = Arc::new(Mutex::new(SimGraph::new(
        channels.clone(),
        tasks.clone(),
        vec![writer_interceptor, reputation_interceptor],
        CustomRecords::from([(UPGRADABLE_TYPE, vec![1]), (ACCOUNTABLE_TYPE, vec![0])]),
        (shutdown_trigger.clone(), shutdown_listener.clone()),
    )?));

    let routing_graph =
        Arc::new(populate_network_graph(channels, clock.clone()).map_err(|e| format!("{:?}", e))?);

    let nodes = ln_node_from_graph(simulation_graph.clone(), routing_graph).await;
    // TODO: remove attacker + target pk from random activity

    let sim_cfg = SimulationCfg::new(
        Some(cli.duration.1.as_secs() as u32),
        3_800_000,
        2.0,
        None,
        Some(13995354354227336701),
    );
    let simulation = Simulation::new(
        sim_cfg,
        nodes,
        tasks,
        clock,
        shutdown_trigger,
        shutdown_listener,
    );

    let activites = vec![];
    simulation.run(&activites).await?;

    Ok(())
}

struct ForwardWriter<C> {
    // Tracks all the currently in-flight HTLCs, reusing the [`BootstrapForward`] struct for
    // convenience. One shortcoming of this approach is that we need to set `settled_ns` to zero
    // when we first store the payment.
    in_flight: Mutex<HashMap<PublicKey, HashMap<HtlcRef, BootstrapForward>>>,
    clock: Arc<C>,
    batch_writer: Mutex<BatchedWriter>,
}

impl<C> ForwardWriter<C>
where
    C: Clock,
{
    fn new(clock: Arc<C>, dir: PathBuf) -> Result<Self, BoxError> {
        Ok(ForwardWriter {
            in_flight: Mutex::new(HashMap::new()),
            clock: clock.clone(),
            batch_writer: Mutex::new(BatchedWriter::new(dir, DEFAULT_FWD_FILE.into(), 500)?),
        })
    }
}

#[async_trait]
impl<C> Interceptor for ForwardWriter<C>
where
    C: Clock + Send + Sync,
{
    async fn intercept_htlc(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, CriticalError> {
        // We only care about writing forwards, not final receives.
        let outgoing_scid = if let Some(scid) = req.outgoing_channel_id {
            scid
        } else {
            return Ok(Ok(CustomRecords::new()));
        };

        let mut lock = self.in_flight.lock().await;
        let in_flight = match lock.entry(req.forwarding_node) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(HashMap::new()),
        };

        match in_flight.entry(HtlcRef {
            channel_id: req.incoming_htlc.channel_id.into(),
            htlc_index: req.incoming_htlc.index,
        }) {
            Entry::Occupied(_) => {
                return Err(CriticalError::InterceptorError(format!(
                    "duplicate incoming htlc {:?}",
                    req.incoming_htlc,
                )))
            }
            Entry::Vacant(v) => {
                v.insert(BootstrapForward {
                    incoming_amt: req.incoming_amount_msat,
                    outgoing_amt: req.outgoing_amount_msat,
                    incoming_expiry: req.incoming_expiry_height,
                    outgoing_expiry: req.outgoing_expiry_height,
                    added_ns: self
                        .clock
                        .now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|e| {
                            CriticalError::InterceptorError(format!("clock error: {}", e))
                        })?
                        .as_nanos() as u64,
                    // Note: we just set this to zero now, because we don't have a settle time.
                    settled_ns: 0,
                    forwarding_node: req.forwarding_node,
                    channel_in_id: req.incoming_htlc.channel_id.into(),
                    channel_out_id: outgoing_scid.into(),
                });
            }
        }

        Ok(Ok(CustomRecords::new()))
    }

    async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), CriticalError> {
        if res.outgoing_channel_id.is_none() {
            return Ok(());
        }

        let mut in_flight = self
            .in_flight
            .lock()
            .await
            .get_mut(&res.forwarding_node)
            .ok_or(CriticalError::InterceptorError(format!(
                "forwarding node: {} not found",
                res.forwarding_node
            )))?
            .remove(&HtlcRef {
                channel_id: res.incoming_htlc.channel_id.into(),
                htlc_index: res.incoming_htlc.index,
            })
            .ok_or(CriticalError::InterceptorError(format!(
                "forward not found in flight: {:?}",
                res.incoming_htlc
            )))?;

        assert_eq!(in_flight.settled_ns, 0);

        in_flight.settled_ns = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CriticalError::InterceptorError(format!("clock error: {}", e)))?
            .as_nanos() as u64;

        self.batch_writer
            .lock()
            .await
            .queue(in_flight)
            .map_err(|e| CriticalError::InterceptorError(format!("could not queue item: {}", e)))?;

        Ok(())
    }

    fn name(&self) -> String {
        "forward writer".to_string()
    }
}
