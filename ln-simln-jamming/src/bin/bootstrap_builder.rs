use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::forward_manager::{ForwardManager, ForwardManagerParams};
use ln_resource_mgr::{AllocationCheck, ProposedForward};
use ln_simln_jamming::analysis::{BatchForwardWriter, ForwardReporter};
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{
    get_history_for_bootstrap, parse_duration, AttackType, NetworkParams, NetworkType,
    ReputationParams,
};
use ln_simln_jamming::reputation_interceptor::{
    BootstrapForward, BootstrapRecords, ReputationInterceptor, ReputationMonitor,
};
use ln_simln_jamming::{BoxError, ACCOUNTABLE_TYPE, SIM_SEED, UPGRADABLE_TYPE};
use log::LevelFilter;
use sim_cli::parsing::{create_simulation_with_network, SimParams};
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::latency_interceptor::LatencyIntercepor;
use simln_lib::runtime::block_on_virtual_time;
use simln_lib::sim_node::CustomRecords;
use simln_lib::SimulationCfg;
use simple_logger::SimpleLogger;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

/// The default amount of time forwarding history is generated for. Anything beyond the reputation
/// window is decayed away, but a margin is generated so the window is fully populated.
pub const DEFAULT_RUNTIME: &str = "6months";

/// Collects generated forwards into memory instead of writing them to a traffic CSV. The full set
/// is drained after the generation sim completes and replayed to build the reputation snapshot.
#[derive(Clone)]
struct ForwardCollector {
    clock: Arc<SimulationClock>,
    forwards: Arc<Mutex<Vec<BootstrapForward>>>,
}

impl ForwardCollector {
    fn new(clock: Arc<SimulationClock>) -> Self {
        Self {
            clock,
            forwards: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl ForwardReporter for ForwardCollector {
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

        self.forwards.lock().await.push(BootstrapForward {
            incoming_amt: forward.amount_in_msat,
            outgoing_amt: forward.amount_out_msat,
            incoming_expiry: forward.expiry_in_height,
            outgoing_expiry: forward.expiry_out_height,
            added_ns: settled_ns - nanos_since_added,
            settled_ns,
            forwarding_node,
            channel_in_id: forward.incoming_ref.channel_id,
            channel_out_id: forward.outgoing_channel_id,
        });
        Ok(())
    }
}

/// Trims an in-memory, timestamp-ordered forward set to the first `window` of activity, matching
/// the cutoff the old file reader applied: stop at the first forward added or settled after
/// `first.added_ns + window`.
fn trim_to_window(forwards: Vec<BootstrapForward>, window: Duration) -> Vec<BootstrapForward> {
    let mut cutoff: Option<u64> = None;
    let mut out = Vec::new();
    for f in forwards {
        let c = *cutoff.get_or_insert(f.added_ns + window.as_nanos() as u64);
        if f.added_ns > c || f.settled_ns > c {
            break;
        }
        out.push(f);
    }
    out
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(flatten)]
    network: NetworkParams,

    /// The amount of time to generate forwarding history for.
    #[arg(long, value_parser = parse_duration, default_value = DEFAULT_RUNTIME)]
    pub duration: Duration,

    #[command(flatten)]
    pub reputation_params: ReputationParams,

    /// The attack whose graph to generate against. Required with --attacker-bootstrap.
    #[arg(long, value_enum, requires = "attacker_bootstrap")]
    pub attack_type: Option<AttackType>,

    /// Duration the attacker passively forwards to build reputation, e.g. 30d. Requires
    /// --attack-type. Produces attacks/<attack>/reputation_<secs>.csv.
    #[arg(long, value_parser = parse_duration, requires = "attack_type")]
    pub attacker_bootstrap: Option<Duration>,
}

fn main() -> Result<(), BoxError> {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .with_module_level("simln_lib", LevelFilter::Info)
        .with_module_level("sim_cli", LevelFilter::Off)
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    let cli = Cli::parse();
    let start_time = SystemTime::now();
    block_on_virtual_time(start_time, |clock| run(clock, cli))??;
    Ok(())
}

async fn run(clock: Arc<SimulationClock>, cli: Cli) -> Result<(), BoxError> {
    let forward_params: ForwardManagerParams = cli.reputation_params.clone().into();
    let network = NetworkType::new(
        &cli.network,
        cli.attack_type.clone(),
        cli.attacker_bootstrap,
    )?;

    // ---- Phase 1: generate forwards in memory ----
    let gen_graph = network.active_network();
    let collector = ForwardCollector::new(clock.clone());
    let gen_interceptor = Arc::new(ReputationInterceptor::new_for_network(
        forward_params,
        gen_graph,
        clock.clone(),
        Some(Arc::new(Mutex::new(collector.clone()))),
    )?);
    let latency = Arc::new(LatencyIntercepor::new_poisson(300.0, Some(SIM_SEED))?);

    let sim_cfg = SimulationCfg::new(
        Some(cli.duration.as_secs() as u32),
        3_800_000,
        2.0,
        None,
        Some(SIM_SEED),
    );

    let exclude = [network.target().1]
        .into_iter()
        .chain(network.attackers().iter().map(|a| a.1))
        .collect();

    let custom_records =
        CustomRecords::from([(UPGRADABLE_TYPE, vec![1]), (ACCOUNTABLE_TYPE, vec![0])]);

    let sim_params = SimParams {
        nodes: vec![],
        sim_network: gen_graph.to_vec(),
        activity: vec![],
        exclude,
    };

    let (simulation, activities, _nodes) = create_simulation_with_network(
        sim_cfg,
        &sim_params,
        clock.clone(),
        TaskTracker::new(),
        vec![gen_interceptor, latency],
        custom_records,
    )
    .await?;
    simulation.run(&activities).await?;

    let generated = std::mem::take(&mut *collector.forwards.lock().await);

    // ---- Phase 2: summarize into a reputation snapshot ----
    let window = forward_params.reputation_params.reputation_window();
    let windowed = trim_to_window(generated, window);

    let target_pubkey = network.target().1;
    let bootstrap: BootstrapRecords = if let Some(bootstrap_dur) = cli.attacker_bootstrap {
        let attacker_pubkeys: Vec<PublicKey> = network.attackers().iter().map(|a| a.1).collect();
        let target_to_attacker_channels: HashSet<u64> = network
            .active_network()
            .iter()
            .filter(|c| {
                (c.node_1.pubkey == target_pubkey && attacker_pubkeys.contains(&c.node_2.pubkey))
                    || (attacker_pubkeys.contains(&c.node_1.pubkey)
                        && c.node_2.pubkey == target_pubkey)
            })
            .map(|c| u64::from(c.scid))
            .collect();
        get_history_for_bootstrap(bootstrap_dur, windowed, target_to_attacker_channels)?
    } else {
        let last_timestamp_nanos = windowed
            .iter()
            .max_by(|x, y| x.settled_ns.cmp(&y.settled_ns))
            .ok_or("at least one entry required in bootstrap history")?
            .settled_ns;
        BootstrapRecords {
            forwards: windowed,
            last_timestamp_nanos,
        }
    };

    let mut rep_interceptor: ReputationInterceptor<BatchForwardWriter, ForwardManager> =
        ReputationInterceptor::new_for_network(
            forward_params,
            network.active_network(),
            clock.clone(),
            None,
        )?;
    rep_interceptor
        .bootstrap_network_history(&bootstrap)
        .await?;

    // Collect all node pubkeys and write the snapshot CSV.
    let mut node_pubkeys = HashSet::new();
    for chan in network.active_network().iter() {
        node_pubkeys.insert(chan.node_1.pubkey);
        node_pubkeys.insert(chan.node_2.pubkey);
    }

    let reputation_file = network.reputation_file();
    let snapshot_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&reputation_file)?;
    let mut csv_writer = csv::Writer::from_writer(snapshot_file);
    csv_writer.write_record([
        "pubkey",
        "scid",
        "channel_capacity",
        "outgoing_reputation",
        "incoming_revenue",
    ])?;
    for pubkey in node_pubkeys {
        for channel in rep_interceptor
            .list_channels(pubkey, InstantClock::now(&*clock))
            .await?
        {
            csv_writer.serialize((
                pubkey,
                channel.0,
                channel.1.capacity_msat,
                channel.1.outgoing_reputation,
                channel.1.incoming_revenue,
            ))?;
        }
    }
    csv_writer.flush()?;
    log::info!("Wrote reputation snapshot to {:?}", reputation_file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(added_ns: u64, settled_ns: u64) -> BootstrapForward {
        BootstrapForward {
            incoming_amt: 1000,
            outgoing_amt: 900,
            incoming_expiry: 0,
            outgoing_expiry: 0,
            added_ns,
            settled_ns,
            forwarding_node: PublicKey::from_slice(&[2; 33]).unwrap(),
            channel_in_id: 1,
            channel_out_id: 2,
        }
    }

    #[test]
    fn trims_at_window_cutoff() {
        // window is 100ns starting at the first forward's added_ns (10).
        let input = vec![fwd(10, 20), fwd(50, 80), fwd(90, 200), fwd(95, 99)];
        let out = trim_to_window(input, Duration::from_nanos(100));
        // Third forward settles at 200 > cutoff 110, so we stop there and keep the first two.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].added_ns, 10);
        assert_eq!(out[1].added_ns, 50);
    }
}
