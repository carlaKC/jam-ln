use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use csv::Writer;
use ln_resource_mgr::{
    forward_manager::{ForwardManager, ForwardManagerParams},
    ReputationParams,
};
use ln_simln_jamming::{
    analysis::BatchForwardWriter,
    clock::InstantClock,
    parsing::{
        find_pubkey_by_alias, get_history_for_bootstrap, history_from_file, parse_duration,
        SimNetwork, DEFAULT_REPUTATION_DIR, DEFAULT_REPUTATION_FILENAME,
        DEFAULT_REPUTATION_MULTIPLIER, DEFAULT_REVENUE_FILENAME, DEFAULT_REVENUE_WINDOW_SECONDS,
        DEFAULT_SIM_FILE,
    },
    reputation_interceptor::{BoostrapRecords, ReputationInterceptor, ReputationMonitor},
    BoxError,
};
use log::LevelFilter;
use simln_lib::clock::SimulationClock;
use simple_logger::SimpleLogger;

/// Default file used to bootstrap reputation.
const DEFAULT_BOOTSTRAP_FILE: &str = "./bootstrap.csv";

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// A json file describing the lightning channels being simulated.
    #[arg(long, short, default_value = DEFAULT_SIM_FILE)]
    sim_file: PathBuf,

    /// A CSV file containing forwards for the network, including the attacker used to bootstrap reputation for the
    /// simulation.
    #[arg(long, default_value = DEFAULT_BOOTSTRAP_FILE)]
    bootstrap_file: PathBuf,

    /// The duration of time that reputation of the attacking node should be bootstrapped for, expressed as human
    /// readable values (eg: 1w, 3d).
    #[arg(long, value_parser = parse_duration)]
    attacker_bootstrap: Option<(String, Duration)>,

    /// The window over which the value of a link's revenue to our node is calculated.
    #[arg(long, default_value = DEFAULT_REVENUE_WINDOW_SECONDS)]
    revenue_window_seconds: u64,

    /// The multiplier applied to revenue_window_seconds to get the duration over which reputation is bootstrapped.
    #[arg(long, default_value = DEFAULT_REPUTATION_MULTIPLIER)]
    reputation_multiplier: u8,

    /// The directory to write reputation snapshot and revenue file.
    #[arg(long, default_value = DEFAULT_REPUTATION_DIR)]
    results_dir: PathBuf,

    /// The alias of the target node.
    #[arg(long)]
    target_alias: String,

    /// The alias of the attacking node.
    #[arg(long)]
    attacker_alias: Option<String>,
}

impl Cli {
    fn reputation_window(&self) -> Duration {
        Duration::from_secs(self.revenue_window_seconds * self.reputation_multiplier as u64)
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    let cli = Cli::parse();

    let SimNetwork { sim_network } =
        serde_json::from_str(&fs::read_to_string(cli.sim_file.as_path())?)?;

    let unfiltered_history =
        history_from_file(&cli.bootstrap_file, Some(cli.reputation_window())).await?;

    let target_pubkey = find_pubkey_by_alias(&cli.target_alias, &sim_network)?;

    // filter bootstrap records if attacker alias and bootstrap provided
    let bootstrap = if cli.attacker_alias.is_some() && cli.attacker_bootstrap.is_some() {
        let attacker_pubkey = find_pubkey_by_alias(&cli.attacker_alias.unwrap(), &sim_network)?;

        let target_to_attacker = match sim_network.iter().find(|&channel| {
            (channel.node_1.pubkey == target_pubkey && channel.node_2.pubkey == attacker_pubkey)
                || (channel.node_1.pubkey == attacker_pubkey
                    && channel.node_2.pubkey == target_pubkey)
        }) {
            Some(channel) => u64::from(channel.scid),
            None => {
                return Err("no channel between target and attacker".to_string().into());
            }
        };

        get_history_for_bootstrap(
            cli.attacker_bootstrap.clone().unwrap().1,
            unfiltered_history,
            HashSet::from_iter(vec![target_to_attacker]),
        )?
    } else {
        let last_timestamp_nanos = unfiltered_history
            .iter()
            .max_by(|x, y| x.settled_ns.cmp(&y.settled_ns))
            .ok_or("at least one entry required in bootstrap history")?
            .settled_ns;
        BoostrapRecords {
            forwards: unfiltered_history,
            last_timestamp_nanos,
        }
    };

    let bootstrap_revenue = bootstrap.forwards.iter().fold(0, |acc, item| {
        if item.forwarding_node == target_pubkey {
            acc + item.incoming_amt - item.outgoing_amt
        } else {
            acc
        }
    });

    let (shutdown, _listener) = triggered::trigger();
    let clock = Arc::new(SimulationClock::new(1)?);
    let forward_params = ForwardManagerParams {
        reputation_params: ReputationParams {
            revenue_window: Duration::from_secs(cli.revenue_window_seconds),
            reputation_multiplier: cli.reputation_multiplier,
            resolution_period: Duration::from_secs(90),
            expected_block_speed: Some(Duration::from_secs(10 * 60)),
        },
        general_slot_portion: 30,
        general_liquidity_portion: 30,
        congestion_slot_portion: 20,
        congestion_liquidity_portion: 20,
    };

    let reputation_clock = Arc::clone(&clock);
    let mut reputation_interceptor: ReputationInterceptor<BatchForwardWriter, ForwardManager> =
        ReputationInterceptor::new_for_network(
            forward_params,
            &sim_network,
            reputation_clock,
            None,
            shutdown,
        )?;

    reputation_interceptor
        .bootstrap_network_history(&bootstrap)
        .await?;

    let mut node_pubkeys = HashSet::new();
    for chan in sim_network {
        node_pubkeys.insert(chan.node_1.pubkey);
        node_pubkeys.insert(chan.node_2.pubkey);
    }

    let snapshot_dir = match cli.attacker_bootstrap {
        // if a bootstrap period is provided, write results in ./reputation-snapshot/{duration}
        Some(bootstrap_filter) => cli.results_dir.join(bootstrap_filter.0),
        None => cli.results_dir,
    };
    fs::create_dir_all(&snapshot_dir)?;

    let mut target_revenue = File::create(snapshot_dir.join(DEFAULT_REVENUE_FILENAME))?;
    write!(target_revenue, "{}", bootstrap_revenue)?;

    let snapshot_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(snapshot_dir.join(DEFAULT_REPUTATION_FILENAME))?;

    let mut csv_writer = Writer::from_writer(snapshot_file);
    csv_writer.write_record([
        "pubkey",
        "scid",
        "channel_capacity",
        "outgoing_reputation",
        "bidirectional_revenue",
    ])?;

    for pubkey in node_pubkeys {
        let channels = reputation_interceptor
            .list_channels(pubkey, InstantClock::now(&*clock))
            .await?;

        for channel in channels {
            csv_writer.serialize((
                pubkey,
                channel.0,
                channel.1.capacity_msat,
                channel.1.outgoing_reputation,
                channel.1.bidirectional_revenue,
            ))?;
        }
    }
    csv_writer.flush()?;

    log::info!("Finished writing reputation snapshot to {:?}", snapshot_dir);

    Ok(())
}
