use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use csv::Writer;
use ln_resource_mgr::{
    ReputationParams,
    forward_manager::{ForwardManager, ForwardManagerParams},
};
use ln_simln_jamming::{
    BoxError,
    analysis::BatchForwardWriter,
    clock::InstantClock,
    parsing::{SimNetwork, find_pubkey_by_alias, get_history_for_bootstrap, history_from_file},
    reputation_interceptor::{BoostrapRecords, ReputationInterceptor, ReputationMonitor},
};
use log::LevelFilter;
use parsing::Cli;
use simln_lib::clock::SimulationClock;
use simple_logger::SimpleLogger;

mod parsing;

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

    // filter bootstrap records if attacker alias and bootstrap provided
    let bootstrap = if cli.attacker_alias.is_some() && cli.attacker_bootstrap.is_some() {
        match cli.target_alias {
            Some(target) => {
                let target_pubkey = find_pubkey_by_alias(&target, &sim_network)?;
                let attacker_pubkey =
                    find_pubkey_by_alias(&cli.attacker_alias.unwrap(), &sim_network)?;

                let target_to_attacker = match sim_network.iter().find(|&channel| {
                    (channel.node_1.pubkey == target_pubkey
                        && channel.node_2.pubkey == attacker_pubkey)
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
            }
            None => return Err("target not provided".to_string().into()),
        }
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

    let (shutdown, _listener) = triggered::trigger();
    let clock = Arc::new(SimulationClock::new(cli.clock_speedup)?);
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

    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(snapshot_dir.join("reputation-snapshot.csv"))?;

    let mut csv_writer = Writer::from_writer(file);
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

    log::info!("finished writing reputation snapshot");

    Ok(())
}
