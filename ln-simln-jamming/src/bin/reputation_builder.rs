use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::Write,
    sync::Arc,
    time::Duration,
};

use clap::Parser;
use csv::Writer;
use ln_resource_mgr::forward_manager::{ForwardManager, ForwardManagerParams};
use ln_simln_jamming::{
    analysis::BatchForwardWriter,
    clock::InstantClock,
    parsing::{
        get_history_for_bootstrap, history_from_file, parse_duration, NetworkParams,
        ReputationParams, SimulationFiles, TrafficType,
    },
    reputation_interceptor::{BootstrapRecords, ReputationInterceptor, ReputationMonitor},
    BoxError,
};
use log::LevelFilter;
use simln_lib::clock::SimulationClock;
use simple_logger::SimpleLogger;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(flatten)]
    network: NetworkParams,

    #[arg(long, value_parser = parse_duration)]
    pub attacker_bootstrap: Option<Duration>,

    #[command(flatten)]
    pub reputation_params: ReputationParams,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    let cli = Cli::parse();
    let forward_params: ForwardManagerParams = cli.reputation_params.into();

    let network_type = match cli.attacker_bootstrap {
        Some(_) => TrafficType::Attacktime,
        None => TrafficType::Peacetime,
    };
    let network_dir = SimulationFiles::new(cli.network.network_dir, network_type)?;
    let (attacker_pubkey, target_pubkey) = (network_dir.attacker.1, network_dir.target.1);

    // If no attacker bootstrap period is specified, we can just use the traffic from peacetime
    // projections to bootstrap peaceful nodes in the network. This may provide a quicker start
    // for some attacks because you do not need to generate the second traffic file.
    let traffic_file = if cli.attacker_bootstrap.is_some() {
        &network_dir.attacktime_traffic()
    } else {
        &network_dir.peacetime_traffic()
    };

    let unfiltered_history = history_from_file(
        traffic_file,
        Some(forward_params.reputation_params.revenue_window),
    )
    .await?;

    // Filter bootstrap records if attacker alias and bootstrap provided.
    let bootstrap = if let Some(bootstrap_dur) = cli.attacker_bootstrap {
        if bootstrap_dur.is_zero() {
            return Err("zero attacker_bootstrap is invalid, do not specify option".into());
        }

        let target_to_attacker = match network_dir.sim_network.iter().find(|&channel| {
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
            bootstrap_dur,
            unfiltered_history,
            HashSet::from_iter(vec![target_to_attacker]),
        )?
    } else {
        let last_timestamp_nanos = unfiltered_history
            .iter()
            .max_by(|x, y| x.settled_ns.cmp(&y.settled_ns))
            .ok_or("at least one entry required in bootstrap history")?
            .settled_ns;
        BootstrapRecords {
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

    let clock = Arc::new(SimulationClock::new(1)?);
    let reputation_clock = Arc::clone(&clock);
    let mut reputation_interceptor: ReputationInterceptor<BatchForwardWriter, ForwardManager> =
        ReputationInterceptor::new_for_network(
            forward_params,
            &network_dir.sim_network,
            reputation_clock,
            None,
        )?;

    reputation_interceptor
        .bootstrap_network_history(&bootstrap)
        .await?;

    let mut node_pubkeys = HashSet::new();
    for chan in network_dir.sim_network.iter() {
        node_pubkeys.insert(chan.node_1.pubkey);
        node_pubkeys.insert(chan.node_2.pubkey);
    }

    let (reputation_state, target_revenue) = network_dir.reputation_summary(cli.attacker_bootstrap);

    let mut target_revenue = File::create(target_revenue)?;
    write!(target_revenue, "{}", bootstrap_revenue)?;

    let snapshot_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&reputation_state)?;

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

    log::info!(
        "Finished writing reputation snapshot to {:?} and {:?}",
        reputation_state,
        target_revenue
    );

    Ok(())
}
