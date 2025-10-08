use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::Write,
    sync::Arc,
    time::Duration,
};

use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use csv::Writer;
use ln_resource_mgr::forward_manager::{ForwardManager, ForwardManagerParams};
use ln_simln_jamming::{
    analysis::BatchForwardWriter,
    clock::InstantClock,
    parsing::{
        get_history_for_bootstrap, history_from_file, parse_duration, AttackType, NetworkParams,
        NetworkType, ReputationParams,
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

    #[command(flatten)]
    pub reputation_params: ReputationParams,

    /// The attack that we're interested in running.
    #[arg(long, value_enum, requires = "attacker_bootstrap")]
    pub attack_type: Option<AttackType>,

    /// The duration of time that reputation of the attacking node's reputation will be bootstrapped
    /// for, expressed as human readable values (eg: 1w, 3d).
    #[arg(long, value_parser = parse_duration, requires = "attack_type")]
    pub attacker_bootstrap: Option<Duration>,
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

    let network = NetworkType::new(&cli.network, cli.attack_type, cli.attacker_bootstrap)?;
    if matches!(network, NetworkType::AttackTime(_, _)) {
        return Err("reputation builder must be run with bootstrapped attack or no attack".into());
    }

    let active_network = network.active_network();
    let target_pubkey = network.target().1;
    let traffic_file = network.traffic_file();

    let unfiltered_history = history_from_file(
        &traffic_file,
        Some(forward_params.reputation_params.reputation_window()),
    )
    .await?;

    // Filter bootstrap records if attacker alias and bootstrap provided.
    // Only add up revenue if attacker bootstrap is specified.
    let (bootstrap, bootstrap_revenue) = if let Some(bootstrap_dur) = cli.attacker_bootstrap {
        let attacker_pubkeys: Vec<PublicKey> = network.attackers().iter().map(|a| a.1).collect();
        let target_to_attacker_channels: HashSet<u64> = active_network
            .iter()
            .filter(|&channel| {
                (channel.node_1.pubkey == target_pubkey
                    && attacker_pubkeys.contains(&channel.node_2.pubkey))
                    || (attacker_pubkeys.contains(&channel.node_1.pubkey)
                        && channel.node_2.pubkey == target_pubkey)
            })
            .map(|channel| u64::from(channel.scid))
            .collect();

        let bootstrap = get_history_for_bootstrap(
            bootstrap_dur,
            unfiltered_history,
            target_to_attacker_channels,
        )?;

        let revenue = bootstrap.forwards.iter().fold(0, |acc, item| {
            if item.forwarding_node == target_pubkey {
                acc + item.incoming_amt - item.outgoing_amt
            } else {
                acc
            }
        });

        (bootstrap, revenue)
    } else {
        let last_timestamp_nanos = unfiltered_history
            .iter()
            .max_by(|x, y| x.settled_ns.cmp(&y.settled_ns))
            .ok_or("at least one entry required in bootstrap history")?
            .settled_ns;

        let bootstrap_records = BootstrapRecords {
            forwards: unfiltered_history,
            last_timestamp_nanos,
        };

        (bootstrap_records, 0)
    };

    let clock = Arc::new(SimulationClock::new(1)?);
    let reputation_clock = Arc::clone(&clock);
    let mut reputation_interceptor: ReputationInterceptor<BatchForwardWriter, ForwardManager> =
        ReputationInterceptor::new_for_network(
            forward_params,
            active_network,
            reputation_clock,
            None,
        )?;

    reputation_interceptor
        .bootstrap_network_history(&bootstrap)
        .await?;

    let mut node_pubkeys = HashSet::new();
    for chan in active_network.iter() {
        node_pubkeys.insert(chan.node_1.pubkey);
        node_pubkeys.insert(chan.node_2.pubkey);
    }

    let reputation_file = network.reputation_file();
    let revenue_file = network.revenue_file();

    if let Some(revenue_file_path) = &revenue_file {
        let mut target_revenue = File::create(revenue_file_path)?;
        write!(target_revenue, "{}", bootstrap_revenue)?;
    }

    let snapshot_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&reputation_file)?;

    let mut csv_writer = Writer::from_writer(snapshot_file);
    csv_writer.write_record([
        "pubkey",
        "scid",
        "channel_capacity",
        "outgoing_reputation",
        "incoming_revenue",
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
                channel.1.incoming_revenue,
            ))?;
        }
    }
    csv_writer.flush()?;

    log::info!(
        "Finished writing reputation snapshot to {:?}{}",
        reputation_file.to_string_lossy(),
        if let Some(p) = revenue_file {
            format!(" and revenue to: {}", p.to_string_lossy())
        } else {
            "".to_string()
        },
    );

    Ok(())
}
