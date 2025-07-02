use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use core::panic;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::ReputationParams;
use ln_simln_jamming::analysis::BatchForwardWriter;
use ln_simln_jamming::attack_interceptor::AttackInterceptor;
use ln_simln_jamming::attacks::sink::SinkAttack;
use ln_simln_jamming::attacks::JammingAttack;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{
    find_alias_by_pubkey, find_pubkey_by_alias, reputation_snapshot_from_file, Cli, SimNetwork,
    DEFAULT_REPUTATION_FILENAME, DEFAULT_REVENUE_FILENAME,
};
use ln_simln_jamming::reputation_interceptor::{GeneralChannelJammer, ReputationInterceptor};
use ln_simln_jamming::revenue_interceptor::{RevenueInterceptor, RevenueSnapshot};
use ln_simln_jamming::{
    get_network_reputation, BoxError, NetworkReputation, ACCOUNTABLE_TYPE, UPGRADABLE_TYPE,
};
use log::LevelFilter;
use sim_cli::parsing::{create_simulation_with_network, SimParams};
use simln_lib::clock::Clock;
use simln_lib::clock::SimulationClock;
use simln_lib::latency_interceptor::LatencyIntercepor;
use simln_lib::sim_node::{CustomRecords, Interceptor, SimGraph, SimNode};
use simln_lib::SimulationCfg;
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

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
    cli.validate()?;

    let SimNetwork { sim_network } =
        serde_json::from_str(&fs::read_to_string(cli.sim_file.as_path())?)?;

    let tasks = TaskTracker::new();
    let (shutdown, listener) = triggered::trigger();

    // Match the target alias using pubkeys provided in sim network file, then collect the pubkeys of all the
    // non-attacker target peers.
    let target_pubkey = find_pubkey_by_alias(&cli.target_alias, &sim_network)?;
    let attacker_pubkey = find_pubkey_by_alias(&cli.attacker_alias, &sim_network)?;

    let target_channels: HashMap<u64, (PublicKey, String)> = sim_network
        .iter()
        .filter_map(|channel| {
            if channel.node_1.pubkey == target_pubkey {
                Some((
                    channel.scid.into(),
                    (channel.node_2.pubkey, channel.node_2.alias.clone()),
                ))
            } else if channel.node_2.pubkey == target_pubkey {
                Some((
                    channel.scid.into(),
                    (channel.node_1.pubkey, channel.node_1.alias.clone()),
                ))
            } else {
                None
            }
        })
        .collect();

    let clock = Arc::new(SimulationClock::new(cli.clock_speedup)?);

    // Use the channel jamming interceptor and latency for simulated payments.
    let latency_interceptor: Arc<dyn Interceptor> =
        Arc::new(LatencyIntercepor::new_poisson(150.0)?);

    let now = InstantClock::now(&*clock);
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

    // Create a writer to store results for nodes that we care about.
    let monitor_channels: Vec<(PublicKey, String)> = target_channels.values().cloned().collect();
    let results_writer = Arc::new(Mutex::new(BatchForwardWriter::new(
        cli.results_dir.clone(),
        &monitor_channels,
        cli.result_batch_size,
        now,
    )));

    let results_writer_1 = results_writer.clone();
    let results_listener = listener.clone();
    let results_shutdown = shutdown.clone();
    let results_clock = clock.clone();
    tasks.spawn(async move {
        let interval = Duration::from_secs(60);
        loop {
            select! {
                _ = results_listener.clone() => return,
                _ = results_clock.sleep(interval) => {
                      if let Err(e) = results_writer_1.lock().await.write(){
                        log::error!("Error writing results: {e}");
                        results_shutdown.trigger();
                        return
                    }
                }
            }
        }
    });

    let reputation_dir = &cli.reputation_dir.join(cli.attacker_bootstrap.0.clone());
    let reputation_snapshot =
        reputation_snapshot_from_file(&reputation_dir.join(DEFAULT_REPUTATION_FILENAME))?;

    let bootstrap_revenue: u64 =
        std::fs::read_to_string(reputation_dir.join(DEFAULT_REVENUE_FILENAME))?.parse()?;

    let reputation_interceptor = Arc::new(Mutex::new(
        ReputationInterceptor::new_from_snapshot(
            forward_params,
            &sim_network,
            reputation_snapshot,
            clock.clone(),
            Some(results_writer),
        )
        .await?,
    ));

    // Reputation is assessed for a channel pair and a specific HTLC that's being proposed. To assess whether pairs
    // have reputation, we'll use LND's default fee policy to get the HTLC risk for our configured htlc size and hold
    // time.
    let risk_margin = forward_params.htlc_opportunity_cost(
        1000 + (0.0001 * cli.reputation_margin_msat as f64) as u64,
        cli.reputation_margin_expiry_blocks,
    );

    // Next, setup the attack interceptor to use our custom attack.
    let attack = Arc::new(SinkAttack::new(
        clock.clone(),
        &sim_network,
        target_pubkey,
        attacker_pubkey,
        risk_margin,
        reputation_interceptor.clone(),
        listener.clone(),
    ));

    let attack_setup = attack.setup_for_network()?;
    for (channel, pubkey) in attack_setup.general_jammed_nodes.iter() {
        reputation_interceptor
            .lock()
            .await
            .jam_channel(pubkey, *channel)
            .await?;
    }

    let attack_custom_actions = Arc::clone(&attack);

    // Do some preliminary checks on our reputation state - there isn't much point in running if we haven't built up
    // some reputation.
    let target_pubkey_map: HashMap<u64, PublicKey> =
        target_channels.iter().map(|(k, v)| (*k, v.0)).collect();

    let start_reputation = get_network_reputation(
        reputation_interceptor.clone(),
        target_pubkey,
        attacker_pubkey,
        &target_pubkey_map,
        risk_margin,
        // The reputation_interceptor clock has been set on decaying averages so we use the clock
        // to provide a new instant rather than the previous fixed point.
        InstantClock::now(&*clock),
    )
    .await?;

    check_reputation_status(&cli, &start_reputation)?;

    let attack_interceptor = AttackInterceptor::new(
        attacker_pubkey,
        reputation_interceptor.clone(),
        attack.clone(),
    );

    let attack_interceptor = Arc::new(attack_interceptor);

    // Spawn a task that will trigger shutdown of the simulation if the attacker loses reputation provided that the
    // target is at similar reputation to the start of the simulation. This is a somewhat crude check, because we're
    // only looking at the count of peers with reputation not the actual pairs.
    let attack_clock = clock.clone();
    let attack_listener = listener.clone();
    let attack_shutdown = shutdown.clone();
    let start_reputation_1 = start_reputation.clone();
    tasks.spawn(async move {
        let interval = Duration::from_secs(cli.attacker_poll_interval_seconds);
        loop {
            select! {
                _ = attack_listener.clone() => return,
                _ = attack_clock.sleep(interval) => {
                    match attack.simulation_completed(start_reputation_1.clone()).await {
                        Ok(shutdown) => if shutdown {attack_shutdown.trigger()},
                        Err(e) => {
                            log::error!("Shutdown check failed: {e}");
                            attack_shutdown.trigger();
                        },
                    }
                }
            }
        }
    });

    let revenue_interceptor = Arc::new(
        RevenueInterceptor::new_with_bootstrap(
            clock.clone(),
            target_pubkey,
            bootstrap_revenue,
            cli.attacker_bootstrap.1,
            cli.peacetime_file,
            listener.clone(),
            shutdown.clone(),
        )
        .await?,
    );

    let revenue_interceptor_1 = revenue_interceptor.clone();
    let revenue_shutdown = shutdown.clone();
    tasks.spawn(async move {
        if let Err(e) = revenue_interceptor_1.process_peacetime_fwds().await {
            log::error!("Error processing peacetime forwards: {e}");
            revenue_shutdown.trigger();
        }
    });

    let revenue_interceptor_2 = revenue_interceptor.clone();
    let revenue_shutdown = shutdown.clone();
    tasks.spawn(async move {
        if let Err(e) = revenue_interceptor_2
            .poll_revenue_difference(Duration::from_secs(5))
            .await
        {
            log::error!("Error polling revenue difference: {e}");
            revenue_shutdown.trigger();
        }
    });

    let interceptors = vec![
        latency_interceptor,
        attack_interceptor.clone(),
        revenue_interceptor.clone(),
    ];

    let custom_records =
        CustomRecords::from([(UPGRADABLE_TYPE, vec![1]), (ACCOUNTABLE_TYPE, vec![0])]);

    // Setup the simulated network with our fake graph.
    let sim_params = SimParams {
        nodes: vec![],
        sim_network,
        activity: vec![],
        exclude: vec![],
    };

    let sim_cfg = SimulationCfg::new(None, 3_800_000, 2.0, None, Some(13995354354227336701));
    let (simulation, validated_activities, sim_nodes) = create_simulation_with_network(
        sim_cfg,
        &sim_params,
        clock.clone(),
        tasks,
        interceptors,
        custom_records,
    )
    .await?;

    let attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph>>>> = sim_nodes
        .into_iter()
        .filter_map(|(pk, node)| {
            if pk == attacker_pubkey {
                let alias = match find_alias_by_pubkey(&pk, &sim_params.sim_network) {
                    Ok(alias) => alias,
                    Err(e) => panic!("Attacker pubkey not found {}", e),
                };

                Some((alias, node))
            } else {
                None
            }
        })
        .collect();

    let attacker_actions_shutdown = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = attack_custom_actions
            .run_custom_actions(attacker_nodes, listener.clone())
            .await
        {
            log::error!("Error running custom attacker actions: {e}");
            attacker_actions_shutdown.trigger();
        }
    });

    // Run simulation until it shuts down, then wait for the graph to exit.
    simulation.run(&validated_activities).await?;

    // Write start and end state to a summary file.
    let end_reputation = get_network_reputation(
        reputation_interceptor,
        target_pubkey,
        attacker_pubkey,
        &target_pubkey_map,
        risk_margin,
        InstantClock::now(&*clock),
    )
    .await?;

    let snapshot = revenue_interceptor.get_revenue_difference().await;
    write_simulation_summary(
        cli.results_dir,
        &snapshot,
        &start_reputation,
        &end_reputation,
        attack_setup.general_jammed_nodes.len(),
    )?;

    Ok(())
}

/// Checks whether the attacker and target meet the required portion of high reputation pairs to required.
fn check_reputation_status(cli: &Cli, status: &NetworkReputation) -> Result<(), BoxError> {
    log::info!(
        "Attacker has {} out of {} pairs with reputation",
        status.attacker_reputation,
        status.attacker_pair_count,
    );

    log::info!(
        "Target has {}/{} pairs with reputation with its peers",
        status.target_reputation,
        status.target_pair_count,
    );

    let attacker_threshold =
        status.attacker_pair_count * cli.attacker_reputation_percent as usize / 100;
    if status.attacker_reputation < attacker_threshold {
        return Err(format!(
            "attacker has {}/{} good reputation pairs which does not meet threshold {}",
            status.attacker_reputation, status.attacker_pair_count, attacker_threshold,
        )
        .into());
    }

    let target_threshold = status.target_pair_count * cli.target_reputation_percent as usize / 100;
    if status.target_reputation < target_threshold {
        return Err(format!(
            "target has {}/{} good reputation pairs which does not meet threshold {}",
            status.target_reputation, status.target_pair_count, target_threshold,
        )
        .into());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_simulation_summary(
    data_dir: PathBuf,
    revenue: &RevenueSnapshot,
    start_reputation: &NetworkReputation,
    end_reputation: &NetworkReputation,
    general_jammed: usize,
) -> Result<(), BoxError> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(data_dir.join("summary.txt"))?;

    let mut writer = BufWriter::new(file);

    writeln!(writer, "Runtime (seconds): {:?}", revenue.runtime.as_secs())?;
    writeln!(
        writer,
        "Peacetime revenue (msat): {}",
        revenue.peacetime_revenue_msat
    )?;
    writeln!(
        writer,
        "Simulation revenue (msat): {}",
        revenue.simulation_revenue_msat,
    )?;

    if revenue.simulation_revenue_msat > revenue.peacetime_revenue_msat {
        writeln!(
            writer,
            "Revenue gain in simulation: {}",
            revenue.simulation_revenue_msat - revenue.peacetime_revenue_msat,
        )?;
    } else {
        writeln!(
            writer,
            "Revenue loss in simulation: {}",
            revenue.peacetime_revenue_msat - revenue.simulation_revenue_msat,
        )?;
    }

    writeln!(
        writer,
        "Attacker start reputation (pairs): {}/{}",
        start_reputation.attacker_reputation, start_reputation.attacker_pair_count,
    )?;
    writeln!(
        writer,
        "Attacker end reputation (pairs): {}/{}",
        end_reputation.attacker_reputation, end_reputation.attacker_pair_count,
    )?;

    writeln!(
        writer,
        "Target start reputation (pairs): {}/{}",
        start_reputation.target_reputation, start_reputation.target_pair_count,
    )?;
    writeln!(
        writer,
        "Target end reputation (pairs): {}/{}",
        end_reputation.attacker_reputation, end_reputation.attacker_pair_count,
    )?;
    writeln!(
        writer,
        "Attacker general jammed {general_jammed} edges (directional)",
    )?;
    writer.flush()?;

    Ok(())
}
