use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::forward_manager::{ForwardManager, ForwardManagerParams};
use ln_resource_mgr::ReputationParams;
use ln_simln_jamming::analysis::BatchForwardWriter;
use ln_simln_jamming::attack_interceptor::AttackInterceptor;
use ln_simln_jamming::attacks::sink::SinkAttack;
use ln_simln_jamming::attacks::JammingAttack;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{get_history_for_bootstrap, history_from_file, Cli};
use ln_simln_jamming::reputation_interceptor::ReputationInterceptor;
use ln_simln_jamming::revenue_interceptor::{RevenueInterceptor, RevenueSnapshot};
use ln_simln_jamming::{get_network_reputation, BoxError, NetworkReputation};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use simln_lib::clock::Clock;
use simln_lib::clock::SimulationClock;
use simln_lib::interceptors::LatencyIntercepor;
use simln_lib::sim_node::{Interceptor, SimulatedChannel};
use simln_lib::{NetworkParser, Simulation, SimulationCfg};
use simple_logger::SimpleLogger;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::select;
use tokio::task::JoinSet;

#[derive(Serialize, Deserialize)]
pub struct SimNetwork {
    #[serde(default)]
    pub sim_network: Vec<NetworkParser>,
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
    cli.validate()?;

    let SimNetwork { sim_network } =
        serde_json::from_str(&fs::read_to_string(cli.sim_file.as_path())?)?;

    let mut tasks = JoinSet::new();
    let (shutdown, listener) = triggered::trigger();

    // Match the target alias using pubkeys provided in sim network file, then collect the pubkeys of all the
    // non-attacker target peers.
    let target_pubkey = find_pubkey_by_alias(&cli.target_alias, &sim_network)?;
    let attacker_pubkey = find_pubkey_by_alias(&cli.attacker_alias, &sim_network)?;

    let target_channels: HashMap<u64, PublicKey> = sim_network
        .iter()
        .filter_map(|channel| {
            if channel.node_1.pubkey == target_pubkey {
                Some((channel.scid.into(), channel.node_2.pubkey))
            } else if channel.node_2.pubkey == target_pubkey {
                Some((channel.scid.into(), channel.node_1.pubkey))
            } else {
                None
            }
        })
        .collect();

    let clock = Arc::new(SimulationClock::new(cli.clock_speedup)?);

    // Pull history that bootstraps the simulation in a network with the attacker's channels present, filter to only
    // have attacker forwards present when the and calculate revenue for the target node during this bootstrap period.
    let unfiltered_history = history_from_file(&cli.bootstrap_file, Some(cli.reputation_window()))?;
    let bootstrap = get_history_for_bootstrap(
        cli.attacker_bootstrap,
        unfiltered_history,
        HashSet::from_iter(target_channels.iter().filter_map(|(k, v)| {
            if *v == target_pubkey {
                Some(*k)
            } else {
                None
            }
        })),
    )?;
    let bootstrap_revenue = bootstrap.forwards.iter().fold(0, |acc, item| {
        if item.forwarding_node == target_pubkey {
            acc + item.incoming_amt - item.outgoing_amt
        } else {
            acc
        }
    });

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

    // Reputation is assessed for a channel pair and a specific HTLC that's being proposed. To assess whether pairs
    // have reputation, we'll use LND's default fee policy to get the HTLC risk for our configured htlc size and hold
    // time.
    let risk_margin = forward_params.htlc_opportunity_cost(
        1000 + (0.0001 * cli.reputation_margin_msat as f64) as u64,
        cli.reputation_margin_expiry_blocks,
    );

    // Next, setup the attack interceptor to use our custom attack.
    let attack = SinkAttack::new(
        clock.clone(),
        &sim_network,
        target_pubkey,
        cli.target_alias.clone(),
        attacker_pubkey,
        risk_margin,
        listener.clone(),
        shutdown.clone(),
    );
    let attack_setup = <SinkAttack<SimulationClock> as JammingAttack<
        ReputationInterceptor<BatchForwardWriter, ForwardManager>,
    >>::setup_for_network(&attack)?;

    // Create a writer to store results for nodes that we care about.
    let results_writer = Arc::new(Mutex::new(BatchForwardWriter::new(
        cli.results_dir.clone(),
        &attack_setup.monitored_nodes,
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
                      if let Err(e) = results_writer_1.lock().unwrap().write(){
                        log::error!("Error writing results: {e}");
                        results_shutdown.trigger();
                        return
                    }
                }
            }
        }
    });

    // Do some preliminary checks on our reputation state - there isn't much point in running if we haven't built up
    // some reputation.
    let reputation_interceptor = ReputationInterceptor::new_with_bootstrap(
        forward_params,
        &sim_network,
        &attack_setup.general_jammed_nodes,
        &bootstrap,
        clock.clone(),
        Some(results_writer),
        shutdown.clone(),
    )
    .await?;

    let start_reputation = get_network_reputation(
        &reputation_interceptor,
        target_pubkey,
        attacker_pubkey,
        &target_channels,
        risk_margin,
        now,
    )
    .await?;

    check_reputation_status(&cli, &start_reputation)?;

    let attack_interceptor = AttackInterceptor::new_for_network(
        clock.clone(),
        attacker_pubkey,
        target_pubkey,
        HashSet::from_iter(target_channels.keys().cloned()),
        reputation_interceptor,
        attack.clone(),
        shutdown.clone(),
    );

    let attack_interceptor = Arc::new(attack_interceptor);

    // Spawn a task that will trigger shutdown of the simulation if the attacker loses reputation provided that the
    // target is at similar reputation to the start of the simulation. This is a somewhat crude check, because we're
    // only looking at the count of peers with reputation not the actual pairs.
    let attack_interceptor_1 = attack_interceptor.clone();
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
                    match attack.simulation_completed(&attack_interceptor_1.reputation_interceptor, start_reputation_1.clone()).await {
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

    let revenue_interceptor = Arc::new(RevenueInterceptor::new_with_bootstrap(
        clock.clone(),
        target_pubkey,
        bootstrap_revenue,
        cli.attacker_bootstrap,
        cli.peacetime_file,
        listener.clone(),
        shutdown.clone(),
    )?);

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

    // Simulated channels for our simulated graph.
    let channels = sim_network
        .clone()
        .into_iter()
        .map(SimulatedChannel::from)
        .collect::<Vec<SimulatedChannel>>();

    // Setup the simulated network with our fake graph.
    let (simulation, graph) = Simulation::new_with_sim_network(
        SimulationCfg::new(None, 3_800_000, 2.0, None, Some(13995354354227336701)),
        channels,
        vec![], // No activities, we want random activity!
        clock.clone(),
        interceptors,
        listener,
        shutdown,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e))?;

    // Run simulation until it shuts down, then wait for the graph to exit.
    simulation.run().await?;
    graph.lock().await.wait_for_shutdown().await;

    // Write start and end state to a summary file.
    let end_reputation = get_network_reputation(
        &attack_interceptor.reputation_interceptor,
        target_pubkey,
        attacker_pubkey,
        &target_channels,
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

fn find_pubkey_by_alias(alias: &str, sim_network: &[NetworkParser]) -> Result<PublicKey, BoxError> {
    let target_channel = sim_network
        .iter()
        .find(|hist| hist.node_1.alias == alias || hist.node_2.alias == alias)
        .ok_or(format!("alias: {alias} not found in sim file"))?;

    Ok(if target_channel.node_1.alias == alias {
        target_channel.node_1.pubkey
    } else {
        target_channel.node_2.pubkey
    })
}

/// Checks whether the attacker and target meet the required portion of high reputation pairs to required.
fn check_reputation_status(cli: &Cli, status: &NetworkReputation) -> Result<(), BoxError> {
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
