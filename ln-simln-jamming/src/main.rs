use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_simln_jamming::analysis::BatchForwardWriter;
use ln_simln_jamming::attack_interceptor::AttackInterceptor;
use ln_simln_jamming::attacks::AttackStatisitcs;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{
    find_pubkey_by_alias, reputation_snapshot_from_file, setup_attack, AttackType, Cli, NetworkType,
};
use ln_simln_jamming::reputation_interceptor::ReputationInterceptor;
use ln_simln_jamming::revenue_interceptor::{
    PeacetimeRevenueMonitor, RevenueComparator, RevenueSnapshot, RevenueTracker,
};
use ln_simln_jamming::{
    get_network_reputation, BoxError, NetworkReputation, ACCOUNTABLE_TYPE, SIM_SEED,
    UPGRADABLE_TYPE,
};
use log::LevelFilter;
use sim_cli::parsing::{create_simulation_with_network, SimParams};
use simln_lib::clock::Clock;
use simln_lib::clock::SimulationClock;
use simln_lib::latency_interceptor::LatencyIntercepor;
use simln_lib::runtime::block_on_virtual_time;
use simln_lib::sim_node::{CustomRecords, Interceptor, SimGraph, SimNode};
use simln_lib::SimulationCfg;
use simple_logger::SimpleLogger;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::select;
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

/// Maximum time to run the simulation for in virutal time, used to safeguard against the clock spinning forever if an
/// attack fails to shut itself down.
const MAX_SIM_TIME_SECS: u32 = 365 * 24 * 60 * 60;

/// The granularity in seconds with which we round our start time to be the same across runs on the same day.
const START_TIME_QUANTUM_SECS: u64 = 24 * 60 * 60;

/// Mean latency (ms) applied to htlc resolution, shared by the attack and peacetime networks so their timing matches.
const LATENCY_MS: f32 = 150.0;

/// Parameters for random activity generation, shared by both networks: expected payment size and activity multiplier.
const EXPECTED_PAYMENT_MSAT: u64 = 3_800_000;
const ACTIVITY_MULTIPLIER: f64 = 2.0;

/// The peacetime revenue must exceed this (msat) before the revenue-drop monitor starts checking, so early
/// small-number noise doesn't trigger a shutdown.
const REVENUE_MONITOR_WARMUP_MSAT: u64 = 10_000_000;

/// The monitor stops the attack once the target's revenue has dropped this fraction below peacetime. A margin keeps
/// the near-tie between an inert attacker and peacetime (which differ only by routing noise) from tripping it.
const REVENUE_DROP_FRACTION: u64 = 20; // 1/20 = 5%.

fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    let forward_params = cli.validate()?;

    SimpleLogger::new()
        .with_level(cli.log_level)
        // Lower logging from sim-ln so that we can focus on our own logs.
        .with_module_level("simln_lib", LevelFilter::Info)
        .with_module_level("sim_cli", LevelFilter::Off)
        // Debug so that we can read interceptor-related logging.
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    // We can't fix start time exactly, because LDK's graph requires a recent timestamp to validate gossip. Round to
    // the nearest day so that our clock is at least fixed for runs on the same day.
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock is before UNIX_EPOCH")
        .as_secs();
    let start_time =
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs - secs % START_TIME_QUANTUM_SECS);

    block_on_virtual_time(start_time, |clock| run(clock, cli, forward_params))??;

    Ok(())
}

async fn run(
    clock: Arc<SimulationClock>,
    cli: Cli,
    forward_params: ForwardManagerParams,
) -> Result<(), BoxError> {
    let network = NetworkType::new(
        &cli.network,
        Some(cli.attack_type.clone()),
        cli.attacker_bootstrap,
    )?;
    let (target_alias, target_pubkey) = network.target();
    let attackers = network.attackers();
    let attacker_pubkeys: Vec<PublicKey> = attackers.iter().map(|a| a.1).collect();
    let attack_graph = network.active_network();

    if matches!(network, NetworkType::Peacetime(_)) {
        return Err("must run simulation with attack set".into());
    }

    // Master shutdown for the whole run. When it fires we stop both co-simulated networks.
    let (shutdown, listener) = triggered::trigger();

    let target_channels: HashMap<u64, (PublicKey, String)> = attack_graph
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

    let now = InstantClock::now(&*clock);

    // Create a writer to store results for nodes that we care about. We use real wall clock time here so that results
    // don't overwrite each other.
    let results_dir = network
        .results_dir(SystemTime::now())
        .ok_or("results dir none for attack")?;
    if !results_dir.exists() {
        fs::create_dir_all(&results_dir)?;
    }

    let mut monitor_channels: Vec<(PublicKey, String)> =
        target_channels.values().cloned().collect();
    monitor_channels.push((target_pubkey, target_alias));
    let results_writer = Arc::new(Mutex::new(BatchForwardWriter::new(
        results_dir.clone(),
        &monitor_channels,
        cli.result_batch_size,
        now,
    )));

    // The attack and peacetime networks each run on their own TaskTracker so their `run()` calls can close and wait
    // independently, but they share the one virtual clock.
    let attack_tasks = TaskTracker::new();
    let peace_tasks = TaskTracker::new();

    let results_writer_1 = results_writer.clone();
    let results_listener = listener.clone();
    let results_shutdown = shutdown.clone();
    let results_clock = clock.clone();
    attack_tasks.spawn(async move {
        let interval = Duration::from_secs(60);
        loop {
            select! {
                _ = results_listener.clone() => {
                    if let Err(e) = results_writer_1.lock().await.write(true) {
                        log::error!("Error writing results on shutdown: {e}");
                    }
                    return
                },
                _ = results_clock.sleep(interval) => {
                      if let Err(e) = results_writer_1.lock().await.write(false) {
                        log::error!("Error writing results: {e}");
                        results_shutdown.trigger();
                        return
                    }
                }
            }
        }
    });

    // ---------- Attack network reputation ----------
    let reputation_file = network.reputation_file();
    let reputation_snapshot = reputation_snapshot_from_file(&reputation_file).map_err(|e| {
        format!(
            "could not find reputation snapshot {:?}, try generating one with bootstrap-builder: {:?}",
            reputation_file.to_string_lossy(), e
        )
    })?;

    let attack_reputation = Arc::new(
        ReputationInterceptor::new_from_snapshot(
            forward_params,
            attack_graph,
            reputation_snapshot,
            // If bootstrapping the attacker's reputation, we expect them to be in our snapshot of starting reputation
            // values. Otherwise, they can be omitted.
            if cli.attacker_bootstrap.is_some() {
                HashSet::new()
            } else {
                HashSet::from_iter(attacker_pubkeys.clone())
            },
            clock.clone(),
            Some(results_writer),
        )
        .await?,
    );

    // ---------- Peacetime network reputation ----------
    // The peacetime network has no attacker channels and always uses the top-level peacetime reputation snapshot.
    let peace_graph = network.peacetime_graph().clone();
    let peace_reputation_file = network.peacetime_reputation_file();
    let peace_snapshot = reputation_snapshot_from_file(&peace_reputation_file).map_err(|e| {
        format!(
            "could not find peacetime reputation snapshot {:?}: {:?}",
            peace_reputation_file.to_string_lossy(),
            e
        )
    })?;
    let peace_reputation = Arc::new(
        ReputationInterceptor::new_from_snapshot(
            forward_params,
            &peace_graph,
            peace_snapshot,
            HashSet::new(),
            clock.clone(),
            None::<Arc<Mutex<BatchForwardWriter>>>,
        )
        .await?,
    );

    // Reputation is assessed for a channel pair and a specific HTLC that's being proposed. To assess whether pairs
    // have reputation, we'll use LND's default fee policy to get the HTLC risk for our configured htlc size and hold
    // time.
    let risk_margin = forward_params.htlc_opportunity_cost(
        1000 + (0.0001 * cli.reputation_margin_msat as f64) as u64,
        cli.reputation_margin_expiry_blocks,
    );

    // The peacetime network's revenue tracker is created up-front so the comparator (used by the attack setup) can
    // reference it; the tracker is wired into the peacetime simulation below.
    let peace_revenue = Arc::new(RevenueTracker::new(target_pubkey));
    let attack_revenue = Arc::new(RevenueTracker::new(target_pubkey));

    // The comparator reads the target's live revenue in both networks at the same virtual instant.
    let comparator = Arc::new(RevenueComparator::new(
        clock.clone(),
        Arc::clone(&attack_revenue),
        Arc::clone(&peace_revenue),
    ));

    // Next, setup the attack interceptor to use our custom attack.
    let attack = setup_attack(
        &cli,
        &network,
        Arc::clone(&clock),
        Arc::clone(&attack_reputation),
        Arc::clone(&comparator),
        Arc::clone(&attack_reputation),
    )?;

    attack.validate()?;

    // Do some preliminary checks on our reputation state - there isn't much point in running if we haven't built up
    // some reputation.
    let target_pubkey_map: HashMap<u64, PublicKey> =
        target_channels.iter().map(|(k, v)| (*k, v.0)).collect();

    let start_reputation = get_network_reputation(
        attack_reputation.clone(),
        target_pubkey,
        &attacker_pubkeys,
        &target_pubkey_map,
        risk_margin,
        InstantClock::now(&*clock),
    )
    .await?;

    check_reputation_status(&cli, &start_reputation)?;

    let attack_interceptor = Arc::new(AttackInterceptor::new(
        attacker_pubkeys.clone(),
        attack_reputation.clone(),
        attack.clone(),
    ));

    let custom_records =
        CustomRecords::from([(UPGRADABLE_TYPE, vec![1]), (ACCOUNTABLE_TYPE, vec![0])]);

    // ---------- Build the two co-simulated networks on the shared clock ----------
    let mut attack_exclude = attacker_pubkeys.clone();
    attack_exclude.push(target_pubkey);

    let (attack_simulation, attack_activities, _attack_revenue_from_build, sim_nodes) =
        build_network_simulation_with_revenue(
            clock.clone(),
            attack_tasks.clone(),
            attack_graph.to_vec(),
            attack_exclude,
            // On the attack network the AttackInterceptor wraps reputation/bucketing, so it is the only middle
            // interceptor.
            vec![Arc::clone(&attack_interceptor) as Arc<dyn Interceptor>],
            Arc::clone(&attack_revenue),
            custom_records.clone(),
        )
        .await?;

    let (peace_simulation, peace_activities, _peace_rev, _peace_nodes) =
        build_network_simulation_with_revenue(
            clock.clone(),
            peace_tasks.clone(),
            peace_graph.clone(),
            vec![target_pubkey],
            // The peacetime network has no attacker, so the reputation interceptor is the only middle interceptor.
            vec![Arc::clone(&peace_reputation) as Arc<dyn Interceptor>],
            Arc::clone(&peace_revenue),
            custom_records.clone(),
        )
        .await?;

    let attack_simulation = Arc::new(attack_simulation);
    let peace_simulation = Arc::new(peace_simulation);

    // Collect all attacker nodes from the attack network.
    let attacker_pubkeys_map: HashMap<PublicKey, String> = network
        .attackers()
        .iter()
        .map(|(alias, pk)| (*pk, alias.clone()))
        .collect();

    // Ugly hack specific to SlowJam attack to include this node in the list of nodes passed to run_attack. This node
    // is used as an "honest" node to send a test payment through our target channel to check that it is jammed.
    let honest_sender_pubkey = if cli.attack_type == AttackType::SlowJam {
        Some(find_pubkey_by_alias("69", attack_graph)?)
    } else {
        None
    };

    let attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>> = sim_nodes
        .into_iter()
        .filter_map(|(pk, node)| {
            if let Some(honest_pk) = honest_sender_pubkey {
                if honest_pk == pk {
                    return Some(("69".to_string(), node));
                }
            }

            attacker_pubkeys_map
                .get(&pk)
                .map(|alias| (alias.clone(), node))
        })
        .collect();

    // Coordinator: when the master shutdown fires, stop both networks.
    {
        let coord_listener = listener.clone();
        let coord_peace = Arc::clone(&peace_simulation);
        let coord_attack = Arc::clone(&attack_simulation);
        tokio::spawn(async move {
            coord_listener.await;
            coord_peace.shutdown();
            coord_attack.shutdown();
        });
    }

    // Revenue-drop monitor: stop the attack once the target's revenue in the attack network has dropped materially
    // below peacetime. Because both networks advance on the same virtual clock, both revenues are read at the same
    // virtual instant.
    {
        let monitor_comparator = Arc::clone(&comparator);
        let monitor_shutdown = shutdown.clone();
        let monitor_listener = listener.clone();
        let monitor_clock = clock.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(60 * 60 * 6);
            loop {
                select! {
                    _ = monitor_listener.clone() => return,
                    _ = monitor_clock.sleep(interval) => {},
                }

                let snapshot = monitor_comparator.get_revenue_difference().await;
                if snapshot.peacetime_revenue_msat < REVENUE_MONITOR_WARMUP_MSAT {
                    continue;
                }

                let drop_margin = snapshot.peacetime_revenue_msat / REVENUE_DROP_FRACTION;
                if snapshot.simulation_revenue_msat + drop_margin < snapshot.peacetime_revenue_msat
                {
                    log::info!(
                        "Revenue-drop monitor: target revenue under attack ({}) fell below peacetime ({}); stopping.",
                        snapshot.simulation_revenue_msat,
                        snapshot.peacetime_revenue_msat,
                    );
                    monitor_shutdown.trigger();
                    return;
                }
            }
        });
    }

    // Drive the attack. When run_attack returns, the attack is done and we shut the whole run down.
    let attack_shutdown_listener = listener.clone();
    let attack_shutdown_trigger = shutdown.clone();
    let attack_start_reputation = start_reputation.clone();
    let attack_clone = Arc::clone(&attack);
    tokio::spawn(async move {
        if let Err(e) = attack_clone
            .run_attack(
                attack_start_reputation,
                attacker_nodes,
                attack_shutdown_listener,
            )
            .await
        {
            log::error!("Error running custom attacker actions: {e}");
        }
        attack_shutdown_trigger.trigger();
    });

    let ctrlc_shutdown = shutdown.clone();
    ctrlc::set_handler(move || {
        ctrlc_shutdown.trigger();
    })?;

    // Run the peacetime network alongside the attack network on the shared clock.
    let peace_run = {
        let peace_sim = Arc::clone(&peace_simulation);
        tokio::spawn(async move { peace_sim.run(&peace_activities).await })
    };

    // Run the attack network. This blocks until the master shutdown fires (via the coordinator) or the attack sim
    // reaches its own time bound.
    attack_simulation.run(&attack_activities).await?;

    // Ensure the master shutdown is triggered so the peacetime network stops at the same virtual time.
    shutdown.trigger();
    if let Err(e) = peace_run.await {
        log::error!("Error awaiting peacetime simulation: {e}");
    }

    // Write start and end state to a summary file.
    let end_reputation = get_network_reputation(
        attack_reputation,
        network.target().1,
        &attacker_pubkeys,
        &target_pubkey_map,
        risk_margin,
        InstantClock::now(&*clock),
    )
    .await?;

    let snapshot = comparator.get_revenue_difference().await;

    log::info!("Writing results to directory {:?}", results_dir);
    write_simulation_summary(
        &cli,
        results_dir,
        &snapshot,
        &start_reputation,
        &end_reputation,
        attack.attack_statistics()?,
    )?;

    Ok(())
}

/// Builds a simulation for a single network on the shared clock. Interceptor order is: latency, the provided
/// `middle_interceptors` (the attack interceptor on the attack network - which itself wraps reputation - or the bare
/// reputation interceptor on the peacetime network), then the revenue tracker (which only observes, so it runs last).
#[allow(clippy::too_many_arguments)]
async fn build_network_simulation_with_revenue(
    clock: Arc<SimulationClock>,
    tasks: TaskTracker,
    graph: Vec<sim_cli::parsing::NetworkParser>,
    exclude: Vec<PublicKey>,
    middle_interceptors: Vec<Arc<dyn Interceptor>>,
    revenue: Arc<RevenueTracker>,
    custom_records: CustomRecords,
) -> Result<
    (
        simln_lib::Simulation<SimulationClock>,
        Vec<simln_lib::ActivityDefinition>,
        Arc<RevenueTracker>,
        HashMap<PublicKey, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
    ),
    BoxError,
> {
    let latency: Arc<dyn Interceptor> =
        Arc::new(LatencyIntercepor::new_poisson(LATENCY_MS, Some(SIM_SEED))?);

    let mut interceptors: Vec<Arc<dyn Interceptor>> = vec![latency];
    interceptors.extend(middle_interceptors);
    interceptors.push(Arc::clone(&revenue) as Arc<dyn Interceptor>);

    let sim_params = SimParams {
        nodes: vec![],
        sim_network: graph,
        activity: vec![],
        exclude,
    };

    let sim_cfg = SimulationCfg::new(
        Some(MAX_SIM_TIME_SECS),
        EXPECTED_PAYMENT_MSAT,
        ACTIVITY_MULTIPLIER,
        None,
        Some(SIM_SEED),
    );

    let (simulation, activities, sim_nodes) = create_simulation_with_network(
        sim_cfg,
        &sim_params,
        clock,
        tasks,
        interceptors,
        custom_records,
    )
    .await?;

    Ok((simulation, activities, revenue, sim_nodes))
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

    if let Some(attacker_percentage) = cli.attacker_reputation_percent {
        let attacker_threshold = status.attacker_pair_count * attacker_percentage as usize / 100;
        if status.attacker_reputation < attacker_threshold {
            return Err(format!(
                "attacker has {}/{} good reputation pairs which does not meet threshold {}",
                status.attacker_reputation, status.attacker_pair_count, attacker_threshold,
            )
            .into());
        }
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
    cli: &Cli,
    data_dir: PathBuf,
    revenue: &RevenueSnapshot,
    start_reputation: &NetworkReputation,
    end_reputation: &NetworkReputation,
    attack_stats: AttackStatisitcs,
) -> Result<(), BoxError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(data_dir.join("summary.txt"))?;

    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "{:?} ran for (seconds): {:?}",
        cli.attack_type,
        revenue.runtime.as_secs()
    )?;
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
        "Attacker bootstrapped reputation for: {} seconds",
        cli.attacker_bootstrap.unwrap_or(Duration::ZERO).as_secs(),
    )?;
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
        end_reputation.target_reputation, end_reputation.target_pair_count,
    )?;
    writeln!(
        writer,
        "Attacker general jammed {} edges (directional)",
        attack_stats.general_jammed_channels,
    )?;
    writeln!(
        writer,
        "Attacker congestion jammed {} edges (directional)",
        attack_stats.congestion_jammed_channels,
    )?;
    writer.flush()?;

    Ok(())
}
