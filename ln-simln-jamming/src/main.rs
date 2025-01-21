use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::outgoing_reputation::{ForwardManagerParams, ReputationParams};
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{history_from_file, Cli};
use ln_simln_jamming::reputation_interceptor::{ReputationInterceptor, ReputationMonitor};
use ln_simln_jamming::revenue_interceptor::RevenueInterceptor;
use ln_simln_jamming::sink_interceptor::{SinkInterceptor, TargetChannelType};
use ln_simln_jamming::BoxError;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use simln_lib::clock::Clock;
use simln_lib::clock::SimulationClock;
use simln_lib::interceptors::LatencyIntercepor;
use simln_lib::sim_node::{Interceptor, SimulatedChannel};
use simln_lib::{NetworkParser, Simulation, SimulationCfg};
use simple_logger::SimpleLogger;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fs, usize};
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

    // Match the target alias using pubkeys provided in sim network file.
    let target_alias = "22".to_string(); // TODO: cli argument
    let target_channel = sim_network
        .iter()
        .find(|hist| hist.node_1.alias == target_alias || hist.node_2.alias == target_alias)
        .ok_or(format!(
            "attacker alias: {target_alias} not found in sim file"
        ))?;

    let target_pubkey = if target_channel.node_1.alias == target_alias {
        target_channel.node_1.pubkey
    } else {
        target_channel.node_2.pubkey
    };

    // Pull history that bootstraps the simulation in a network with the attacker's channels present and calculate
    // revenue for the target node during this bootstrap period.
    let history = history_from_file(&cli.bootstrap_file, Some(cli.bootstrap_duration))?;

    let bootstrap_revenue = history.iter().fold(0, |acc, item| {
        if item.forwarding_node == target_pubkey {
            acc + item.incoming_amt - item.outgoing_amt
        } else {
            acc
        }
    });

    // TODO: args!
    let target_pubkey = find_pubkey_by_alias("22", &sim_network)?;
    let attacker_pubkey = find_pubkey_by_alias("50", &sim_network)?;

    // Use the channel jamming interceptor and latency for simulated payments.
    let latency_interceptor: Arc<dyn Interceptor> =
        Arc::new(LatencyIntercepor::new_poisson(150.0)?);

    let clock = Arc::new(SimulationClock::new(cli.clock_speedup)?);
    let forward_params = ForwardManagerParams {
        reputation_params: ReputationParams {
            revenue_window: Duration::from_secs(14 * 24 * 60 * 60),
            reputation_multiplier: 12,
            resolution_period: Duration::from_secs(90),
            expected_block_speed: Some(Duration::from_secs(10 * 60)),
        },
        general_slot_portion: 50,
        general_liquidity_portion: 50,
    };

    let (shutdown, listener) = triggered::trigger();
    let attack_interceptor = SinkInterceptor::new_for_network(
        clock.clone(),
        attacker_pubkey,
        target_pubkey,
        &sim_network,
        ReputationInterceptor::new_with_bootstrap(
            forward_params,
            &sim_network,
            &history,
            clock.clone(),
            shutdown.clone(),
        )
        .await?,
        listener.clone(),
        shutdown.clone(),
    );

    // Do some preliminary checks on our reputation state - there isn't much point in running if we haven't built up
    // some reputation.
    check_reputation_status(
        &attack_interceptor,
        &cli,
        forward_params,
        InstantClock::now(&*clock),
        true,
    )
    .await?;

    let attack_interceptor = Arc::new(attack_interceptor);

    // Spawn a task that will trigger shutdown of the simulation if the attacker loses reputation.
    let mut tasks = JoinSet::new();
    let attack_interceptor_1 = attack_interceptor.clone();
    let attack_clock = clock.clone();
    let attack_listener = listener.clone();
    let attack_shutdown = shutdown.clone();
    let reputation_threshold = forward_params.htlc_opportunity_cost(
        get_reputation_margin_fee(&cli),
        cli.reputation_margin_expiry_blocks,
    );

    tasks.spawn(async move {
    let interval = Duration::from_secs(cli.attacker_poll_interval_seconds);
    loop {
        select! {
            _ = attack_listener.clone() => return,
            _ = attack_clock.sleep(interval) => {
                match attack_interceptor_1
                    .get_target_pairs(
                        target_pubkey,
                        TargetChannelType::Attacker,
                        InstantClock::now(&*attack_clock),
                    )
                .await {
                    Ok(rep) => {
                        if !rep.iter().any(|pair| pair.outgoing_reputation(reputation_threshold)) {
                            log::error!("Attacker has no more reputation with the target");
                            attack_shutdown.trigger();
                            return;
                        }
                    },
                    Err(e) => {
                        log::error!("Error checking attacker reputation: {e}");
                        attack_shutdown.trigger();
                        return;
                    },
                }
            }
        }
    }});

    let revenue_interceptor = Arc::new(RevenueInterceptor::new_with_bootstrap(
        clock.clone(),
        target_pubkey,
        bootstrap_revenue,
        cli.bootstrap_duration,
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

    let interceptors = vec![latency_interceptor, attack_interceptor, revenue_interceptor];

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
        clock,
        interceptors,
        listener,
        shutdown,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e))?;

    // Run simulation until it shuts down, then wait for the graph to exit.
    simulation.run().await?;
    graph.lock().await.wait_for_shutdown().await;

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

fn get_reputation_margin_fee(cli: &Cli) -> u64 {
    1000 + (0.0001 * cli.reputation_margin_msat as f64) as u64
}
/// Gets reputation pairs for the target node and attacking node, logs them and optionally checking that each node
/// meets the configured threshold of good reputation if require_reputation is set.
async fn check_reputation_status<C, R>(
    attack_interceptor: &SinkInterceptor<C, R>,
    cli: &Cli,
    params: ForwardManagerParams,
    instant: Instant,
    require_reputation: bool,
) -> Result<(), BoxError>
where
    C: InstantClock + Clock,
    R: Interceptor + ReputationMonitor,
{
    let status = attack_interceptor.get_reputation_status(instant).await?;

    let margin_fee = get_reputation_margin_fee(cli);

    let attacker_reputation = status.reputation_count(
        false,
        &params,
        margin_fee,
        cli.reputation_margin_expiry_blocks,
    );

    let target_reputation = status.reputation_count(
        true,
        &params,
        margin_fee,
        cli.reputation_margin_expiry_blocks,
    );

    log::info!(
        "Attacker has {} out of {} pairs with reputation",
        attacker_reputation,
        status.attacker_reputation.len()
    );

    log::info!(
        "Target has {}/{} pairs with reputation with its peers",
        target_reputation,
        status.target_reputation.len()
    );

    if !require_reputation {
        return Ok(());
    }

    let attacker_threshold =
        status.attacker_reputation.len() * cli.attacker_reputation_percent as usize / 100;
    if attacker_reputation < attacker_threshold {
        return Err(format!(
            "attacker has {}/{} good reputation pairs which does not meet threshold {}",
            attacker_reputation,
            status.attacker_reputation.len(),
            attacker_threshold,
        )
        .into());
    }

    let target_threshold =
        status.target_reputation.len() * cli.target_reputation_percent as usize / 100;
    if target_reputation < target_threshold {
        return Err(format!(
            "target has {}/{} good reputation pairs which does not meet threshold {}",
            target_reputation,
            status.target_reputation.len(),
            target_threshold,
        )
        .into());
    }

    Ok(())
}
