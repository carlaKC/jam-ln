use std::sync::Arc;
use std::time::{Duration, Instant};

use ln_simln_jamming::sink_attack_interceptor::SinkInterceptor;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use simln_lib::interceptors::LatencyIntercepor;
use simln_lib::sim_node::{Interceptor, SimulatedChannel};
use simln_lib::{NetworkParser, Simulation, SimulationCfg};
use simple_logger::SimpleLogger;

#[derive(Serialize, Deserialize)]
pub struct SimNetwork {
    #[serde(default)]
    pub sim_network: Vec<NetworkParser>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        // Lower logging from sim-ln so that we can focus on our own logs.
        .with_module_level("simln_lib", LevelFilter::Info)
        .with_module_level("sim_cli", LevelFilter::Off)
        // Debug so that we can read interceptor-related logging.
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    let SimNetwork { sim_network } =
        serde_json::from_str(&std::fs::read_to_string("./simln.json")?)?;

    // Use the channel jamming interceptor and latency for simulated payments.
    let latency_interceptor: Box<dyn Interceptor> =
        Box::new(LatencyIntercepor::new_poisson(150.0)?);

    // TODO: these should be shared with simln!!
    let (shutdown, listener) = triggered::trigger();
    let sink_interceptor = SinkInterceptor::new_for_network(
        Instant::now(),
        Duration::from_secs(60),
        "51".to_string(),
        "22".to_string(),
        sim_network.clone(),
        listener,
        shutdown,
    );

    tokio::spawn(sink_interceptor.poll_reputation_stats(Duration::from_secs(30)));

    let attack_interceptor: Box<dyn Interceptor> = Box::new(sink_interceptor);

    let interceptors = Arc::new(vec![latency_interceptor, attack_interceptor]);

    // Simulated channels for our simulated graph.
    let channels = sim_network
        .clone()
        .into_iter()
        .map(SimulatedChannel::from)
        .collect::<Vec<SimulatedChannel>>();

    // Setup the simulated network with our fake graph.
    let (simulation, graph) = Simulation::new_with_sim_network(
        SimulationCfg::new(None, 3_800_000, 2.0, None, None),
        channels,
        vec![], // No activities, we want random activity!
        1,      // No clock speedup, just run with regular timing for now.
        interceptors,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e))?;

    // Run simulation until it shuts down, then wait for the graph to exit.
    simulation.run().await?;
    graph.lock().await.wait_for_shutdown().await;

    Ok(())
}
