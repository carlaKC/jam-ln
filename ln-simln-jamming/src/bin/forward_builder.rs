use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::net::Shutdown;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use clap::Parser;
use ln_simln_jamming::parsing::{SimNetwork, DEFAULT_SIM_FILE};
use ln_simln_jamming::BoxError;
use simln_lib::clock::SimulationClock;
use simln_lib::sim_node::{InterceptRequest, InterceptResolution, Interceptor, SimulatedChannel};
use simln_lib::{Simulation, SimulationCfg};
use triggered::Trigger;

/// The default output location for generated forwards.
pub const DEFAULT_FWD_FILE: &str = "./forwards.csv";

#[derive(Parser)]
struct Cli {
    /// A json file describing the lightning channels being simulated.
    #[arg(long, short, default_value = DEFAULT_SIM_FILE)]
    sim_file: PathBuf,

    #[arg(long, short, default_value = DEFAULT_SIM_FILE)]
    output_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    let SimNetwork { sim_network } =
        serde_json::from_str(&fs::read_to_string(cli.sim_file.as_path())?)?;

    let channels = sim_network
        .clone()
        .into_iter()
        .map(SimulatedChannel::from)
        .collect::<Vec<SimulatedChannel>>();

    // When generating data, we always want to go as fast as possible, so set maximum clock speedup.
    let clock = Arc::new(SimulationClock::new(1000)?);
    let (shutdown, listener) = triggered::trigger();
    let (simulation, graph) = Simulation::new_with_sim_network(
        SimulationCfg::new(None, 3_800_000, 2.0, None, Some(13995354354227336701)),
        channels,
        vec![], // No activities, we want random activity!
        clock.clone(),
        HashMap::new(),
        vec![Arc::new(ForwardWriter::new(shutdown.clone()))],
        (shutdown, listener),
    )
    .await?;

    simulation.run().await?;
    graph.lock().await.wait_for_shutdown().await;

    Ok(())
}

struct ForwardWriter {
    shutdown: Trigger,
}

impl ForwardWriter {
    fn new(shutdown: Trigger) -> Self {
        ForwardWriter { shutdown }
    }
}

#[async_trait]
impl Interceptor for ForwardWriter {
    async fn intercept_htlc(&self, req: InterceptRequest) {
        if let Err(e) = req.response.send(Ok(Ok(HashMap::new()))).await {
            log::error!("Failure to send interceptor response: {e}");
            self.shutdown.trigger();
        }
    }

    async fn notify_resolution(
        &self,
        res: InterceptResolution,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
		println!("Res: {:?}", res.success);
        Ok(())
    }

    fn name(&self) -> String {
        "forward writer".to_string()
    }
}
