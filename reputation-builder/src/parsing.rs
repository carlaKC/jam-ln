use clap::Parser;
use humantime::Duration as HumanDuration;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Default file used to describe the network being simulated.
const DEFAULT_SIM_FILE: &str = "./simln.json";

/// Default file used to bootstrap reputation.
const DEFAULT_BOOTSTRAP_FILE: &str = "./bootstrap.csv";

/// Default clock speedup to run with regular wall time.
const DEFAULT_CLOCK_SPEEDUP: &str = "1";

/// The default window that we consider revenue over (2 weeks = 60 * 60 * 24 * 7).
const DEFAULT_REVENUE_WINDOW_SECONDS: &str = "1210000";

/// The default multiplier applied to the revenue window to get reputation window.
const DEFAULT_REPUTATION_MULTIPLIER: &str = "12";

/// The default location to output resulting reputation snapshot.
const DEFAULT_RESULTS_DIR: &str = "./reputation-snapshots";

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    /// A json file describing the lightning channels being simulated.
    #[arg(long, short, default_value = DEFAULT_SIM_FILE)]
    pub sim_file: PathBuf,

    /// A CSV file containing forwards for the network, including the attacker used to bootstrap reputation for the
    /// simulation.
    #[arg(long, default_value = DEFAULT_BOOTSTRAP_FILE)]
    pub bootstrap_file: PathBuf,

    /// The duration of time that reputation of the attacking node should be bootstrapped for, expressed as human
    /// readable values (eg: 1w, 3d).
    #[arg(long, value_parser = parse_duration)]
    pub attacker_bootstrap: Option<(String, Duration)>,

    /// Speed up multiplier to add to the wall clock to run the simulation faster.
    #[arg(long, default_value = DEFAULT_CLOCK_SPEEDUP)]
    pub clock_speedup: u32,

    /// The window over which the value of a link's revenue to our node is calculated.
    #[arg(long, default_value = DEFAULT_REVENUE_WINDOW_SECONDS)]
    pub revenue_window_seconds: u64,

    /// The multiplier applied to revenue_window_seconds to get the duration over which reputation is bootstrapped.
    #[arg(long, default_value = DEFAULT_REPUTATION_MULTIPLIER)]
    pub reputation_multiplier: u8,

    /// The directory to write reputation snapshot file.
    #[arg(long, default_value = DEFAULT_RESULTS_DIR)]
    pub results_dir: PathBuf,

    /// The alias of the target node.
    #[arg(long)]
    pub target_alias: Option<String>,

    /// The alias of the attacking node.
    #[arg(long)]
    pub attacker_alias: Option<String>,
}

impl Cli {
    pub fn reputation_window(&self) -> Duration {
        Duration::from_secs(self.revenue_window_seconds * self.reputation_multiplier as u64)
    }
}

fn parse_duration(s: &str) -> Result<(String, Duration), String> {
    HumanDuration::from_str(s)
        .map(|hd| (s.to_string(), hd.into()))
        .map_err(|e| format!("Invalid duration '{}': {}", s, e))
}
