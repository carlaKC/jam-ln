use crate::reputation_interceptor::BootstrapForward;
use crate::revenue_interceptor::RevenueEvent;
use crate::BoxError;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use csv::StringRecord;
use humantime::Duration as HumanDuration;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::BufReader;
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Default file used to describe the network being simulated.
const DEFAULT_SIM_FILE: &str = "./simln.json";

/// Default file used to bootstrap reputation.
const DEFAULT_BOOTSTRAP_FILE: &str = "./bootstrap.csv";

/// Default file used to imitate peacetime revenue
const DEFAULT_PEACETIME_FILE: &str = "./no_attacker.csv";

/// Default percent of good reputation pairs the target requires.
const DEFAULT_TARGET_REP_PERCENT: &str = "50";

/// Default percent of good reputation pairs with the target that the attacker requires.
const DEFAULT_ATTACKER_REP_PERCENT: &str = "50";

/// Default clock speedup to run with regular wall time.
const DEFAULT_CLOCK_SPEEDUP: &str = "1";

/// Default htlc size that a peer must be able to get endorsed to be considered as having good reputation, $10 at the
/// time of writing.
const DEFAULT_REPUTATION_MARGIN_MSAT: &str = "10000000";

/// Default htlc expiry used for calculating reputation margin htlc's risk.
const DEFAULT_REPUTATION_MARGIN_EXIPRY: &str = "200";

/// The default interval used to poll whether the attacker still has reputation with the target, 5 minutes expresssed
/// in seconds.
const DEFAULT_ATTACKER_POLL_SECONDS: &str = "300";

/// The default batch size for writing results to disk.
const DEFAULT_RESULT_BATCH_SIZE: &str = "500";

/// The default window that we consider revenue over (2 weeks = 60 * 60 * 24 * 7).
const DEFAULT_REVENUE_WINDOW_SECONDS: &str = "1210000";

/// The default multiplier applied to the revenue window to get reputation window.
const DEFAULT_REPUTATION_MULTIPLIER: &str = "12";

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

    /// A CSV file containing forwards for the network, excluding the attacker used to represent peacetime revenue
    /// for the target node.
    #[arg(long, default_value = DEFAULT_PEACETIME_FILE)]
    pub peacetime_file: PathBuf,

    /// The duration of time that reputation of the attacking node should be bootstrapped for, expressed as human
    /// readable values (eg: 1w, 3d).
    #[arg(long, value_parser = parse_duration)]
    pub attacker_bootstrap: Duration,

    /// The minimum percentage of channel pairs between the target and its honest peers that the target needs to have
    /// good reputation on for the simulation to run.
    #[arg(long, default_value = DEFAULT_TARGET_REP_PERCENT)]
    pub target_reputation_percent: u8,

    /// The minimum percentage of pairs with between the target and the attacker that the attacker needs to have good
    /// reputation on for the simulation to run.
    #[arg(long, default_value = DEFAULT_ATTACKER_REP_PERCENT)]
    pub attacker_reputation_percent: u8,

    /// Speed up multiplier to add to the wall clock to run the simulation faster.
    #[arg(long, default_value = DEFAULT_CLOCK_SPEEDUP)]
    pub clock_speedup: u32,

    /// The htlc amount that a peer must be able to get endorsed to be considered as having a good reputation, expressed
    /// in msat. This will be converted to a fee using a base fee of 1000 msat and a proportional charge of 0.01% of the
    /// amount.
    #[arg(long, default_value = DEFAULT_REPUTATION_MARGIN_MSAT)]
    pub reputation_margin_msat: u64,

    /// The htlc expiry that is used to assess whether a peer has sufficient reputation to forward a htlc, expressed
    /// in blocks.
    #[arg(long, default_value = DEFAULT_REPUTATION_MARGIN_EXIPRY)]
    pub reputation_margin_expiry_blocks: u32,

    /// The interval to poll whether the attacker still has reputation with the target node, expressed in seconds.
    #[arg(long, default_value = DEFAULT_ATTACKER_POLL_SECONDS)]
    pub attacker_poll_interval_seconds: u64,

    /// The size of results batches to write to disk.
    #[arg(long, default_value = DEFAULT_RESULT_BATCH_SIZE)]
    pub result_batch_size: u16,

    /// The window over which the value of a link's revenue to our node is calculated.
    #[arg(long, default_value = DEFAULT_REVENUE_WINDOW_SECONDS)]
    pub revenue_window_seconds: u64,

    /// The multiplier applied to revenue_window_seconds to get the duration over which reputation is bootstrapped.
    #[arg(long, default_value = DEFAULT_REPUTATION_MULTIPLIER)]
    pub reputation_multiplier: u8,
}

impl Cli {
    pub fn validate(&self) -> Result<(), BoxError> {
        if self.target_reputation_percent == 0 || self.target_reputation_percent > 100 {
            return Err(format!(
                "target reputation percent {} must be in (0;100]",
                self.target_reputation_percent
            )
            .into());
        }

        if self.attacker_reputation_percent == 0 || self.attacker_reputation_percent > 100 {
            return Err(format!(
                "attacker reputation percent {} must be in (0;100]",
                self.attacker_reputation_percent
            )
            .into());
        }

        if self.reputation_window() < self.attacker_bootstrap {
            return Err(format!(
                "attacker_bootstrap {:?} < reputation window {:?} ({} * {})))",
                self.attacker_bootstrap,
                self.reputation_window(),
                self.revenue_window_seconds,
                self.reputation_multiplier,
            )
            .into());
        }

        Ok(())
    }

    pub fn reputation_window(&self) -> Duration {
        Duration::from_secs(self.revenue_window_seconds * self.reputation_multiplier as u64)
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    HumanDuration::from_str(s)
        .map(|hd| hd.into())
        .map_err(|e| format!("Invalid duration '{}': {}", s, e))
}

/// Reads forwards from a CSV (generated by simln), optionally filtering to only get a set duration of forwards from
/// the file.
pub fn history_from_file(
    file_path: &PathBuf,
    filter_duration: Option<Duration>,
) -> Result<Vec<BootstrapForward>, BoxError> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);

    let mut forwards = Vec::new();
    let mut start_ts = None;

    for result in csv_reader.records() {
        let record: StringRecord = result?;

        // We can skip 6/7 because they're outgoing timestamps, we only care about when the htlc is fully removed
        // from the incoming link (for simplicity's sake).
        let incoming_amt: u64 = record[0].parse()?;
        let incoming_expiry: u32 = record[1].parse()?;
        let incoming_add_ts: u64 = record[2].parse()?;
        let incoming_remove_ts: u64 = record[3].parse()?;
        let outgoing_amt: u64 = record[4].parse()?;
        let outgoing_expiry: u32 = record[5].parse()?;
        let forwarding_node = PublicKey::from_slice(&hex::decode(&record[8])?)?;
        let channel_in_id: u64 = record[10].parse()?;
        let channel_out_id: u64 = record[11].parse()?;

        // If we're filtering cut off any htlc that was in flight at the cutoff point.
        if let Some(duration) = filter_duration {
            let cutoff = match start_ts {
                Some(s) => s,
                None => {
                    start_ts = Some(incoming_add_ts);
                    incoming_add_ts
                }
            }
            .add(duration.as_nanos() as u64);

            if incoming_add_ts > cutoff || incoming_remove_ts > cutoff {
                break;
            }
        }

        let forward = BootstrapForward {
            incoming_amt,
            outgoing_amt,
            incoming_expiry,
            outgoing_expiry,
            added_ns: incoming_add_ts,
            settled_ns: incoming_remove_ts,
            forwarding_node,
            channel_in_id,
            channel_out_id,
        };

        forwards.push(forward);
    }

    Ok(forwards)
}

/// Reads from a CSV (generated by simln) and populates all forwards belonging to the target node in min heap by
/// timestamp.
pub fn peacetime_from_file(
    file_path: &PathBuf,
    target_pubkey: PublicKey,
) -> Result<BinaryHeap<RevenueEvent>, BoxError> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);

    let mut heap = BinaryHeap::new();
    for result in csv_reader.records() {
        let record: StringRecord = result?;

        let forwarding_node = PublicKey::from_slice(&hex::decode(&record[8])?)?;
        if forwarding_node != target_pubkey {
            continue;
        }

        let incoming_amt: u64 = record[0].parse()?;
        let outgoing_amt: u64 = record[4].parse()?;

        heap.push(RevenueEvent {
            timestamp_ns: record[3].parse()?,
            fee_msat: incoming_amt - outgoing_amt,
        })
    }

    Ok(heap)
}
