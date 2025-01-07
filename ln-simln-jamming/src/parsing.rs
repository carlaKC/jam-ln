use crate::reputation_interceptor::BootstrapForward;
use crate::BoxError;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use csv::StringRecord;
use humantime::Duration as HumanDuration;
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

    /// The duration of time that reputation for the network should be bootstrapped for, expressed as human readable
    /// values (eg: 1w, 3d).
    #[arg(long, value_parser = parse_duration)]
    pub bootstrap_duration: Duration,
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