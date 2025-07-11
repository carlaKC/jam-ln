use crate::reputation_interceptor::{BootstrapForward, BootstrapRecords};
use crate::revenue_interceptor::RevenueEvent;
use crate::BoxError;
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use csv::{ReaderBuilder, StringRecord};
use humantime::Duration as HumanDuration;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::ChannelSnapshot;
use serde::{Deserialize, Serialize};
use sim_cli::parsing::NetworkParser;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek};
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::task::{self, JoinSet};

/// Default percent of good reputation pairs the target requires.
pub const DEFAULT_TARGET_REP_PERCENT: &str = "50";

/// Default percent of good reputation pairs with the target that the attacker requires.
pub const DEFAULT_ATTACKER_REP_PERCENT: &str = "50";

/// Default clock speedup to run with regular wall time.
pub const DEFAULT_CLOCK_SPEEDUP: &str = "1";

/// Default htlc size that a peer must be able to get accountable to be considered as having good reputation, $10 at the
/// time of writing.
pub const DEFAULT_REPUTATION_MARGIN_MSAT: &str = "10000000";

/// Default htlc expiry used for calculating reputation margin htlc's risk.
pub const DEFAULT_REPUTATION_MARGIN_EXIPRY: &str = "200";

/// The default interval used to poll whether the attacker still has reputation with the target, 5 minutes expresssed
/// in seconds.
pub const DEFAULT_ATTACKER_POLL_SECONDS: &str = "300";

/// The default batch size for writing results to disk.
pub const DEFAULT_RESULT_BATCH_SIZE: &str = "500";

#[derive(Clone, Parser)]
pub struct ReputationParams {
    /// The window over which the value of a link's revenue to our node is calculated.
    #[arg(long)]
    pub revenue_window_seconds: Option<u64>,

    /// The multiplier applied to revenue_window_seconds to get the duration over which reputation is bootstrapped.
    #[arg(long)]
    pub reputation_multiplier: Option<u8>,
}

impl From<ReputationParams> for ForwardManagerParams {
    fn from(cli: ReputationParams) -> Self {
        let mut forward_params = ForwardManagerParams::default();
        if let Some(revenue_window) = cli.revenue_window_seconds {
            forward_params.reputation_params.revenue_window = Duration::from_secs(revenue_window);
        }
        if let Some(multiplier) = cli.reputation_multiplier {
            forward_params.reputation_params.reputation_multiplier = multiplier;
        }
        forward_params
    }
}

#[derive(Clone, Parser)]
pub struct NetworkParams {
    /// The directory containing all files required for the simulation.
    #[arg(long)]
    pub network_dir: PathBuf,
}

/// Describes a network of files used to run a simulation.
pub struct SimulationFiles {
    /// The network directory that contains all files required for the simulation.
    dir: PathBuf,

    /// The graph that the simulation will run on.
    pub sim_network: Vec<NetworkParser>,

    /// The details of the attacking node.
    pub attacker: (String, PublicKey),

    /// The details of the target node.
    pub target: (String, PublicKey),
}

impl SimulationFiles {
    /// Reads simulation relevant files and creates and directories necessary for the simulation.
    pub fn new(network_dir: PathBuf) -> Result<Self, BoxError> {
        // We don't actually need to use this file, but if it's not present the simulation has
        // probably been set up incorrectly (because you need to generate peacetime traffic
        // from this file).
        let _ = &fs::read_to_string(network_dir.join("peacetime_network.json"))
            .map_err(|e| format!("could not find peacetime_network.json: {}", e))?;

        let SimNetwork { sim_network } = serde_json::from_str(
            &fs::read_to_string(network_dir.join("attacktime_network.json"))
                .map_err(|e| format!("could not find attacktime_network.json: {}", e))?,
        )?;

        // In future commits, we'll allow multiple attacker aliases. For now, read a CSV and enforce
        // that there's only one attacker present.
        let attacker_list = fs::read_to_string(network_dir.join("attacker.csv")).map_err(|e| {
            format!(
                "attacker.csv file containing attacker alias not found: {}",
                e
            )
        })?;
        let attacker_aliases: Vec<&str> = attacker_list.trim().split(',').collect();

        if attacker_aliases.len() != 1 {
            return Err(format!(
                "expected on attacker alias, got: {}",
                attacker_aliases.len()
            )
            .into());
        }

        let attacker_alias = attacker_aliases
            .first()
            .ok_or("No attacker alias found in file")?;

        // We only allow one target node, but if there are multiple aliases in this file we'll
        // fail to find the pubkey by alias below.
        let target_alias = fs::read_to_string(network_dir.join("target.txt"))
            .map_err(|e| format!("target.txt file containing target alias not found: {}", e))?;

        let attacker_pubkey = find_pubkey_by_alias(attacker_alias, &sim_network)?;
        let target_pubkey = find_pubkey_by_alias(&target_alias.trim(), &sim_network)?;

        // Create results + reputation directories if they're not present, they are part of our
        // expected structure for the network.
        std::fs::create_dir_all(network_dir.join("reputation"))?;
        std::fs::create_dir_all(network_dir.join("results"))?;

        Ok(SimulationFiles {
            dir: network_dir,
            sim_network,
            attacker: (attacker_alias.to_string(), attacker_pubkey),
            target: (target_alias.to_string(), target_pubkey),
        })
    }

    /// Returns a directory to write simulation results to.
    pub fn results_dir(&self) -> PathBuf {
        self.dir.join("results")
    }

    /// Returns the location of a reputation and target revenue summary for the period of time
    /// that the attacker in the network is bootstrapped for, creating sub-directories to hold
    /// these files is necessary.
    pub fn reputation_summary(&self, duration: Option<Duration>) -> (PathBuf, PathBuf) {
        let reputation_dir = self
            .dir
            .join("reputation")
            .join(HumanDuration::from(duration.unwrap_or(Duration::ZERO)).to_string());

        // Create the specific duration directory
        let _ = std::fs::create_dir_all(&reputation_dir);

        (
            reputation_dir.join("reputation_summary.csv"),
            reputation_dir.join("target_revenue.txt"),
        )
    }

    /// Returns the location of the file containing peacetime projections for the network.
    pub fn peacetime_traffic(&self) -> PathBuf {
        self.dir.join("peacetime_traffic.csv")
    }

    /// Returns the location of the file used to generate reputation snapshots from.
    pub fn attacktime_traffic(&self) -> PathBuf {
        self.dir.join("attacktime_traffic.csv")
    }
}

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(flatten)]
    pub network: NetworkParams,

    /// The duration of time that reputation of the attacking node's reputation will be bootstrapped
    /// for, expressed as human readable values (eg: 1w, 3d).
    ///
    /// Requires that a file with the following name format is provided in [`Self::network_dir`]:
    ///
    /// - bootstrap_attacker_for_{t}.csv
    ///
    /// For example, if bootstrapping for 3w, the simulator will look for:
    /// network_dir/bootstrap_attacker_for_3w.csv
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
    pub clock_speedup: u16,

    /// The htlc amount that a peer must be able to get accountable to be considered as having a good reputation, expressed
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

    #[command(flatten)]
    pub reputation_params: ReputationParams,
}

impl Cli {
    pub fn validate(&self) -> Result<ForwardManagerParams, BoxError> {
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

        let forward_params: ForwardManagerParams = self.reputation_params.clone().into();
        if forward_params.reputation_params.reputation_window() < self.attacker_bootstrap {
            return Err(format!(
                "attacker_bootstrap {:?} < reputation window {:?} ({:?} * {})))",
                self.attacker_bootstrap,
                forward_params.reputation_params.reputation_window(),
                forward_params.reputation_params.revenue_window,
                forward_params.reputation_params.reputation_multiplier,
            )
            .into());
        }

        Ok(forward_params)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SimNetwork {
    #[serde(default)]
    pub sim_network: Vec<NetworkParser>,
}

pub fn find_pubkey_by_alias(
    alias: &str,
    sim_network: &[NetworkParser],
) -> Result<PublicKey, BoxError> {
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

pub fn find_alias_by_pubkey(
    pubkey: &PublicKey,
    sim_network: &[NetworkParser],
) -> Result<String, BoxError> {
    let target_channel = sim_network
        .iter()
        .find(|hist| hist.node_1.pubkey == *pubkey || hist.node_2.pubkey == *pubkey)
        .ok_or(format!("pubkey: {pubkey} not found in sim file"))?;

    Ok(if target_channel.node_1.pubkey == *pubkey {
        target_channel.node_1.alias.clone()
    } else {
        target_channel.node_2.alias.clone()
    })
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    Ok(HumanDuration::from_str(s)
        .map_err(|e| format!("Invalid duration '{}': {}", s, e))?
        .into())
}

fn find_next_newline(file: &mut BufReader<File>, start: u64) -> Result<u64, BoxError> {
    let mut position = start;
    file.seek(std::io::SeekFrom::Start(position))?;
    let mut buffer = [0; 1];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 || buffer[0] == b'\n' {
            break;
        }
        position += 1;
    }
    Ok(position)
}

fn calc_file_chunks(file_path: &PathBuf, num_chunks: u8) -> Result<Vec<u64>, BoxError> {
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();
    let chunk_size = file_size / num_chunks as u64;
    let mut breakpoints = Vec::with_capacity((num_chunks - 1) as usize);

    let mut reader = BufReader::new(file);
    // Set (num_chunks - 1)  breakpoints in the file for the tasks to start reading at.
    // Set breakpoints where the closest line ends.
    let mut current_breakpoint = 0;
    for _ in 0..num_chunks {
        let mut end = current_breakpoint + chunk_size;
        if end > file_size {
            end = file_size;
        }

        breakpoints.push(current_breakpoint);
        let next_eol_point = find_next_newline(&mut reader, end)?;
        current_breakpoint = next_eol_point + 1;
        if current_breakpoint >= file_size {
            break;
        }
    }

    Ok(breakpoints)
}

/// Reads forwards from a CSV (generated by simln), optionally filtering to only get a set duration of forwards from
/// the file.
pub async fn history_from_file(
    file_path: &PathBuf,
    filter_duration: Option<Duration>,
) -> Result<Vec<BootstrapForward>, BoxError> {
    let num_chunks = Handle::current().metrics().num_workers().div_ceil(2);
    let breakpoints = calc_file_chunks(file_path, num_chunks as u8)?;

    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();
    let filter_cutoff = {
        if let Some(duration) = filter_duration {
            let reader = BufReader::new(file);
            let mut csv_reader = csv::Reader::from_reader(reader);
            let mut first_record = StringRecord::new();
            csv_reader.read_record(&mut first_record)?;
            let incoming_add_ts: u64 = first_record[4].parse()?;
            Some(incoming_add_ts.add(duration.as_nanos() as u64))
        } else {
            None
        }
    };

    let mut tasks: Vec<tokio::task::JoinHandle<Result<Vec<BootstrapForward>, BoxError>>> =
        Vec::with_capacity(num_chunks);

    for i in 0..breakpoints.len() - 1 {
        let start = breakpoints[i];
        let end = if i == num_chunks - 1 {
            file_size
        } else {
            breakpoints[i + 1]
        };
        let path_clone = file_path.clone();
        tasks.push(task::spawn(async move {
            let mut file = File::open(path_clone)?;
            file.seek(std::io::SeekFrom::Start(start))?;
            let reader = BufReader::new(file).take(end - start);

            let mut csv_reader = if i == 0 {
                csv::Reader::from_reader(reader)
            } else {
                ReaderBuilder::new().has_headers(false).from_reader(reader)
            };

            let mut forwards = Vec::new();
            for result in csv_reader.deserialize() {
                let forward: BootstrapForward = result?;

                // If we're filtering cut off any htlc that was in flight at the cutoff point.
                if let Some(cutoff) = filter_cutoff {
                    if forward.added_ns > cutoff || forward.settled_ns > cutoff {
                        break;
                    }
                }

                forwards.push(forward);
            }

            Ok(forwards)
        }));
    }

    let mut forwards = Vec::new();
    for task in tasks {
        let task_forwards = task.await??;
        forwards.extend_from_slice(&task_forwards);
    }

    Ok(forwards)
}

pub fn reputation_snapshot_from_file(
    file_path: &PathBuf,
) -> Result<HashMap<PublicKey, HashMap<u64, ChannelSnapshot>>, BoxError> {
    let mut reputation_snapshot: HashMap<PublicKey, HashMap<u64, ChannelSnapshot>> = HashMap::new();

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);
    for result in csv_reader.records() {
        let record: StringRecord = result?;

        let pubkey = PublicKey::from_slice(&hex::decode(&record[0])?)?;
        let scid: u64 = record[1].parse()?;
        let capacity_msat: u64 = record[2].parse()?;
        let outgoing_reputation: i64 = record[3].parse()?;
        let bidirectional_revenue: i64 = record[4].parse()?;

        reputation_snapshot.entry(pubkey).or_default().insert(
            scid,
            ChannelSnapshot {
                capacity_msat,
                outgoing_reputation,
                bidirectional_revenue,
            },
        );
    }

    Ok(reputation_snapshot)
}

/// Reads from a CSV (generated by simln) and populates all forwards belonging to the target node in min heap by
/// timestamp.
pub async fn peacetime_from_file(
    file_path: &PathBuf,
    target_pubkey: PublicKey,
) -> Result<BinaryHeap<RevenueEvent>, BoxError> {
    let num_chunks = Handle::current().metrics().num_workers().div_ceil(2);
    let breakpoints = calc_file_chunks(file_path, num_chunks as u8)?;
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();

    let mut tasks: JoinSet<Result<(), BoxError>> = JoinSet::new();
    let heap = Arc::new(Mutex::new(BinaryHeap::new()));

    for i in 0..num_chunks {
        let start = breakpoints[i];
        let end = if i == num_chunks - 1 {
            file_size
        } else {
            breakpoints[i + 1]
        };
        let path_clone = file_path.clone();
        let heap_clone = Arc::clone(&heap);

        tasks.spawn(async move {
            let mut file = File::open(path_clone)?;
            file.seek(std::io::SeekFrom::Start(start))?;
            let reader = BufReader::new(file).take(end - start);
            let mut csv_reader = csv::Reader::from_reader(reader);

            for result in csv_reader.records() {
                let record: StringRecord = result?;

                let forwarding_node = PublicKey::from_slice(&hex::decode(&record[8])?)?;
                if forwarding_node != target_pubkey {
                    continue;
                }

                let incoming_amt: u64 = record[0].parse()?;
                let outgoing_amt: u64 = record[4].parse()?;

                heap_clone.lock().unwrap().push(RevenueEvent {
                    timestamp_ns: record[3].parse()?,
                    fee_msat: incoming_amt - outgoing_amt,
                })
            }
            Ok(())
        });
    }

    while let Some(res) = tasks.join_next().await {
        res??
    }

    let heap = Arc::try_unwrap(heap)
        .map_err(|_| "Heap Arc had more than one reference".to_string())?
        .into_inner()?;

    Ok(heap)
}

/// simulation is configured with (because anything more will just be decayed away). The file provided will then be
/// filtered to only bootstrap the attacker's payments for the duration configured. For example, if the reputation
/// window is 30 days and the attacker's bootstrap is 15 days, it'll read 30 days of forwards and remove all attacker
/// forwards for the first 15 days, so that the bootstrap period is effectively shorter for that node.
pub fn get_history_for_bootstrap(
    attacker_bootstrap: Duration,
    unfiltered_history: Vec<BootstrapForward>,
    attacker_channels: HashSet<u64>,
) -> Result<BootstrapRecords, BoxError> {
    let last_timestamp_nanos = unfiltered_history
        .iter()
        .max_by(|x, y| x.settled_ns.cmp(&y.settled_ns))
        .ok_or("at least one entry required in bootstrap history")?
        .settled_ns;

    if last_timestamp_nanos < attacker_bootstrap.as_nanos() as u64 {
        return Err(format!(
            "last absolute timestamp in bootstrap file: {last_timestamp_nanos} < relative attacker bootstrap: {}",
            attacker_bootstrap.as_nanos()
        )
        .into());
    }
    let bootstrap_cutoff = last_timestamp_nanos - attacker_bootstrap.as_nanos() as u64;

    Ok(BootstrapRecords {
        forwards: unfiltered_history
            .into_iter()
            .filter(|forward| {
                if forward.added_ns >= bootstrap_cutoff {
                    return true;
                }

                !attacker_channels.contains(&forward.channel_out_id)
            })
            .collect(),
        last_timestamp_nanos,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ops::Add;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::parsing::get_history_for_bootstrap;
    use crate::test_utils::test_bootstrap_forward;

    /// Tests the cases where filtering bootstrap data fails.
    #[test]
    fn test_get_history_for_bootstrap_errors() {
        assert!(get_history_for_bootstrap(
            Duration::from_secs(1),
            vec![],
            HashSet::from_iter(vec![10])
        )
        .is_err());

        // Bootstrapped with a duration that's too high for the data provided.
        let settled_ts = Duration::from_secs(100);
        let unfiltered_history = vec![test_bootstrap_forward(
            settled_ts.as_nanos() as u64 - 10,
            settled_ts.as_nanos() as u64,
            123,
            321,
        )];

        assert!(get_history_for_bootstrap(
            settled_ts.add(Duration::from_secs(10)),
            unfiltered_history,
            HashSet::from_iter(vec![123])
        )
        .is_err());
    }

    #[test]
    fn test_get_history_for_bootstrap() {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let attacker_channel = 123;
        let channel_1 = 456;
        let channel_2 = 789;

        let unfiltered_history = vec![
            // Before bootstrap period, one attacker outgoing forward that should be filtered, and incoming attacker
            // forward that should not be filtered.
            test_bootstrap_forward(start_time.add(1), start_time.add(10), channel_1, channel_2),
            test_bootstrap_forward(
                start_time.add(1),
                start_time.add(5),
                channel_1,
                attacker_channel,
            ),
            test_bootstrap_forward(
                start_time.add(3),
                start_time.add(4),
                attacker_channel,
                channel_1,
            ),
            // After bootstrap period, all attacker channels should be filtered.
            test_bootstrap_forward(
                start_time.add(7),
                start_time.add(8),
                channel_2,
                attacker_channel,
            ),
            test_bootstrap_forward(
                start_time.add(9),
                start_time.add(13),
                attacker_channel,
                channel_1,
            ),
        ];

        let filtered_history = get_history_for_bootstrap(
            Duration::from_nanos(9),
            unfiltered_history,
            HashSet::from_iter(vec![attacker_channel]),
        )
        .unwrap();
        assert_eq!(filtered_history.forwards.len(), 4);
        assert_eq!(filtered_history.last_timestamp_nanos, start_time.add(13));
    }
}
