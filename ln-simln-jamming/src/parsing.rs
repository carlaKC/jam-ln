use crate::attacks::sink::SinkAttack;
use crate::attacks::JammingAttack;
use crate::clock::InstantClock;
use crate::reputation_interceptor::{BootstrapForward, BootstrapRecords, ReputationMonitor};
use crate::revenue_interceptor::{PeacetimeRevenueMonitor, RevenueEvent};
use crate::BoxError;
use bitcoin::secp256k1::PublicKey;
use clap::{Parser, ValueEnum};
use csv::{ReaderBuilder, StringRecord};
use humantime::Duration as HumanDuration;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::ChannelSnapshot;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use sim_cli::parsing::NetworkParser;
use simln_lib::clock::Clock;
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

#[derive(Debug, Copy, Clone, Parser, ValueEnum)]
pub enum TrafficType {
    Peacetime,
    Attacktime,
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

    /// Attacker nodes that will be used in the simulation.
    pub attackers: Vec<(String, PublicKey)>,

    /// The details of the target node.
    pub target: (String, PublicKey),
}

impl SimulationFiles {
    /// Reads simulation relevant files and creates and directories necessary for the simulation.
    pub fn new(network_dir: PathBuf, graph_type: TrafficType) -> Result<Self, BoxError> {
        // We'll always read both graphs to make sure that they're sanely set up, even though
        // we only need one or the other depending on graph type.
        let peacetime_network: SimNetwork = serde_json::from_str(
            &fs::read_to_string(network_dir.join("peacetime_network.json"))
                .map_err(|e| format!("could not find peacetime_network.json: {}", e))?,
        )?;

        let attacktime_network: SimNetwork = serde_json::from_str(
            &fs::read_to_string(network_dir.join("attacktime_network.json"))
                .map_err(|e| format!("could not find attacktime_network.json: {}", e))?,
        )?;

        let attacker_list = fs::read_to_string(network_dir.join("attacker.csv"))
            .map_err(|e| format!("attacker.csv file containing attacker alias not found: {e}"))?;
        let attacker_aliases: Vec<&str> = attacker_list.trim().split(',').collect();

        if attacker_aliases.is_empty() {
            return Err("could not read attackers from attacker.csv".into());
        }
        diff_peacetime_attacktime(
            &peacetime_network.sim_network,
            &attacktime_network.sim_network,
            &attacker_aliases,
        )?;

        let mut attackers = Vec::with_capacity(attacker_aliases.len());
        for alias in attacker_aliases {
            let attacker_pubkey = find_pubkey_by_alias(alias, &attacktime_network.sim_network)?;
            attackers.push((alias.to_string(), attacker_pubkey));
        }

        // We only allow one target node, but if there are multiple aliases in this file we'll
        // fail to find the pubkey by alias below.
        let target_alias = fs::read_to_string(network_dir.join("target.txt"))
            .map_err(|e| format!("target.txt file containing target alias not found: {}", e))?
            .trim()
            .to_owned();

        let target_pubkey = find_pubkey_by_alias(&target_alias, &attacktime_network.sim_network)?;

        // Create results + reputation directories if they're not present, they are part of our
        // expected structure for the network.
        std::fs::create_dir_all(network_dir.join("reputation"))?;
        std::fs::create_dir_all(network_dir.join("results"))?;

        Ok(SimulationFiles {
            dir: network_dir,
            sim_network: match graph_type {
                TrafficType::Attacktime => attacktime_network.sim_network,
                TrafficType::Peacetime => peacetime_network.sim_network,
            },
            attackers,
            target: (target_alias, target_pubkey),
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

/// Checks that the only difference in the peacetime and attack time channel graphs are attacker
/// owned channels.
fn diff_peacetime_attacktime(
    peacetime: &[NetworkParser],
    attacktime: &[NetworkParser],
    attacker_aliases: &[&str],
) -> Result<(), BoxError> {
    let peacetime_map: HashMap<u64, (String, String)> = peacetime
        .iter()
        .map(|channel| {
            (
                channel.scid.into(),
                (channel.node_1.alias.clone(), channel.node_2.alias.clone()),
            )
        })
        .collect();

    let mut attacktime_map: HashMap<u64, (String, String)> = attacktime
        .iter()
        .map(|channel| {
            (
                channel.scid.into(),
                (channel.node_1.alias.clone(), channel.node_2.alias.clone()),
            )
        })
        .collect();

    let attacker_aliases: HashSet<String> =
        HashSet::from_iter(attacker_aliases.iter().map(|s| s.to_string()));

    for (scid, (peacetime_1, peacetime_2)) in peacetime_map.iter() {
        if attacker_aliases.contains(peacetime_1) || attacker_aliases.contains(peacetime_2) {
            return Err(format!(
                "peacetime map contains channel: {} belonging to attacker: ({}, {})",
                scid, peacetime_1, peacetime_2
            )
            .into());
        }

        match attacktime_map.remove(scid) {
            Some((attack_1, attack_2)) => {
                if (attack_1 != *peacetime_1 || attack_2 != *peacetime_2)
                    && (attack_2 != *peacetime_1 || attack_1 != *peacetime_2)
                {
                    return Err(format!(
                        "channel: {} has mismatched aliases - peacetime ({}, {}), attacktime: ({}, {})",
                        scid, peacetime_1, peacetime_2, attack_1, attack_2,
                    ).into());
                }
            }
            None => {
                return Err(
                    format!("channel: {} found in peacetime map but not attacker", scid).into(),
                )
            }
        }
    }

    // Once we've removed all the matching channels, only attacker channels should remain.
    for (scid, (node_1, node_2)) in attacktime_map {
        if !(attacker_aliases.contains(&node_1) || attacker_aliases.contains(&node_2)) {
            return Err(format!(
                "attacker graph contains channel: {} which is not in peacetime graph and does not belong to attacker: ({}, {})",
                 scid, node_1, node_2,
            ).into());
        }
    }

    Ok(())
}

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(flatten)]
    pub network: NetworkParams,

    /// The duration of time that reputation of the attacking node's reputation will be bootstrapped
    /// for, expressed as human readable values (eg: 1w, 3d). Requires that a reputation bootstrap
    /// file has been created in advance for this duration.
    #[arg(long, value_parser = parse_duration)]
    pub attacker_bootstrap: Option<Duration>,

    /// The minimum percentage of channel pairs between the target and its honest peers that the target needs to have
    /// good reputation on for the simulation to run.
    #[arg(long, default_value = DEFAULT_TARGET_REP_PERCENT)]
    pub target_reputation_percent: u8,

    /// The minimum percentage of pairs with between the target and the attacker that the attacker needs to have good
    /// reputation on for the simulation to run.
    #[arg(long)]
    pub attacker_reputation_percent: Option<u8>,

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

    /// The size of results batches to write to disk.
    #[arg(long, default_value = DEFAULT_RESULT_BATCH_SIZE)]
    pub result_batch_size: u16,

    #[command(flatten)]
    pub reputation_params: ReputationParams,

    /// The attack that will be run on the simulation.
    #[arg(long, value_enum, default_value = "sink")]
    pub attack: AttackType,

    #[clap(long, default_value = "debug")]
    pub log_level: LevelFilter,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum AttackType {
    Sink,
    // NOTE: add your attack that you want to run here.
}

pub fn setup_attack<C, R, M>(
    cli: &Cli,
    simulation: &SimulationFiles,
    clock: Arc<C>,
    reputation_monitor: Arc<R>,
    revenue_monitor: Arc<M>,
    risk_margin: u64,
) -> Result<Arc<dyn JammingAttack + Send + Sync>, BoxError>
where
    C: Clock + InstantClock + 'static,
    R: ReputationMonitor + Send + Sync + 'static,
    M: PeacetimeRevenueMonitor + Send + Sync + 'static,
{
    let sim_network = simulation.sim_network.clone();

    // NOTE: If you are implementing your own attack and have added the variant to AttackType, you can
    // then do any setup specific to your attack here and return.
    match cli.attack {
        AttackType::Sink => {
            let attacker_pubkeys: Vec<PublicKey> =
                simulation.attackers.iter().map(|a| a.1).collect();
            let attack = Arc::new(SinkAttack::new(
                clock,
                &sim_network,
                simulation.target.1,
                attacker_pubkeys,
                risk_margin,
                reputation_monitor,
                revenue_monitor,
            ));

            Ok(attack)
        }
    }
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

        if let Some(attacker_target) = self.attacker_reputation_percent {
            if attacker_target == 0 || attacker_target > 100 {
                return Err(format!(
                    "attacker reputation percent {} must be in (0;100]",
                    attacker_target,
                )
                .into());
            }
        }

        let forward_params: ForwardManagerParams = self.reputation_params.clone().into();
        if let Some(bootstrap) = self.attacker_bootstrap {
            if forward_params.reputation_params.reputation_window() < bootstrap {
                return Err(format!(
                    "attacker_bootstrap {:?} > reputation window {:?} ({:?} * {})))",
                    bootstrap,
                    forward_params.reputation_params.reputation_window(),
                    forward_params.reputation_params.revenue_window,
                    forward_params.reputation_params.reputation_multiplier,
                )
                .into());
            }
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

                let forwarding_node = PublicKey::from_slice(&hex::decode(&record[6])?)?;
                if forwarding_node != target_pubkey {
                    continue;
                }

                let incoming_amt: u64 = record[0].parse()?;
                let outgoing_amt: u64 = record[1].parse()?;

                heap_clone.lock().unwrap().push(RevenueEvent {
                    timestamp_ns: record[5].parse()?,
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
