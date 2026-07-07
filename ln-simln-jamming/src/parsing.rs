use crate::attacks::fast_jam::FastJam;
use crate::attacks::general_jam::GeneralJam;
use crate::attacks::inflation::InflationAttack;
use crate::attacks::looped_htlc::LoopedHtlc;
use crate::attacks::null::NullAttack;
use crate::attacks::sink::SinkAttack;
use crate::attacks::slot_jam::SlotJam;
use crate::attacks::slow_jam::SlowJam;
use crate::attacks::{AttackCost, JammingAttack};
use crate::reputation_interceptor::{
    BootstrapForward, BootstrapRecords, ChannelJammer, ReputationMonitor,
};
use crate::revenue_interceptor::PeacetimeRevenueMonitor;
use crate::BoxError;
use bitcoin::secp256k1::PublicKey;
use clap::{Parser, ValueEnum};
use csv::StringRecord;
use humantime::Duration as HumanDuration;
use lightning::routing::gossip::NetworkGraph;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::ChannelSnapshot;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use sim_cli::parsing::NetworkParser;
use simln_lib::clock::SimulationClock;
use simln_lib::sim_node::{populate_network_graph, SimulatedChannel, WrappedLog};
use simln_lib::SimulationError;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::BufReader;
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default percent of good reputation pairs the target requires.
pub const DEFAULT_TARGET_REP_PERCENT: &str = "50";

/// Default percent of good reputation pairs with the target that the attacker requires.
pub const DEFAULT_ATTACKER_REP_PERCENT: &str = "50";

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

#[derive(Clone, Parser)]
pub struct NetworkParams {
    /// The directory containing all files required for the simulation.
    #[arg(long)]
    pub network_dir: PathBuf,
}

pub enum NetworkType {
    Peacetime(PeacetimeNetwork),
    AttackTime(PeacetimeNetwork, AttacktimeNetwork),
    BootstrapAttackTime(PeacetimeNetwork, AttacktimeNetwork, Duration),
}

impl NetworkType {
    pub fn new(
        params: &NetworkParams,
        attack_type: Option<AttackType>,
        attacker_bootstrap: Option<Duration>,
    ) -> Result<Self, BoxError> {
        let peacetime_network = PeacetimeNetwork::new(params.network_dir.clone())?;
        if let Some(attack) = attack_type {
            let attacktime_network = AttacktimeNetwork::new(
                params
                    .network_dir
                    .join("attacks")
                    .join(format!("{:?}", attack)),
                attack.clone(),
            )?;

            diff_peacetime_attacktime(
                &peacetime_network.graph,
                &attacktime_network.graph,
                HashSet::from_iter(attacktime_network.attackers.iter().map(|a| a.0.clone())),
            )?;

            if let Some(bootstrap) = attacker_bootstrap {
                return Ok(Self::BootstrapAttackTime(
                    peacetime_network,
                    attacktime_network,
                    bootstrap,
                ));
            }

            Ok(Self::AttackTime(peacetime_network, attacktime_network))
        } else {
            Ok(Self::Peacetime(peacetime_network))
        }
    }

    /// Returns the file that contains traffic projections for the peacetime network. May be
    /// the same as reputation_file if running in NetworkType::PeacetimeNetwork.
    pub fn peacetime_projections(&self) -> PathBuf {
        match self {
            NetworkType::Peacetime(p)
            | NetworkType::AttackTime(p, _)
            | NetworkType::BootstrapAttackTime(p, _, _) => {
                p.network_dir.join(PeacetimeNetwork::TRAFFIC)
            }
        }
    }

    /// Returns the graph that we're actively simulating payments on.
    pub fn active_network(&self) -> &Vec<NetworkParser> {
        match self {
            NetworkType::Peacetime(p) => &p.graph,
            NetworkType::AttackTime(_, a) | NetworkType::BootstrapAttackTime(_, a, _) => &a.graph,
        }
    }

    /// Returns the peacetime graph (without any attacker channels), which is co-simulated
    /// alongside the attack graph to provide the live peacetime revenue baseline.
    pub fn peacetime_graph(&self) -> &Vec<NetworkParser> {
        match self {
            NetworkType::Peacetime(p)
            | NetworkType::AttackTime(p, _)
            | NetworkType::BootstrapAttackTime(p, _, _) => &p.graph,
        }
    }

    /// Returns the reputation snapshot file for the peacetime network (always the top-level
    /// peacetime `reputation.csv`, regardless of attacker bootstrap).
    pub fn peacetime_reputation_file(&self) -> PathBuf {
        match self {
            NetworkType::Peacetime(p)
            | NetworkType::AttackTime(p, _)
            | NetworkType::BootstrapAttackTime(p, _, _) => {
                p.network_dir.join(PeacetimeNetwork::REPUTATION)
            }
        }
    }

    /// Returns the location of a file that holds projected payments for our active graph.
    pub fn traffic_file(&self) -> PathBuf {
        match self {
            NetworkType::Peacetime(p) => p.network_dir.join(PeacetimeNetwork::TRAFFIC),
            NetworkType::AttackTime(_, a) | NetworkType::BootstrapAttackTime(_, a, _) => {
                a.attack_dir.join(AttacktimeNetwork::TRAFFIC)
            }
        }
    }

    /// Returns the location of a file that holds reputation summaries for our active graph.
    pub fn reputation_file(&self) -> PathBuf {
        match self {
            // For both a peacetime network and an attack time one without bootstrap we use
            // reputation build in our peacetime network.
            NetworkType::Peacetime(p) | NetworkType::AttackTime(p, _) => {
                p.network_dir.join(PeacetimeNetwork::REPUTATION)
            }
            NetworkType::BootstrapAttackTime(_, a, duration) => a
                .attack_dir
                .join(format!("reputation_{}.csv", duration.as_secs())),
        }
    }

    /// Returns the location that revenue built by the target during setup should be written.
    pub fn revenue_file(&self) -> Option<PathBuf> {
        match self {
            NetworkType::BootstrapAttackTime(_, a, duration) => Some(
                a.attack_dir
                    .join(format!("revenue_{}.csv", duration.as_secs())),
            ),
            _ => None,
        }
    }

    /// Returns a directory to write simulation results to, if appropriate for network type,
    /// namespacing by the runtime provided.
    pub fn results_dir(&self, now: SystemTime) -> Option<PathBuf> {
        match self {
            NetworkType::Peacetime(_) => None,
            NetworkType::AttackTime(_, a) | NetworkType::BootstrapAttackTime(_, a, _) => {
                let sec_since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

                Some(
                    PathBuf::from("results")
                        .join(format!("{:?}", a.attack))
                        .join(sec_since_epoch.to_string()),
                )
            }
        }
    }

    /// Returns the target node in our network.
    pub fn target(&self) -> (String, PublicKey) {
        match self {
            NetworkType::Peacetime(p)
            | NetworkType::AttackTime(p, _)
            | NetworkType::BootstrapAttackTime(p, _, _) => p.target.clone(),
        }
    }

    /// Returns the public keys of attackers in our network, if any.
    pub fn attackers(&self) -> &[(String, PublicKey)] {
        match self {
            NetworkType::Peacetime(_) => &[],
            NetworkType::AttackTime(_, a) | NetworkType::BootstrapAttackTime(_, a, _) => {
                &a.attackers
            }
        }
    }

    /// Returns the type of attack being run on the network.
    pub fn attack_type(&self) -> Option<AttackType> {
        match self {
            NetworkType::Peacetime(_) => None,
            NetworkType::AttackTime(_, a) | NetworkType::BootstrapAttackTime(_, a, _) => {
                Some(a.attack.clone())
            }
        }
    }
}

pub struct PeacetimeNetwork {
    network_dir: PathBuf,
    graph: Vec<NetworkParser>,
    target: (String, PublicKey),
}

impl PeacetimeNetwork {
    const PEACETIME_NETWORK: &'static str = "peacetime_network.json";
    const TARGET: &'static str = "target.txt";
    const REPUTATION: &'static str = "reputation.csv";
    const TRAFFIC: &'static str = "peacetime_traffic.csv";

    /// Creates a new peacetime network representation, failing if the files we expect to exist
    /// are not present.
    fn new(network_dir: PathBuf) -> Result<Self, BoxError> {
        let peacetime_graph = network_dir.join(Self::PEACETIME_NETWORK);
        if !peacetime_graph.exists() {
            return Err(format!(
                "expected peacetime graph: {} to exist",
                peacetime_graph.to_string_lossy()
            )
            .into());
        }

        let peacetime_network: SimNetwork =
            serde_json::from_str(&fs::read_to_string(&peacetime_graph).map_err(|e| {
                format!(
                    "could not find {}: {}",
                    peacetime_graph.to_string_lossy(),
                    e
                )
            })?)?;

        // We only allow one target node, but if there are multiple aliases in this file we'll
        // fail to find the pubkey by alias below.
        let target_alias = fs::read_to_string(network_dir.join(Self::TARGET))
            .map_err(|e| format!("target.txt file containing target alias not found: {}", e))?
            .trim()
            .to_owned();

        let target_pubkey = find_pubkey_by_alias(&target_alias, &peacetime_network.sim_network)?;

        Ok(Self {
            network_dir,
            graph: peacetime_network.sim_network,
            target: (target_alias, target_pubkey),
        })
    }
}

pub struct AttacktimeNetwork {
    attack_dir: PathBuf,
    graph: Vec<NetworkParser>,
    attackers: Vec<(String, PublicKey)>,
    attack: AttackType,
}

impl AttacktimeNetwork {
    const ATTACKTIME_NETWORK: &'static str = "attacktime_network.json";
    const ATTACKERS: &'static str = "attacker.csv";
    const TRAFFIC: &'static str = "attacktime_traffic.csv";

    fn new(attack_dir: PathBuf, attack: AttackType) -> Result<Self, BoxError> {
        let attack_graph = attack_dir.join(Self::ATTACKTIME_NETWORK);
        let attacktime_network: SimNetwork =
            serde_json::from_str(&fs::read_to_string(attack_graph.clone()).map_err(|e| {
                format!("could not find {}: {}", attack_graph.to_string_lossy(), e)
            })?)?;

        let attackers = attack_dir.join(Self::ATTACKERS);
        let attacker_list = fs::read_to_string(attackers.clone())
            .map_err(|e| format!("could not find: {}: {}", attackers.to_string_lossy(), e))?;
        let attacker_aliases: Vec<&str> = attacker_list.trim().split(',').collect();

        if attacker_aliases.is_empty() {
            return Err("could not read attackers from attacker.csv".into());
        }

        let mut attackers = Vec::with_capacity(attacker_aliases.len());
        for alias in attacker_aliases {
            let attacker_pubkey = find_pubkey_by_alias(alias, &attacktime_network.sim_network)?;
            attackers.push((alias.to_string(), attacker_pubkey));
        }

        Ok(Self {
            attack_dir,
            graph: attacktime_network.sim_network,
            attackers,
            attack,
        })
    }
}

/// Checks that the only difference in the peacetime and attack time channel graphs are attacker
/// owned channels.
fn diff_peacetime_attacktime(
    peacetime: &[NetworkParser],
    attacktime: &[NetworkParser],
    attacker_aliases: HashSet<String>,
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

/// Counts the channels in the network that have an attacker node as one of their endpoints,
/// i.e. the channels the attacker had to open in the graph to mount the attack.
pub fn count_attacker_channels(network: &[NetworkParser], attackers: &HashSet<PublicKey>) -> usize {
    network
        .iter()
        .filter(|channel| {
            attackers.contains(&channel.node_1.pubkey) || attackers.contains(&channel.node_2.pubkey)
        })
        .count()
}

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(flatten)]
    pub network: NetworkParams,

    /// The minimum percentage of channel pairs between the target and its honest peers that the target needs to have
    /// good reputation on for the simulation to run.
    #[arg(long, default_value = DEFAULT_TARGET_REP_PERCENT)]
    pub target_reputation_percent: u8,

    /// The minimum percentage of pairs with between the target and the attacker that the attacker needs to have good
    /// reputation on for the simulation to run.
    #[arg(long)]
    pub attacker_reputation_percent: Option<u8>,

    /// The htlc amount that a peer must be able to get accountable to be considered as having a good reputation, expressed
    /// in msat. This will be converted to a fee using a base fee of 1000 msat and a proportional charge of 0.01% of the
    /// amount.
    #[arg(long, default_value = DEFAULT_REPUTATION_MARGIN_MSAT)]
    pub reputation_margin_msat: u64,

    /// The htlc expiry that is used to assess whether a peer has sufficient reputation to forward a htlc, expressed
    /// in blocks.
    #[arg(long, default_value = DEFAULT_REPUTATION_MARGIN_EXIPRY)]
    pub reputation_margin_expiry_blocks: u32,

    /// The attack that we're interested in running.
    #[arg(long, value_enum)]
    pub attack_type: AttackType,

    /// The duration of time that reputation of the attacking node's reputation will be bootstrapped
    /// for, expressed as human readable values (eg: 1w, 3d). Requires that a reputation bootstrap
    /// file has been created in advance for this duration.
    #[arg(long, value_parser = parse_duration)]
    pub attacker_bootstrap: Option<Duration>,

    /// The size of results batches to write to disk.
    #[arg(long, default_value = DEFAULT_RESULT_BATCH_SIZE)]
    pub result_batch_size: u16,

    #[command(flatten)]
    pub reputation_params: ReputationParams,

    #[clap(long, default_value = "debug")]
    pub log_level: LevelFilter,
}

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq)]
pub enum AttackType {
    Sink,
    SlowJam,
    /// Inert baseline: adds attacker channels to the graph but takes no action, used to establish
    /// the Common-Random-Numbers baseline an attack's revenue impact is measured against.
    Null,
    /// Saturates the general bucket of every one of the target's channels and holds it.
    GeneralJam,
    /// The real (non-helper) general-bucket jam: pins each (incoming, outgoing) channel pair's
    /// assigned general slots with held tiny HTLCs routed through the target.
    SlotJam,
    /// Fast jam: an endless stream of small, fast-failing HTLCs the attacker pushes through the
    /// target to keep its channels' general-bucket HTLC slots full, so honest unaccountable
    /// payments are rejected with `no general resources`. The defence is the unconditional fee.
    FastJam,
    /// Loops accountable HTLCs through the target across several of its channels and holds them to
    /// damage the target's outgoing reputation, combined with a general-bucket jam.
    LoopedHtlc,
    /// Inflates the target's per-channel incoming-revenue thresholds with genuine settling
    /// payments to price out honest peers' reputation, then congests the buckets so their
    /// traffic is dropped.
    Inflation,
    // NOTE: add your attack that you want to run here.
}

#[allow(clippy::too_many_arguments)]
pub fn setup_attack<R, M, J>(
    cli: &Cli,
    network: &NetworkType,
    clock: Arc<SimulationClock>,
    reputation_monitor: Arc<R>,
    revenue_monitor: Arc<M>,
    channel_jammer: Arc<J>,
    attack_cost: Arc<AttackCost>,
) -> Result<Arc<dyn JammingAttack + Send + Sync>, BoxError>
where
    R: ReputationMonitor + Send + Sync + 'static,
    M: PeacetimeRevenueMonitor + Send + Sync + 'static,
    J: ChannelJammer + Send + Sync + 'static,
{
    let forward_params: ForwardManagerParams = cli.reputation_params.clone().into();
    let sim_network = network.active_network();

    // NOTE: If you are implementing your own attack and have added the variant to AttackType, you can
    // then do any setup specific to your attack here and return.
    match network
        .attack_type()
        .ok_or("attack type must be set for simulation")?
    {
        AttackType::Sink => {
            // Reputation is assessed for a channel pair and a specific HTLC that's being proposed. To assess whether pairs
            // have reputation, we'll use LND's default fee policy to get the HTLC risk for our configured htlc size and hold
            // time.
            let risk_margin = forward_params.htlc_opportunity_cost(
                1000 + (0.0001 * cli.reputation_margin_msat as f64) as u64,
                cli.reputation_margin_expiry_blocks,
            );

            let attack = Arc::new(SinkAttack::new(
                clock,
                sim_network,
                network.target().1,
                network.attackers().iter().map(|a| a.1).collect(),
                risk_margin,
                reputation_monitor,
                revenue_monitor,
                channel_jammer,
            ));

            Ok(attack)
        }
        AttackType::SlowJam => {
            let attackers = network.attackers();
            let attacker_pubkey_1 = attackers
                .iter()
                .find(|a| a.0 == "70")
                .ok_or("Required attacker with alias 70 not found")?;

            // Attacker node that will be used to send malicious payments.
            let attacker_sender = attackers
                .iter()
                .find(|a| a.0 == "25")
                .ok_or("Required attacker sender with alias 25 not found")?;

            let honest_sender = ("69".to_string(), find_pubkey_by_alias("69", sim_network)?);
            let honest_receiver = ("5".to_string(), find_pubkey_by_alias("5", sim_network)?);

            // Channel with target's peer that will be jammed.
            let target_peer_pubkey = PublicKey::from_str(
                "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
            )?;

            let channel_to_jam = (target_peer_pubkey, 348545186070528);
            let network_graph = network_graph(sim_network.clone())?;

            let attack = Arc::new(SlowJam::new(
                Arc::clone(&clock),
                sim_network,
                network.target().1,
                attacker_sender.clone(),
                attacker_pubkey_1.clone(),
                honest_sender,
                honest_receiver,
                channel_to_jam,
                Arc::clone(&reputation_monitor),
                Arc::clone(&channel_jammer),
                network_graph,
                attack_cost,
            ));

            Ok(attack)
        }
        AttackType::Null => Ok(Arc::new(NullAttack::new(clock))),
        AttackType::GeneralJam => Ok(Arc::new(GeneralJam::new(
            clock,
            sim_network,
            network.target().1,
            channel_jammer,
        ))),
        AttackType::SlotJam => {
            let target_pubkey = network.target().1;
            let attackers = network.attackers();
            // Sender originates the held HTLCs; receiver holds them (two nodes, since LDK will not
            // route a payment back to its own origin).
            let attacker_sender = attackers
                .iter()
                .find(|a| a.0 == "50")
                .ok_or("Required SlotJam attacker sender with alias 50 not found")?
                .clone();
            let attacker_receiver = attackers
                .iter()
                .find(|a| a.0 == "51")
                .ok_or("Required SlotJam attacker receiver with alias 51 not found")?
                .1;

            // The target's honest peers (its channel counterparties), sorted by channel capacity
            // descending so SlotJam jams the highest-value (I, O) pairs first when it is capped.
            let mut peers_with_cap: Vec<(PublicKey, u64)> = sim_network
                .iter()
                .filter_map(|c| {
                    if c.node_1.pubkey == target_pubkey {
                        Some((c.node_2.pubkey, c.capacity_msat))
                    } else if c.node_2.pubkey == target_pubkey {
                        Some((c.node_1.pubkey, c.capacity_msat))
                    } else {
                        None
                    }
                })
                .collect();
            peers_with_cap.sort_by(|a, b| b.1.cmp(&a.1));
            let target_peers: Vec<PublicKey> = peers_with_cap.into_iter().map(|(pk, _)| pk).collect();

            let network_graph = network_graph(sim_network.clone())?;

            Ok(Arc::new(SlotJam::new(
                clock,
                target_pubkey,
                attacker_sender,
                attacker_receiver,
                target_peers,
                network_graph,
                reputation_monitor,
                attack_cost,
            )))
        }
        AttackType::FastJam => {
            let attackers = network.attackers();

            // Attacker sender (originates the jamming payments) and receiver (fails them fast). The
            // receiver is the last hop of every jamming route, so the target forwards our HTLCs out
            // to it; the sender pushes them in through the target's honest peers.
            let sender = attackers
                .iter()
                .find(|a| a.0 == "51")
                .ok_or("required fast-jam attacker sender with alias 51 not found")?;
            let receiver = attackers
                .iter()
                .find(|a| a.0 == "50")
                .ok_or("required fast-jam attacker receiver with alias 50 not found")?;

            // The target's incoming channels we keep jammed. We pick the target's two
            // highest-capacity peers (44, 31), which carry the bulk of the honest traffic the
            // target forwards, so filling their general buckets denies the largest share of the
            // target's routing revenue for the fewest jammed channels (and thus the least
            // unconditional fee).
            let peers_to_jam = vec![
                find_pubkey_by_alias("44", sim_network)?,
                find_pubkey_by_alias("31", sim_network)?,
            ];

            let network_graph = network_graph(sim_network.clone())?;

            let attack = Arc::new(FastJam::new(
                clock,
                network.target().1,
                sender.0.clone(),
                receiver.1,
                peers_to_jam,
                network_graph,
                attack_cost,
            ));

            Ok(attack)
        }
        AttackType::LoopedHtlc => {
            let target_pubkey = network.target().1;
            // Two attacker nodes: 50 originates the loop, 51 receives and holds its final hop. A
            // single node cannot be both (LDK refuses to route a payment back to its own origin).
            let attacker_sender = network
                .attackers()
                .iter()
                .find(|a| a.0 == "50")
                .ok_or("Required attacker sender with alias 50 not found")?
                .clone();
            let attacker_receiver = network
                .attackers()
                .iter()
                .find(|a| a.0 == "51")
                .ok_or("Required attacker receiver with alias 51 not found")?
                .clone();

            // Honest peer used to inject the loop into the target. Alias 47 has a low
            // target-incoming-revenue, so the loop's first crossing (target -> mid_peer) clears the
            // reputation threshold set by this channel's revenue.
            let entry_peer = find_pubkey_by_alias("47", sim_network)?;

            // Honest peer used only to prime the receiver's reputation. Alias 31 already has very
            // high target-incoming-revenue, so the fees the priming payments credit to its channel
            // don't meaningfully move any threshold the loops depend on.
            let prime_peer = find_pubkey_by_alias("31", sim_network)?;

            // The target's highest-outgoing-reputation channels: these are the ones that would
            // rescue honest forwards under the general jam (by upgrading them to protected), so
            // destroying their reputation is what turns the jam into revenue loss. Each is also a
            // low target-incoming-revenue peer, keeping the loop's final-hop threshold small.
            let mid_aliases = ["8", "42", "44"];
            let mut mid_peers = Vec::with_capacity(mid_aliases.len());
            for alias in mid_aliases {
                let pubkey = find_pubkey_by_alias(alias, sim_network)?;
                let scid = sim_network
                    .iter()
                    .find(|c| {
                        (c.node_1.pubkey == target_pubkey && c.node_2.pubkey == pubkey)
                            || (c.node_2.pubkey == target_pubkey && c.node_1.pubkey == pubkey)
                    })
                    .ok_or(format!("target channel with mid peer {alias} not found"))?
                    .scid
                    .into();
                mid_peers.push((pubkey, scid));
            }

            // The receiver must have a channel with the target for the loop's final hop; validate it
            // exists (its reputation is primed at runtime).
            sim_network
                .iter()
                .find(|c| {
                    (c.node_1.pubkey == target_pubkey && c.node_2.pubkey == attacker_receiver.1)
                        || (c.node_2.pubkey == target_pubkey
                            && c.node_1.pubkey == attacker_receiver.1)
                })
                .ok_or("receiver must have a channel with the target for the receive hop")?;

            let network_graph = network_graph(sim_network.clone())?;

            Ok(Arc::new(LoopedHtlc::new(
                clock,
                sim_network,
                target_pubkey,
                attacker_sender,
                attacker_receiver,
                entry_peer,
                prime_peer,
                mid_peers,
                // Loop amount: small enough that the accountable HTLC's in-flight risk stays under
                // the entry peer's reputation (so honest hops forward it), but non-trivial so the
                // target's per-hop fee — and hence the reputation damage on failure — is meaningful.
                1_000_000,
                // Priming: a few large-fee settling payments build the receiver's reputation.
                4,
                100_000,
                channel_jammer,
                network_graph,
                attack_cost,
            )))
        }
        AttackType::Inflation => {
            let attackers = network.attackers();
            // Attacker node that originates inflation payments (has channels to the inject peers).
            let sender = attackers
                .iter()
                .find(|a| a.0 == "50")
                .ok_or("Required attacker sender with alias 50 not found")?
                .clone();
            // Attacker node that receives inflation payments (has a channel to the exit peer).
            let receiver = attackers
                .iter()
                .find(|a| a.0 == "51")
                .ok_or("Required attacker receiver with alias 51 not found")?
                .clone();

            // Honest peers of the target whose incoming channel we inflate. Chosen among the
            // target's channels whose current incoming-revenue threshold is low enough to be
            // meaningfully raised (peer 31's is already ~1.4B and is not worth inflating).
            let inject_peers = ["44", "4", "47"]
                .iter()
                .map(|alias| find_pubkey_by_alias(alias, sim_network))
                .collect::<Result<Vec<_>, _>>()?;

            // Exit peer: routed *out* through a high-fee channel (peer 5, 2000ppm) so the target's
            // fee per forward - which is what credits the inject channels' revenue - is large.
            let exit_peer = find_pubkey_by_alias("5", sim_network)?;

            let network_graph = network_graph(sim_network.clone())?;

            Ok(Arc::new(InflationAttack::new(
                clock,
                sim_network,
                network.target().1,
                sender,
                receiver,
                inject_peers,
                exit_peer,
                reputation_monitor,
                revenue_monitor,
                channel_jammer,
                network_graph,
                attack_cost,
            )))
        }
    }
}

fn network_graph(
    network: Vec<NetworkParser>,
) -> Result<Arc<NetworkGraph<Arc<WrappedLog>>>, BoxError> {
    let channels = network
        .clone()
        .into_iter()
        .map(|channel| {
            SimulatedChannel::new(
                channel.capacity_msat,
                channel.scid,
                channel.node_1,
                channel.node_2,
                false,
            )
        })
        .collect::<Vec<SimulatedChannel>>();

    let clock = Arc::new(SimulationClock::new(std::time::SystemTime::now()));

    Ok(Arc::new(
        populate_network_graph(channels, clock.clone())
            .map_err(|e| SimulationError::SimulatedNetworkError(format!("{:?}", e)))?,
    ))
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
            if bootstrap.is_zero() {
                return Err("zero attacker_bootstrap is invalid, do not specify option".into());
            }

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

/// Reads forwards from a CSV (generated by simln), optionally filtering to only get a set duration of forwards from
/// the file.
pub async fn history_from_file(
    file_path: &PathBuf,
    filter_duration: Option<Duration>,
) -> Result<Vec<BootstrapForward>, BoxError> {
    let file = File::open(file_path)?;
    let mut csv_reader = csv::Reader::from_reader(BufReader::new(file));

    // The cutoff is the first forward's added_ns plus the filter duration. The file is ordered by
    // timestamp, so we can stop at the first forward added or settled after the cutoff.
    let mut filter_cutoff: Option<u64> = None;
    let mut forwards = Vec::new();
    for result in csv_reader.deserialize() {
        let forward: BootstrapForward = result?;

        if let Some(duration) = filter_duration {
            let cutoff = *filter_cutoff
                .get_or_insert_with(|| forward.added_ns.add(duration.as_nanos() as u64));
            if forward.added_ns > cutoff || forward.settled_ns > cutoff {
                break;
            }
        }

        forwards.push(forward);
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
        let incoming_revenue: i64 = record[4].parse()?;

        reputation_snapshot.entry(pubkey).or_default().insert(
            scid,
            ChannelSnapshot {
                capacity_msat,
                outgoing_reputation,
                incoming_revenue,
            },
        );
    }

    Ok(reputation_snapshot)
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

    /// Counts only channels that touch an attacker node, regardless of which endpoint it is.
    #[test]
    fn test_count_attacker_channels() {
        use crate::parsing::count_attacker_channels;
        use crate::test_utils::{get_random_keypair, setup_test_edge};
        use bitcoin::secp256k1::PublicKey;

        let attacker = get_random_keypair().1;
        let honest_1 = get_random_keypair().1;
        let honest_2 = get_random_keypair().1;

        let network = vec![
            setup_test_edge(0.into(), honest_1, honest_2),
            setup_test_edge(1.into(), attacker, honest_1),
            setup_test_edge(2.into(), honest_2, attacker),
        ];

        let attackers = HashSet::from([attacker]);
        assert_eq!(count_attacker_channels(&network, &attackers), 2);

        let no_attackers: HashSet<PublicKey> = HashSet::new();
        assert_eq!(count_attacker_channels(&network, &no_attackers), 0);
    }

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
