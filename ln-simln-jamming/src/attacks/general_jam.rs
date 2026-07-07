use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use sim_cli::parsing::NetworkParser;
use simln_lib::clock::{Clock, SimulationClock};
use simln_lib::sim_node::{SimGraph, SimNode};
use tokio::select;
use tokio::sync::Mutex as TokioMutex;
use triggered::Listener;

use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::ASSIGNED_SLOTS;

use crate::reputation_interceptor::ChannelJammer;
use crate::{BoxError, NetworkReputation};

use super::{channels_to_jam_general, AttackStatisitcs, JammingAttack};

/// Default duration the jam is held for, in seconds (30 days), matching the peacetime baseline window.
const DEFAULT_JAM_SECS: u64 = 30 * 24 * 60 * 60;
const JAM_SECS_ENV: &str = "BASELINE_SECS";

/// Saturates only the `general` bucket of every one of the target's channels and holds it, then
/// measures how much honest forwarding revenue the target loses versus the co-simulated peacetime
/// network. Honest unaccountable traffic that can no longer fit `general` must either fall back to
/// `congestion` (a one-shot tit-for-tat) or be upgraded to `protected` (which needs reputation), so
/// this measures how much of the target's honest revenue depends on the open `general` bucket
/// before reputable peers route around the jam.
///
/// The jam is applied with the [`ChannelJammer`] helper, which does not itself open the channels
/// an attacker would really need to hold the buckets full. `attack_statistics` estimates that
/// cost with [`channels_to_jam_general`] — the minimum of opening the channel pairs directly (as
/// SlotJam does) and the hard-coded ~20-per-channel rule of thumb — and the summary charges it.
pub struct GeneralJam<J>
where
    J: ChannelJammer + Send + Sync,
{
    clock: Arc<SimulationClock>,
    target_pubkey: PublicKey,
    /// scids of every channel the target is an endpoint of; we jam the target's general resources
    /// on each so it cannot forward honest traffic out over them.
    target_channels: Vec<u64>,
    channel_jammer: Arc<J>,
    run_for: Duration,
    /// Number of channels actually jammed, recorded for the statistics summary.
    jammed_channels: Mutex<usize>,
}

impl<J> GeneralJam<J>
where
    J: ChannelJammer + Send + Sync,
{
    pub fn new(
        clock: Arc<SimulationClock>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        channel_jammer: Arc<J>,
    ) -> Self {
        let target_channels = network
            .iter()
            .filter_map(|channel| {
                if channel.node_1.pubkey == target_pubkey || channel.node_2.pubkey == target_pubkey
                {
                    Some(channel.scid.into())
                } else {
                    None
                }
            })
            .collect();

        let secs = std::env::var(JAM_SECS_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_JAM_SECS);

        Self {
            clock,
            target_pubkey,
            target_channels,
            channel_jammer,
            run_for: Duration::from_secs(secs),
            jammed_channels: Mutex::new(0),
        }
    }
}

#[async_trait]
impl<J> JammingAttack for GeneralJam<J>
where
    J: ChannelJammer + Send + Sync,
{
    fn validate(&self) -> Result<(), BoxError> {
        if self.target_channels.is_empty() {
            return Err("target has no channels to jam".into());
        }
        Ok(())
    }

    /// Jam the general resources on every one of the target's channels up front, then hold the
    /// jam for the configured duration so honest traffic has to route around it. Exit early if the
    /// simulation is already shutting down (e.g. the revenue-drop monitor stopped us).
    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        _attacker_nodes: HashMap<String, Arc<TokioMutex<SimNode<SimGraph, SimulationClock>>>>,
        shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        let mut jammed = 0;
        for scid in &self.target_channels {
            self.channel_jammer
                .jam_general_resources(&self.target_pubkey, *scid)
                .await?;
            jammed += 1;
        }
        *self.jammed_channels.lock().unwrap() = jammed;

        log::info!(
            "GeneralJam: jammed general resources on {} of the target's channels; holding for {:?}",
            jammed,
            self.run_for,
        );

        select! {
            _ = shutdown_listener => {},
            _ = self.clock.sleep(self.run_for) => {},
        }

        Ok(())
    }

    fn attack_statistics(&self) -> Result<AttackStatisitcs, BoxError> {
        let jammed = *self.jammed_channels.lock().unwrap();
        // The ChannelJammer helper jams for free; estimate the channels a real attacker would have
        // to open to hold these buckets full (min of the pairs-based and hard-coded approaches).
        let params = ForwardManagerParams::default();
        let estimated_jam_channels = channels_to_jam_general(
            jammed,
            self.target_channels.len(),
            params.general_slot_count(),
            ASSIGNED_SLOTS,
        );
        Ok(AttackStatisitcs {
            general_jammed_channels: jammed,
            congestion_jammed_channels: 0,
            estimated_jam_channels,
        })
    }
}
