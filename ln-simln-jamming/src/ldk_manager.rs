//! Wrapper that lets the LDK [`DefaultResourceManager`] be used as a drop-in
//! [`ReputationManager`] for the simulator.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use ln_resource_mgr::forward_manager::{ForwardManagerParams, SimulationDebugManager};
use ln_resource_mgr::{
    AccountableSignal, AllocationCheck, BucketResources, ChannelSnapshot, FailureReason,
    ForwardResolution, ForwardingOutcome, HtlcRef, ProposedForward, ReputationCheck,
    ReputationError, ReputationManager, ResourceCheck,
};

use lightning_ldk::ln::resource_manager::{
    AllocationSnapshot, BucketSnapshot, ChannelReputationSnapshot, DefaultResourceManager,
    ForwardingOutcome as LdkForwardingOutcome, ResourceManagerConfig,
};
use lightning_ldk::sign::EntropySource;

/// The LDK manager tracks HTLC hold time as an absolute cltv expiry minus the height the HTLC was
/// added at. The simulator's `ProposedForward` provides `expiry_in_height` as the number of blocks
/// the HTLC may be held (the same value the native `ForwardManager` feeds into its risk
/// calculation), so we pass it as the cltv expiry with a zero height added to reproduce the same
/// hold-time and keep the two implementations comparable.
const HEIGHT_ADDED: u32 = 0;

const MAX_ACCEPTED_HTLCS: u16 = 483;

/// A process-wide anchor mapping a reference [`Instant`] to a base unix timestamp. Shared by all
/// adapters so reputation values remain comparable across nodes. The base is large enough that
/// instants captured before the anchor (e.g. during bootstrap) still map to positive timestamps.
static TIME_ANCHOR: OnceLock<(Instant, u64)> = OnceLock::new();

const ANCHOR_BASE_UNIX_SECS: u64 = 4_000_000_000;

fn instant_to_unix_secs(instant: Instant) -> u64 {
    let (anchor_instant, anchor_secs) =
        *TIME_ANCHOR.get_or_init(|| (Instant::now(), ANCHOR_BASE_UNIX_SECS));
    if instant >= anchor_instant {
        anchor_secs.saturating_add(instant.duration_since(anchor_instant).as_secs())
    } else {
        anchor_secs.saturating_sub(anchor_instant.duration_since(instant).as_secs())
    }
}

/// A fixed entropy source used to salt each manager's general-bucket slot assignment, so that
/// runs are reproducible. Salts are per-node and each node's buckets are independent, so sharing
/// one constant salt is fine.
struct FixedEntropy;

impl EntropySource for FixedEntropy {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

fn params_to_config(params: &ForwardManagerParams) -> ResourceManagerConfig {
    ResourceManagerConfig {
        general_allocation_pct: params.general_slot_portion,
        congestion_allocation_pct: params.congestion_slot_portion,
        resolution_period: params.reputation_params.resolution_period,
        revenue_window: params.reputation_params.revenue_window,
        reputation_multiplier: params.reputation_params.reputation_multiplier,
    }
}

fn bucket_from_snapshot(snapshot: BucketSnapshot) -> BucketResources {
    BucketResources {
        slots_used: snapshot.slots_used,
        slots_available: snapshot.slots_available,
        liquidity_used_msat: snapshot.liquidity_used_msat,
        liquidity_available_msat: snapshot.liquidity_available_msat,
    }
}

fn allocation_check_from_snapshot(snapshot: AllocationSnapshot) -> AllocationCheck {
    AllocationCheck {
        reputation_check: ReputationCheck {
            reputation: snapshot.outgoing_reputation,
            revenue_threshold: snapshot.incoming_revenue,
            in_flight_total_risk: snapshot.in_flight_total_risk,
            htlc_risk: snapshot.htlc_risk,
        },
        general_eligible: snapshot.general_eligible,
        congestion_eligible: snapshot.congestion_eligible,
        resource_check: ResourceCheck {
            general_bucket: bucket_from_snapshot(snapshot.general_bucket),
            congestion_bucket: bucket_from_snapshot(snapshot.congestion_bucket),
            protected_bucket: bucket_from_snapshot(snapshot.protected_bucket),
        },
    }
}

/// Wraps the LDK [`DefaultResourceManager`], exposing it through the simulator's
/// [`ReputationManager`] and [`SimulationDebugManager`] traits.
///
/// The two APIs differ in a few ways that this wrapper reconciles:
/// - **Time**: the simulator works in [`Instant`]s; the LDK manager works in unix seconds. We map
///   between them using a single process-wide anchor so every node uses a consistent mapping.
/// - **Channel sizing**: the simulator adds channels by `capacity_msat`; the LDK manager wants
///   `max_htlc_value_in_flight_msat` + `max_accepted_htlcs`. We map capacity to the in-flight
///   limit and use the protocol max of 483 accepted HTLCs.
/// - **Snapshots**: the simulator seeds/reads reputation via `ChannelSnapshot`; we thread this
///   through the LDK manager's `add_channel_with_reputation` / `list_channels`. The LDK snapshot
///   doesn't carry capacity, so we track that here.
pub struct LdkResourceManager {
    inner: DefaultResourceManager,
    /// Tracks each channel's capacity, which the LDK manager does not itself retain but the
    /// simulator's `ChannelSnapshot` requires.
    capacities: Mutex<HashMap<u64, u64>>,
}

impl LdkResourceManager {
    pub fn new(params: ForwardManagerParams) -> Self {
        let inner = DefaultResourceManager::new(params_to_config(&params), &FixedEntropy)
            .expect("resource manager config derived from ForwardManagerParams should be valid");

        Self {
            inner,
            capacities: Mutex::new(HashMap::new()),
        }
    }
}

impl From<ForwardManagerParams> for LdkResourceManager {
    fn from(params: ForwardManagerParams) -> Self {
        LdkResourceManager::new(params)
    }
}

impl ReputationManager for LdkResourceManager {
    fn add_channel(
        &self,
        channel_id: u64,
        capacity_msat: u64,
        add_ins: Instant,
        channel_reputation: Option<ChannelSnapshot>,
    ) -> Result<(), ReputationError> {
        let mut capacities = self
            .capacities
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;
        if capacities.contains_key(&channel_id) {
            return Err(ReputationError::ErrChannelExists(channel_id));
        }

        let timestamp = instant_to_unix_secs(add_ins);
        let max_in_flight = capacity_msat;

        let result = match channel_reputation {
            Some(snapshot) => {
                if snapshot.capacity_msat != capacity_msat {
                    return Err(ReputationError::ErrChannelCapacityMismatch(
                        capacity_msat,
                        snapshot.capacity_msat,
                    ));
                }
                self.inner.add_channel_with_reputation(
                    channel_id,
                    max_in_flight,
                    MAX_ACCEPTED_HTLCS,
                    timestamp,
                    ChannelReputationSnapshot {
                        outgoing_reputation: snapshot.outgoing_reputation,
                        incoming_revenue: snapshot.incoming_revenue,
                    },
                )
            }
            None => {
                self.inner
                    .add_channel(channel_id, max_in_flight, MAX_ACCEPTED_HTLCS, timestamp)
            }
        };

        result.map_err(|_| {
            ReputationError::ErrUnrecoverable(format!(
                "ldk add_channel rejected channel {channel_id} (capacity {capacity_msat})"
            ))
        })?;

        capacities.insert(channel_id, capacity_msat);
        Ok(())
    }

    fn remove_channel(&self, _channel_id: u64) -> Result<(), ReputationError> {
        unimplemented!()
    }

    fn get_allocation_snapshot(
        &self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError> {
        let snapshot = self
            .inner
            .allocation_snapshot(
                forward.incoming_ref.channel_id,
                forward.amount_in_msat,
                forward.expiry_in_height,
                forward.outgoing_channel_id,
                forward.amount_out_msat,
                HEIGHT_ADDED,
                instant_to_unix_secs(forward.added_at),
            )
            .map_err(|_| {
                ReputationError::ErrUnrecoverable(format!(
                    "ldk allocation_snapshot failed for forward {forward}"
                ))
            })?;

        Ok(allocation_check_from_snapshot(snapshot))
    }

    fn add_htlc(&self, forward: &ProposedForward) -> Result<ForwardingOutcome, ReputationError> {
        let outcome = self
            .inner
            .add_htlc(
                forward.incoming_ref.channel_id,
                forward.amount_in_msat,
                forward.expiry_in_height,
                forward.outgoing_channel_id,
                forward.amount_out_msat,
                forward.incoming_accountable == AccountableSignal::Accountable,
                forward.incoming_ref.htlc_index,
                HEIGHT_ADDED,
                instant_to_unix_secs(forward.added_at),
            )
            .map_err(|_| {
                ReputationError::ErrUnrecoverable(format!(
                    "ldk add_htlc rejected forward {forward}"
                ))
            })?;

        Ok(match outcome {
            LdkForwardingOutcome::Forward(accountable) => {
                ForwardingOutcome::Forward(if accountable {
                    AccountableSignal::Accountable
                } else {
                    AccountableSignal::Unaccountable
                })
            }
            LdkForwardingOutcome::Fail => ForwardingOutcome::Fail(FailureReason::NoResources),
        })
    }

    fn resolve_htlc(
        &self,
        outgoing_channel: u64,
        incoming_ref: HtlcRef,
        resolution: ForwardResolution,
        resolved_instant: Instant,
    ) -> Result<(), ReputationError> {
        self.inner
            .resolve_htlc(
                incoming_ref.channel_id,
                incoming_ref.htlc_index,
                outgoing_channel,
                resolution == ForwardResolution::Settled,
                instant_to_unix_secs(resolved_instant),
            )
            .map_err(|_| ReputationError::ErrForwardNotFound(outgoing_channel, incoming_ref))
    }

    fn list_channels(
        &self,
        access_ins: Instant,
    ) -> Result<HashMap<u64, ChannelSnapshot>, ReputationError> {
        let timestamp = instant_to_unix_secs(access_ins);
        let reputations = self.inner.list_channels(timestamp);

        let capacities = self
            .capacities
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        let mut snapshots = HashMap::with_capacity(reputations.len());
        for (scid, reputation) in reputations {
            let capacity_msat = *capacities.get(&scid).ok_or_else(|| {
                ReputationError::ErrUnrecoverable(format!(
                    "capacity for channel {scid} not tracked"
                ))
            })?;
            snapshots.insert(
                scid,
                ChannelSnapshot {
                    capacity_msat,
                    outgoing_reputation: reputation.outgoing_reputation,
                    incoming_revenue: reputation.incoming_revenue,
                },
            );
        }

        Ok(snapshots)
    }
}

impl SimulationDebugManager for LdkResourceManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError> {
        self.inner
            .general_jam_channel(channel)
            .map_err(|_| ReputationError::ErrChannelNotFound(channel))
    }

    fn congestion_jam_channel(&self, channel: u64) -> Result<(), ReputationError> {
        self.inner
            .congestion_jam_channel(channel)
            .map_err(|_| ReputationError::ErrChannelNotFound(channel))
    }
}
