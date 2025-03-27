use crate::decaying_average::DecayingAverage;
use crate::htlc_manager::{ChannelFilter, InFlightHtlc, InFlightManager};
use crate::incoming_channel::IncomingChannel;
use crate::outgoing_channel::{BucketParameters, OutgoingChannel};
use crate::{
    AllocationCheck, BucketResources, ForwardResolution, HtlcRef, ProposedForward, ReputationCheck,
    ReputationError, ReputationManager, ReputationParams, ReputationSnapshot, ResourceBucketType,
    ResourceCheck,
};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracks reputation and revenue for a channel.
#[derive(Debug)]
struct TrackedChannel {
    outgoing_direction: OutgoingChannel,
    incoming_direction: IncomingChannel,
    /// Tracks the revenue that this channel has been responsible for, considering htlcs where the channel has been the
    /// incoming or outgoing forwarding channel.
    bidirectional_revenue: DecayingAverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardManagerParams {
    pub reputation_params: ReputationParams,
    pub general_slot_portion: u8,
    pub general_liquidity_portion: u8,
    pub congestion_slot_portion: u8,
    pub congestion_liquidity_portion: u8,
}

impl ForwardManagerParams {
    /// Returns the opportunity cost for the htlc amount and expiry provided, assuming 10 minute blocks.
    pub fn htlc_opportunity_cost(&self, fee_msat: u64, expiry: u32) -> u64 {
        self.reputation_params
            .opportunity_cost(fee_msat, Duration::from_secs(expiry as u64 * 10 * 60))
    }
}

/// Defines special actions that can be taken during a simulation that wouldn't otherwise be used in regular operation.
pub trait SimualtionDebugManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError>;
}

/// Implements outgoing reputation algorithm and resource bucketing for an individual node.
#[derive(Debug)]
pub struct ForwardManager {
    params: ForwardManagerParams,
    inner: Mutex<ForwardManagerImpl>,
}

#[derive(Debug)]
struct ForwardManagerImpl {
    channels: HashMap<u64, TrackedChannel>,
    htlcs: InFlightManager,
}

impl ForwardManagerImpl {
    fn get_forwarding_outcome(
        &mut self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError> {
        forward.validate()?;

        // Get the incoming revenue threshold that the outgoing channel must meet.
        let incoming_channel = self
            .channels
            .get_mut(&forward.incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                forward.incoming_ref.channel_id,
            ))?;

        let incoming_threshold = incoming_channel
            .bidirectional_revenue
            .value_at_instant(forward.added_at)?;

        let no_congestion_misuse = incoming_channel
            .incoming_direction
            .no_congestion_misuse(forward.added_at);

        // Check reputation and resources available for the forward.
        let outgoing_channel = &mut self
            .channels
            .get_mut(&forward.outgoing_channel_id)
            .ok_or(ReputationError::ErrOutgoingNotFound(
                forward.outgoing_channel_id,
            ))?
            .outgoing_direction;

        Ok(AllocationCheck {
            reputation_check: ReputationCheck {
                outgoing_reputation: outgoing_channel.outgoing_reputation(forward.added_at)?,
                incoming_revenue: incoming_threshold,
                in_flight_total_risk: self.htlcs.channel_in_flight_risk(
                    ChannelFilter::OutgoingChannel(forward.outgoing_channel_id),
                ),
                // The underlying simulation is block height agnostic, and starts its routes with a height of zero, so
                // we can just use the incoming expiry to reflect "maximum time htlc can be held on channel", because
                // we're calculating expiry_in_height - 0.
                htlc_risk: self
                    .htlcs
                    .htlc_risk(forward.fee_msat(), forward.expiry_in_height),
            },
            // The incoming channel can only use congestion resources if it hasn't recently misused congestion
            // resources and it doesn't currently have any htlcs using them.
            congestion_eligible: no_congestion_misuse
                && self
                    .htlcs
                    .congestion_eligible(forward.incoming_ref.channel_id),
            resource_check: ResourceCheck {
                general_bucket: BucketResources {
                    slots_used: self.htlcs.bucket_in_flight_count(
                        forward.outgoing_channel_id,
                        ResourceBucketType::General,
                    ),
                    slots_available: outgoing_channel.general_bucket.slot_count,
                    liquidity_used_msat: self.htlcs.bucket_in_flight_msat(
                        forward.outgoing_channel_id,
                        ResourceBucketType::General,
                    ),
                    liquidity_available_msat: outgoing_channel.general_bucket.liquidity_msat,
                },
                congestion_bucket: BucketResources {
                    slots_used: self.htlcs.bucket_in_flight_count(
                        forward.outgoing_channel_id,
                        ResourceBucketType::Congestion,
                    ),
                    slots_available: outgoing_channel.congestion_bucket.slot_count,
                    liquidity_used_msat: self.htlcs.bucket_in_flight_msat(
                        forward.outgoing_channel_id,
                        ResourceBucketType::Congestion,
                    ),
                    liquidity_available_msat: outgoing_channel.congestion_bucket.liquidity_msat,
                },
            },
        })
    }
}

impl ForwardManager {
    pub fn new(params: ForwardManagerParams) -> Self {
        Self {
            params,
            inner: Mutex::new(ForwardManagerImpl {
                channels: HashMap::new(),
                htlcs: InFlightManager::new(params.reputation_params),
            }),
        }
    }
}

impl SimualtionDebugManager for ForwardManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError> {
        self.inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
            .get_mut(&channel)
            .ok_or(ReputationError::ErrChannelNotFound(channel))?
            .outgoing_direction
            .general_jam_channel();

        Ok(())
    }
}

impl ReputationManager for ForwardManager {
    fn add_channel(&self, channel_id: u64, capacity_msat: u64) -> Result<(), ReputationError> {
        match self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
            .entry(channel_id)
        {
            Entry::Occupied(_) => Err(ReputationError::ErrChannelExists(channel_id)),
            Entry::Vacant(v) => {
                let general_slot_count = 483 * self.params.general_slot_portion as u16 / 100;
                let general_liquidity_amount =
                    capacity_msat * self.params.general_liquidity_portion as u64 / 100;

                let congestion_slot_count = 483 * self.params.congestion_slot_portion as u16 / 100;
                let congestion_liquidity_amount =
                    capacity_msat * self.params.congestion_liquidity_portion as u64 / 100;

                v.insert(TrackedChannel {
                    incoming_direction: IncomingChannel::new(self.params.reputation_params),
                    outgoing_direction: OutgoingChannel::new(
                        self.params.reputation_params,
                        BucketParameters {
                            slot_count: general_slot_count,
                            liquidity_msat: general_liquidity_amount,
                        },
                        BucketParameters {
                            slot_count: congestion_slot_count,
                            liquidity_msat: congestion_liquidity_amount,
                        },
                    )?,
                    bidirectional_revenue: DecayingAverage::new(
                        self.params.reputation_params.revenue_window,
                    ),
                });

                Ok(())
            }
        }
    }

    fn remove_channel(&self, channel_id: u64) -> Result<(), ReputationError> {
        match self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
            .remove(&channel_id)
        {
            Some(_) => Ok(()),
            None => Err(ReputationError::ErrChannelNotFound(channel_id)),
        }
    }

    fn get_forwarding_outcome(
        &self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError> {
        self.inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .get_forwarding_outcome(forward)
    }

    fn add_htlc(&self, forward: &ProposedForward) -> Result<AllocationCheck, ReputationError> {
        let mut inner_lock = self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        let allocation_check = inner_lock.get_forwarding_outcome(forward)?;

        if let Ok(bucket) = allocation_check
            .inner_forwarding_outcome(forward.amount_out_msat, forward.incoming_endorsed)
        {
            inner_lock.htlcs.add_htlc(
                forward.incoming_ref,
                InFlightHtlc {
                    outgoing_channel_id: forward.outgoing_channel_id,
                    hold_blocks: forward.expiry_in_height,
                    outgoing_amt_msat: forward.amount_out_msat,
                    fee_msat: forward.fee_msat(),
                    added_instant: forward.added_at,
                    incoming_endorsed: forward.incoming_endorsed,
                    bucket,
                },
            )?;
        }

        Ok(allocation_check)
    }

    fn resolve_htlc(
        &self,
        outgoing_channel: u64,
        incoming_ref: HtlcRef,
        resolution: ForwardResolution,
        resolved_instant: Instant,
    ) -> Result<(), ReputationError> {
        let inner_lock = &mut self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        // Remove the hltc from our tracker, as well as the incoming and outgoing direction's current state.
        let in_flight = inner_lock
            .htlcs
            .remove_htlc(outgoing_channel, incoming_ref)?;

        inner_lock
            .channels
            .get_mut(&incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                incoming_ref.channel_id,
            ))?
            .incoming_direction
            .remove_incoming_htlc(&in_flight, resolved_instant);

        inner_lock
            .channels
            .get_mut(&outgoing_channel)
            .ok_or(ReputationError::ErrOutgoingNotFound(outgoing_channel))?
            .outgoing_direction
            .remove_outgoing_htlc(&in_flight, resolution, resolved_instant)?;

        if resolution == ForwardResolution::Failed {
            return Ok(());
        }

        // If the htlc was settled, update *both* the outgoing and incoming channel's revenue trackers.
        let fee_i64 = i64::try_from(in_flight.fee_msat).unwrap_or(i64::MAX);

        inner_lock
            .channels
            .get_mut(&outgoing_channel)
            .ok_or(ReputationError::ErrOutgoingNotFound(outgoing_channel))?
            .bidirectional_revenue
            .add_value(fee_i64, resolved_instant)?;

        inner_lock
            .channels
            .get_mut(&incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                incoming_ref.channel_id,
            ))?
            .bidirectional_revenue
            .add_value(fee_i64, resolved_instant)?;

        Ok(())
    }

    /// Lists the reputation scores of each channel at the access instant provided. This function will mutate the
    /// underlying decaying averages to be tracked at the instant provided.
    fn list_reputation(
        &self,
        access_ins: Instant,
    ) -> Result<HashMap<u64, ReputationSnapshot>, ReputationError> {
        let inner_lock = &mut self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels;

        let mut reputations = HashMap::with_capacity(inner_lock.len());
        for (scid, channel) in inner_lock.iter_mut() {
            reputations.insert(
                *scid,
                ReputationSnapshot {
                    outgoing_reputation: channel
                        .outgoing_direction
                        .outgoing_reputation(access_ins)?,
                    incoming_revenue: channel.bidirectional_revenue.value_at_instant(access_ins)?,
                },
            );
        }

        Ok(reputations)
    }
}
