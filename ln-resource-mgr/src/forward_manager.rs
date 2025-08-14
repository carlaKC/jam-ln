use crate::decaying_average::DecayingAverage;
use crate::htlc_manager::{ChannelFilter, InFlightHtlc, InFlightManager};
use crate::incoming_channel::{BucketParameters, IncomingChannel};
use crate::outgoing_channel::OutgoingChannel;
use crate::{
    AllocationCheck, BucketResources, ChannelSnapshot, ForwardResolution, ForwardingOutcome,
    HtlcRef, ProposedForward, ReputationCheck, ReputationError, ReputationManager,
    ReputationParams, ResourceBucketType, ResourceCheck,
};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracks reputation and revenue for a channel.
#[derive(Debug)]
struct TrackedChannel {
    capacity_msat: u64,
    outgoing_direction: OutgoingChannel,
    incoming_direction: IncomingChannel,
    /// Tracks the revenue that this channel has been responsible for, considering htlcs where the channel has been the
    /// incoming or outgoing forwarding channel.
    bidirectional_revenue: RevenueAverage,
}

/// Tracks the average bi-directional revenue of a channel over multiple windows of time to smooth out this value over
/// time. The number of windows that this average is tracked over is determined by [`Self::window_count`].
///
/// For example: if we're interested in tracking revenue over two weeks and we're interested in aggregating over ten
/// windows, we will track the aggregate revenue over the last ten two week windows.
#[derive(Debug)]
struct RevenueAverage {
    /// Tracks when the average started to be tracked. Used to track the actual number of windows we've been tracking
    /// for when we haven't yet reached the full [`Self::window_count`]. This gives us some robustness on startup,
    /// rather than underestimating.
    ///
    /// For example: if we've only been tracking for two windows of time, and we're averaging over ten windows we only
    /// want to average across the two tracked windows (rather than averaging over ten and including eight windows that
    /// are effectively zero).
    start_ins: Instant,
    /// The number of windows that we want to track our average revenue.
    window_count: u8,
    /// The length of the window we're tracking average values for.
    window_duration: Duration,
    /// Tracks the channel's average bi-directional revenue over the full period of time that we're interested in
    /// aggregating. This is a decent approximation of tracking each window separately, and saves us needing to store
    /// multiple data points per channel.
    ///
    /// For example:
    /// - 2 week revenue period
    /// - 12 window_count
    ///
    /// [`Self::aggregated_revenue_decaying`] will track average revenue over 24 weeks. The two week revenue window
    /// revenue average can then be obtained by adjusting for the window side, which has the effect of evenly
    /// distributing revenue between the windows.
    aggregated_revenue_decaying: DecayingAverage,
}

impl RevenueAverage {
    fn new(params: &ReputationParams, start_ins: Instant) -> Self {
        RevenueAverage {
            start_ins,
            window_count: params.reputation_multiplier,
            window_duration: params.revenue_window,
            aggregated_revenue_decaying: DecayingAverage::new(
                params.revenue_window * params.reputation_multiplier.into(),
            ),
        }
    }

    /// Decays the tracked value to its value at the instant provided and returns the updated value. The access_instant
    /// must be after the last_updated time of the decaying average, tolerant to nanosecond differences.
    fn add_value(&mut self, value: i64, update_time: Instant) -> Result<i64, ReputationError> {
        self.aggregated_revenue_decaying
            .add_value(value, update_time)
    }

    /// The number of full windows that have been tracked since the average started. Returned as a float so that the
    /// average can be gradually scaled.
    fn windows_tracked(&self, access_ins: Instant) -> f64 {
        access_ins.duration_since(self.start_ins).as_secs_f64() / self.window_duration.as_secs_f64()
    }

    /// Updates the current value of the decaying average and then adds the new value provided. The value provided
    /// will act as a saturating add if it exceeds i64::MAX.
    fn value_at_instant(&mut self, access_ins: Instant) -> Result<i64, ReputationError> {
        // If we're below our count of windows, we only want to aggregate for the amount of windows we've tracked so
        // far. If we've reached out count, we just use that because the average only tracks this number of windows.
        let windows_tracked = self.windows_tracked(access_ins);
        let window_divisor = f64::min(
            // If less than one window has been tracked, this will be a fraction which will inflate our revenue so we
            // just flatten it to 1.
            // TODO: better strategy for first window?
            if windows_tracked < 1.0 {
                1.0
            } else {
                windows_tracked
            },
            self.window_count as f64,
        );

        // To give the value for this longer-running average over an equivalent two week period, we just divide it by
        // the number of windows we're counting.
        Ok((self
            .aggregated_revenue_decaying
            .value_at_instant(access_ins)? as f64
            / window_divisor)
            .round() as i64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardManagerParams {
    pub reputation_params: ReputationParams,
    pub general_slot_portion: u8,
    pub general_liquidity_portion: u8,
    pub congestion_slot_portion: u8,
    pub congestion_liquidity_portion: u8,
}

impl Default for ForwardManagerParams {
    fn default() -> Self {
        ForwardManagerParams {
            reputation_params: ReputationParams {
                revenue_window: Duration::from_secs(60 * 60 * 24 * 14),
                reputation_multiplier: 12,
                resolution_period: Duration::from_secs(90),
                expected_block_speed: Some(Duration::from_secs(10 * 60)),
            },
            general_slot_portion: 30,
            general_liquidity_portion: 30,
            congestion_slot_portion: 20,
            congestion_liquidity_portion: 20,
        }
    }
}

impl ForwardManagerParams {
    /// Returns the opportunity cost for the htlc amount and expiry provided, assuming 10 minute blocks.
    pub fn htlc_opportunity_cost(&self, fee_msat: u64, expiry: u32) -> u64 {
        self.reputation_params
            .opportunity_cost(fee_msat, Duration::from_secs(expiry as u64 * 10 * 60))
    }
}

/// Defines special actions that can be taken during a simulation that wouldn't otherwise be used in regular operation.
pub trait SimulationDebugManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError>;
    fn congestion_jam_channel(&self, channel: u64) -> Result<(), ReputationError>;
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
    fn get_allocation_snapshot(
        &mut self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError> {
        forward.validate()?;

        // Check reputation and resources available for the forward.
        let outgoing_channel = &mut self
            .channels
            .get_mut(&forward.outgoing_channel_id)
            .ok_or(ReputationError::ErrOutgoingNotFound(
                forward.outgoing_channel_id,
            ))?
            .outgoing_direction;

        let no_congestion_misuse = outgoing_channel.no_congestion_misuse(forward.added_at);
        let outgoing_reputation = outgoing_channel.outgoing_reputation(forward.added_at)?;

        let incoming_channel = self
            .channels
            .get_mut(&forward.incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                forward.incoming_ref.channel_id,
            ))?;

        let incoming_revenue_threshold = incoming_channel
            .bidirectional_revenue
            .value_at_instant(forward.added_at)?;

        Ok(AllocationCheck {
            reputation_check: ReputationCheck {
                reputation: outgoing_reputation,
                revenue_threshold: incoming_revenue_threshold,
                in_flight_total_risk: self.htlcs.channel_in_flight_risk(
                    ChannelFilter::OutgoingChannel(forward.outgoing_channel_id),
                ),
                htlc_risk: self
                    .htlcs
                    .htlc_risk(forward.fee_msat(), forward.expiry_in_height),
            },
            general_eligible: incoming_channel
                .incoming_direction
                .general_bucket
                .may_add_htlc(forward.outgoing_channel_id, forward.amount_in_msat)?,
            // The outgoing channel can only use congestion resources if it hasn't recently misused congestion
            // resources and it doesn't currently have any htlcs using them.
            congestion_eligible: no_congestion_misuse
                && self.htlcs.congestion_eligible(forward.outgoing_channel_id),
            resource_check: ResourceCheck {
                general_bucket: BucketResources {
                    slots_used: self.htlcs.bucket_in_flight_count(
                        forward.incoming_ref.channel_id,
                        ResourceBucketType::General,
                    ),
                    slots_available: incoming_channel
                        .incoming_direction
                        .general_bucket
                        .params
                        .slot_count,
                    liquidity_used_msat: self.htlcs.bucket_in_flight_msat(
                        forward.incoming_ref.channel_id,
                        ResourceBucketType::General,
                    ),
                    liquidity_available_msat: incoming_channel
                        .incoming_direction
                        .general_bucket
                        .params
                        .liquidity_msat,
                },
                congestion_bucket: BucketResources {
                    slots_used: self.htlcs.bucket_in_flight_count(
                        forward.incoming_ref.channel_id,
                        ResourceBucketType::Congestion,
                    ),
                    slots_available: incoming_channel
                        .incoming_direction
                        .congestion_bucket
                        .slot_count,
                    liquidity_used_msat: self.htlcs.bucket_in_flight_msat(
                        forward.incoming_ref.channel_id,
                        ResourceBucketType::Congestion,
                    ),
                    liquidity_available_msat: incoming_channel
                        .incoming_direction
                        .congestion_bucket
                        .liquidity_msat,
                },
                protected_bucket: BucketResources {
                    slots_used: self.htlcs.bucket_in_flight_count(
                        forward.incoming_ref.channel_id,
                        ResourceBucketType::Protected,
                    ),
                    slots_available: incoming_channel
                        .incoming_direction
                        .protected_bucket
                        .slot_count,
                    liquidity_used_msat: self.htlcs.bucket_in_flight_msat(
                        forward.incoming_ref.channel_id,
                        ResourceBucketType::Protected,
                    ),
                    liquidity_available_msat: incoming_channel
                        .incoming_direction
                        .protected_bucket
                        .liquidity_msat,
                },
            },
        })
    }
}

impl ForwardManager {
    pub fn new(params: ForwardManagerParams) -> Self {
        assert!(params.general_slot_portion + params.congestion_slot_portion < 100);
        assert!(params.general_liquidity_portion + params.congestion_liquidity_portion < 100);
        Self {
            params,
            inner: Mutex::new(ForwardManagerImpl {
                channels: HashMap::new(),
                htlcs: InFlightManager::new(params.reputation_params),
            }),
        }
    }
}

impl SimulationDebugManager for ForwardManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError> {
        self.inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
            .get_mut(&channel)
            .ok_or(ReputationError::ErrChannelNotFound(channel))?
            .incoming_direction
            .general_jam_channel();
        Ok(())
    }

    fn congestion_jam_channel(&self, channel: u64) -> Result<(), ReputationError> {
        self.inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
            .get_mut(&channel)
            .ok_or(ReputationError::ErrChannelNotFound(channel))?
            .incoming_direction
            .congestion_jam_channel();
        Ok(())
    }
}

impl ReputationManager for ForwardManager {
    fn add_channel(
        &self,
        channel_id: u64,
        capacity_msat: u64,
        add_ins: Instant,
        channel_reputation: Option<ChannelSnapshot>,
    ) -> Result<(), ReputationError> {
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

                let protected_slot_portion =
                    100 - self.params.general_slot_portion - self.params.congestion_slot_portion;

                let protected_liquidity_portion = 100
                    - self.params.general_liquidity_portion
                    - self.params.congestion_liquidity_portion;

                let protected_slot_count = 483 * protected_slot_portion as u16 / 100;
                let protected_liquidity_amount =
                    capacity_msat * protected_liquidity_portion as u64 / 100;

                let outgoing_reputation = channel_reputation
                    .as_ref()
                    .map(|channel| (channel.outgoing_reputation, add_ins));

                let revenue = match &channel_reputation {
                    Some(channel) => {
                        if channel.capacity_msat != capacity_msat {
                            return Err(ReputationError::ErrChannelCapacityMismatch(
                                capacity_msat,
                                channel.capacity_msat,
                            ));
                        }

                        let mut revenue =
                            RevenueAverage::new(&self.params.reputation_params, add_ins);
                        revenue.add_value(channel.bidirectional_revenue, add_ins)?;
                        revenue
                    }
                    None => RevenueAverage::new(&self.params.reputation_params, add_ins),
                };

                v.insert(TrackedChannel {
                    capacity_msat,
                    incoming_direction: IncomingChannel::new(
                        channel_id,
                        BucketParameters {
                            slot_count: general_slot_count,
                            liquidity_msat: general_liquidity_amount,
                        },
                        BucketParameters {
                            slot_count: congestion_slot_count,
                            liquidity_msat: congestion_liquidity_amount,
                        },
                        BucketParameters {
                            slot_count: protected_slot_count,
                            liquidity_msat: protected_liquidity_amount,
                        },
                    )?,
                    outgoing_direction: OutgoingChannel::new(
                        self.params.reputation_params,
                        outgoing_reputation,
                    )?,
                    bidirectional_revenue: revenue,
                });

                Ok(())
            }
        }
    }

    fn remove_channel(&self, channel_id: u64) -> Result<(), ReputationError> {
        let mut inner_lock = self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        // Stop tracking this channel in all our other channels, to clean up any state that we
        // no longer need.
        for (scid, channel) in inner_lock.channels.iter_mut() {
            if *scid == channel_id {
                continue;
            }

            let _ = channel
                .incoming_direction
                .general_bucket
                .remove_channel(channel_id);
        }

        inner_lock
            .channels
            .remove(&channel_id)
            .ok_or(ReputationError::ErrChannelNotFound(channel_id))
            .map(|_| ())
    }

    fn get_allocation_snapshot(
        &self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError> {
        self.inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .get_allocation_snapshot(forward)
    }

    fn add_htlc(&self, forward: &ProposedForward) -> Result<ForwardingOutcome, ReputationError> {
        let mut inner_lock = self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        let allocation_check = inner_lock.get_allocation_snapshot(forward)?;

        let fwd_outcome = allocation_check.inner_forwarding_outcome(
            forward.amount_in_msat,
            forward.incoming_accountable,
            forward.upgradable_accountability,
        );

        let fwd_outcome = match fwd_outcome {
            Ok(fwd_sucess) => {
                // Add to our inner channel's bucket, failing if we can't add the HTLC. We've just
                // checked our forwarding outcome and our state is locked so this should always
                // succeed.
                if fwd_sucess.bucket == ResourceBucketType::General
                    && !inner_lock
                        .channels
                        .get_mut(&forward.incoming_ref.channel_id)
                        .ok_or(ReputationError::ErrIncomingNotFound(
                            forward.incoming_ref.channel_id,
                        ))?
                        .incoming_direction
                        .general_bucket
                        .add_htlc(forward.outgoing_channel_id, forward.amount_in_msat)?
                {
                    return Err(ReputationError::ErrUnrecoverable("Could not assign HTLC previously considered eligible with internal lock held - we have a bug!".to_string()));
                }

                inner_lock.htlcs.add_htlc(
                    forward.incoming_ref,
                    InFlightHtlc {
                        outgoing_channel_id: forward.outgoing_channel_id,
                        hold_blocks: forward.expiry_in_height,
                        incoming_amt_msat: forward.amount_in_msat,
                        fee_msat: forward.fee_msat(),
                        added_instant: forward.added_at,
                        outgoing_accountable: fwd_sucess.accountable_signal,
                        bucket: fwd_sucess.bucket,
                    },
                )?;
                ForwardingOutcome::Forward(fwd_sucess.accountable_signal)
            }
            Err(e) => ForwardingOutcome::Fail(e),
        };

        Ok(fwd_outcome)
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

        // Remove the htlc from our tracker, as well as the incoming and outgoing direction's current state.
        let in_flight = inner_lock
            .htlcs
            .remove_htlc(outgoing_channel, incoming_ref)?;

        if in_flight.bucket == ResourceBucketType::General {
            inner_lock
                .channels
                .get_mut(&incoming_ref.channel_id)
                .ok_or(ReputationError::ErrIncomingNotFound(
                    incoming_ref.channel_id,
                ))?
                .incoming_direction
                .general_bucket
                .remove_htlc(outgoing_channel, in_flight.incoming_amt_msat)?;
        }

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
    fn list_channels(
        &self,
        access_ins: Instant,
    ) -> Result<HashMap<u64, ChannelSnapshot>, ReputationError> {
        let inner_lock = &mut self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels;

        let mut reputations = HashMap::with_capacity(inner_lock.len());
        for (scid, channel) in inner_lock.iter_mut() {
            reputations.insert(
                *scid,
                ChannelSnapshot {
                    capacity_msat: channel.capacity_msat,
                    outgoing_reputation: channel
                        .outgoing_direction
                        .outgoing_reputation(access_ins)?,
                    bidirectional_revenue: channel
                        .bidirectional_revenue
                        .value_at_instant(access_ins)?,
                },
            );
        }

        Ok(reputations)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{ForwardManagerParams, RevenueAverage};
    use crate::{
        forward_manager::{ForwardManager, SimulationDebugManager},
        AccountableSignal, ChannelSnapshot, FailureReason, ForwardingOutcome, HtlcRef,
        ProposedForward, ReputationError, ReputationManager, ReputationParams,
    };

    #[test]
    fn test_jamming_helpers() {
        // Sanity check that jamming helpers set the appropriate bucket resources to 0.
        let fwd_manager = ForwardManager::new(test_forward_manager_params());

        let now = Instant::now();
        let channel_capacity = 10_000_000;
        fwd_manager
            .add_channel(0, channel_capacity, now, None)
            .unwrap();

        let inner_fwd_manager = fwd_manager.inner.lock().unwrap();
        let channel_0 = &inner_fwd_manager
            .channels
            .get(&0)
            .unwrap()
            .incoming_direction;
        assert!(channel_0.general_bucket.params.slot_count > 0);
        assert!(channel_0.congestion_bucket.slot_count > 0);

        // Drop the lock for `general_jam_channel`
        drop(inner_fwd_manager);

        fwd_manager.general_jam_channel(0).unwrap();
        fwd_manager.congestion_jam_channel(0).unwrap();
        let inner_fwd_manager = fwd_manager.inner.lock().unwrap();
        let channel_0 = &inner_fwd_manager
            .channels
            .get(&0)
            .unwrap()
            .incoming_direction;
        assert!(channel_0.general_bucket.params.slot_count == 0);
        assert!(channel_0.congestion_bucket.slot_count == 0);
    }

    #[test]
    fn test_revenue_average() {
        let params = ReputationParams {
            revenue_window: Duration::from_secs(60 * 60 * 24 * 14),
            reputation_multiplier: 10,
            resolution_period: Duration::from_secs(90),
            expected_block_speed: None,
        };

        let now = Instant::now();
        let mut revenue_average = RevenueAverage::new(&params, now);

        assert_eq!(revenue_average.value_at_instant(now).unwrap(), 0);

        let value = 10_000;

        // When we're right at the beginning our our tracking, revenue shouldn't be divided over multiple periods,
        // because we haven't tracked that long yet.
        revenue_average.add_value(value, now).unwrap();
        assert_eq!(revenue_average.value_at_instant(now).unwrap(), value);

        // Progress our timestamp to the end of the first window of time. We're testing the division of total revenue
        // tracked over windows, not the actual decaying average, so we peek under the hood to get the value that we've
        // decayed to and then assert that
        let end_first_window = now.checked_add(params.revenue_window).unwrap();
        let decayed_value = revenue_average
            .aggregated_revenue_decaying
            .value_at_instant(end_first_window)
            .unwrap();

        assert_eq!(
            revenue_average.value_at_instant(end_first_window).unwrap(),
            decayed_value
        );

        // Move to half way through the second window, the value should now be split between two periods. Again, we'll
        // peek under at the decayed value and then check that it's being split over periods.
        let half_second_window = end_first_window
            .checked_add(params.revenue_window / 2)
            .unwrap();
        let decayed_value = revenue_average
            .aggregated_revenue_decaying
            .value_at_instant(half_second_window)
            .unwrap();

        assert_eq!(
            revenue_average
                .value_at_instant(half_second_window)
                .unwrap(),
            (decayed_value as f64 / 1.5).round() as i64,
        );

        // Finally, test that once we reach our total window count, we don't continue to divide by more and more
        // windows.
        let final_window = now
            .checked_add(params.revenue_window * params.reputation_multiplier.into())
            .unwrap();
        let decayed_value = revenue_average
            .aggregated_revenue_decaying
            .value_at_instant(final_window)
            .unwrap();

        assert_eq!(
            revenue_average.value_at_instant(final_window).unwrap(),
            (decayed_value as f64 / params.reputation_multiplier as f64).round() as i64,
        );

        // Once we get beyond the window count, it's just the decay at play and we're using the count to divide our
        // running average.
        let beyond_final_window = now
            .checked_add(params.revenue_window * params.reputation_multiplier.into() * 5)
            .unwrap();
        let decayed_value = revenue_average
            .aggregated_revenue_decaying
            .value_at_instant(beyond_final_window)
            .unwrap();

        assert_eq!(
            revenue_average
                .value_at_instant(beyond_final_window)
                .unwrap(),
            (decayed_value as f64 / params.reputation_multiplier as f64).round() as i64,
        );
    }

    fn test_forward_manager_params() -> ForwardManagerParams {
        ForwardManagerParams {
            reputation_params: ReputationParams {
                revenue_window: Duration::from_secs(60 * 60 * 24 * 14),
                reputation_multiplier: 10,
                resolution_period: Duration::from_secs(90),
                expected_block_speed: None,
            },
            general_slot_portion: 30,
            general_liquidity_portion: 30,
            congestion_slot_portion: 20,
            congestion_liquidity_portion: 20,
        }
    }

    #[test]
    fn test_add_and_remove_channel() {
        let params = test_forward_manager_params();
        let now = Instant::now();

        let fwd_manager = ForwardManager::new(params);

        let channel_capacity = 10_000_000;
        assert!(fwd_manager
            .add_channel(0, channel_capacity, now, None)
            .is_ok());

        // Test adding channel from a snapshot
        let snapshot = ChannelSnapshot {
            capacity_msat: 10_000_000,
            outgoing_reputation: 1000,
            bidirectional_revenue: 500,
        };
        assert!(fwd_manager
            .add_channel(1, channel_capacity, now, Some(snapshot.clone()))
            .is_ok());

        assert!(
            fwd_manager
                .add_channel(0, channel_capacity, now, None)
                .err()
                .unwrap()
                == ReputationError::ErrChannelExists(0)
        );
        assert!(
            fwd_manager
                .add_channel(5, 20_000_000, now, Some(snapshot))
                .err()
                .unwrap()
                == ReputationError::ErrChannelCapacityMismatch(20_000_000, 10_000_000)
        );

        let channels = fwd_manager.list_channels(Instant::now()).unwrap();

        assert!(channels.len() == 2);
        assert!(channels.get(&0).unwrap().capacity_msat == channel_capacity);
        // Check values on 2nd channel added from snapshot
        assert!(channels.get(&1).unwrap().capacity_msat == channel_capacity);
        assert!(channels.get(&1).unwrap().outgoing_reputation == 1000);
        assert!(channels.get(&1).unwrap().bidirectional_revenue == 500);

        assert!(fwd_manager.remove_channel(0).is_ok());
        assert!(
            fwd_manager.remove_channel(100).err().unwrap()
                == ReputationError::ErrChannelNotFound(100)
        )
    }

    fn test_proposed_forward(
        incoming: u64,
        outgoing: u64,
        htlc_index: u64,
        accountable: AccountableSignal,
    ) -> ProposedForward {
        ProposedForward {
            incoming_ref: HtlcRef {
                channel_id: incoming,
                htlc_index,
            },
            outgoing_channel_id: outgoing,
            amount_in_msat: 10_000,
            amount_out_msat: 10_000 - 100,
            expiry_in_height: 80,
            expiry_out_height: 40,
            added_at: Instant::now(),
            incoming_accountable: accountable,
            upgradable_accountability: true,
        }
    }

    #[test]
    fn test_add_htlc_incoming_unaccountable() {
        let params = test_forward_manager_params();
        let now = Instant::now();
        let fwd_manager = ForwardManager::new(params);

        let channel_capacity = 10_000_000;
        fwd_manager
            .add_channel(0, channel_capacity, now, None)
            .unwrap();
        fwd_manager
            .add_channel(1, channel_capacity, now, None)
            .unwrap();

        let htlc_1 = test_proposed_forward(0, 1, 1, AccountableSignal::Unaccountable);
        let fwd_outcome = fwd_manager.add_htlc(&htlc_1).unwrap();

        // With general resources available, check that htlc_1 is forwarded as unaccountable.
        assert!(fwd_outcome == ForwardingOutcome::Forward(AccountableSignal::Unaccountable));

        // Jam the channel and try adding more htlcs.
        fwd_manager.general_jam_channel(0).unwrap();

        // With no general resources available, unaccountable htlc should go into congestion bucket
        // and be forwarded as accountable.
        let htlc_2 = test_proposed_forward(0, 1, 2, AccountableSignal::Unaccountable);
        let fwd_outcome = fwd_manager.add_htlc(&htlc_2).unwrap();
        assert!(fwd_outcome == ForwardingOutcome::Forward(AccountableSignal::Accountable));

        // Outgoing channel is already using a congestion slot, so it should fail with no resources
        let htlc_3 = test_proposed_forward(0, 1, 3, AccountableSignal::Unaccountable);
        let fwd_outcome = fwd_manager.add_htlc(&htlc_3).unwrap();
        assert!(fwd_outcome == ForwardingOutcome::Fail(FailureReason::NoGeneralResources));

        // Add a channel with sufficient reputation
        let snapshot = ChannelSnapshot {
            capacity_msat: channel_capacity,
            outgoing_reputation: 10_000_000,
            bidirectional_revenue: 1_000_000,
        };
        let channel_with_reputation = 2;

        fwd_manager
            .add_channel(
                channel_with_reputation,
                channel_capacity,
                now,
                Some(snapshot),
            )
            .unwrap();

        // With general resources jammed, an unaccountable htlc for a peer with reputation is
        // upgraded to accountable
        let htlc_4 = test_proposed_forward(
            0,
            channel_with_reputation,
            4,
            AccountableSignal::Unaccountable,
        );
        let fwd_outcome = fwd_manager.add_htlc(&htlc_4).unwrap();
        assert!(fwd_outcome == ForwardingOutcome::Forward(AccountableSignal::Accountable));
    }

    #[test]
    fn test_add_htlc_incoming_accountable() {
        let params = test_forward_manager_params();
        let now = Instant::now();
        let fwd_manager = ForwardManager::new(params);

        let channel_capacity = 10_000_000;
        fwd_manager
            .add_channel(0, channel_capacity, now, None)
            .unwrap();
        fwd_manager
            .add_channel(1, channel_capacity, now, None)
            .unwrap();

        let htlc_1 = test_proposed_forward(0, 1, 1, AccountableSignal::Accountable);
        let fwd_outcome = fwd_manager.add_htlc(&htlc_1).unwrap();

        // Accountable htlc for a peer with no reputation should fail
        assert!(fwd_outcome == ForwardingOutcome::Fail(FailureReason::NoReputation));

        // Add a channel with sufficient reputation
        let snapshot = ChannelSnapshot {
            capacity_msat: channel_capacity,
            outgoing_reputation: 10_000_000,
            bidirectional_revenue: 1_000_000,
        };
        let channel_with_reputation = 2;

        fwd_manager
            .add_channel(
                channel_with_reputation,
                channel_capacity,
                now,
                Some(snapshot),
            )
            .unwrap();

        // Accountable htlc for a peer with reputation
        let htlc_2 = test_proposed_forward(
            0,
            channel_with_reputation,
            2,
            AccountableSignal::Accountable,
        );
        let fwd_outcome = fwd_manager.add_htlc(&htlc_2).unwrap();
        assert!(fwd_outcome == ForwardingOutcome::Forward(AccountableSignal::Accountable));
    }
}
