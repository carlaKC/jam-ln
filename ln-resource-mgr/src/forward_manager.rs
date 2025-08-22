use crate::htlc_manager::{InFlightHtlc, InFlightManager};
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
use std::time::Instant;

/// Tracks reputation and revenue for a channel.
#[derive(Debug)]
struct TrackedChannel {
    capacity_msat: u64,
    outgoing_direction: OutgoingChannel,
    incoming_direction: IncomingChannel,
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
            reputation_params: ReputationParams::default(),
            general_slot_portion: 30,
            general_liquidity_portion: 30,
            congestion_slot_portion: 20,
            congestion_liquidity_portion: 20,
        }
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
        params: &ReputationParams,
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

        let in_flight_total_risk = self
            .htlcs
            .channel_in_flight_risk(forward.outgoing_channel_id)
            .iter()
            .try_fold(0u64, |acc, (k, v)| -> Result<u64, ReputationError> {
                let incoming_utilization = self
                    .channels
                    .get_mut(k)
                    .ok_or(ReputationError::ErrIncomingNotFound(*k))?
                    .incoming_direction
                    .max_utilization(forward.added_at)?;

                // We're happy to round HTLC risk because in the network we expect a expiry
                // delta of at least 10 (implementations should not allow setting a lower delta,
                // it's unsafe, and the default is around 80).
                let risk = v.iter().fold(0, |acc, v| {
                    acc + (params.htlc_risk(v.fee_msat, v.hold_blocks) as f64
                        * incoming_utilization)
                        .round() as u64
                });

                Ok(acc + risk)
            })?;

        let incoming_channel = self
            .channels
            .get_mut(&forward.incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                forward.incoming_ref.channel_id,
            ))?;

        let incoming_revenue_threshold = incoming_channel
            .incoming_direction
            .revenue
            .value_at_instant(forward.added_at)?;

        let incoming_utilization = incoming_channel
            .incoming_direction
            .max_utilization(forward.added_at)?;

        Ok(AllocationCheck {
            reputation_check: ReputationCheck {
                reputation: outgoing_reputation,
                revenue_threshold: incoming_revenue_threshold,
                in_flight_total_risk,
                // As noted above, we're okay with the rounding risk here due to typical values.
                htlc_risk: (params.htlc_risk(forward.fee_msat(), forward.expiry_in_height) as f64
                    * incoming_utilization)
                    .round() as u64,
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
                htlcs: InFlightManager::new(),
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

                if let Some(ref channel) = channel_reputation {
                    if channel.capacity_msat != capacity_msat {
                        return Err(ReputationError::ErrChannelCapacityMismatch(
                            capacity_msat,
                            channel.capacity_msat,
                        ));
                    }
                }

                v.insert(TrackedChannel {
                    capacity_msat,
                    incoming_direction: IncomingChannel::new(
                        &self.params.reputation_params,
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
                        add_ins,
                        channel_reputation.map(|snapshot| {
                            (
                                snapshot.incoming_slot_utilization,
                                snapshot.incoming_liquidity_utilization,
                                snapshot.incoming_revenue,
                            )
                        }),
                    )?,
                    outgoing_direction: OutgoingChannel::new(
                        self.params.reputation_params,
                        outgoing_reputation,
                    )?,
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
            .get_allocation_snapshot(&self.params.reputation_params, forward)
    }

    fn add_htlc(&self, forward: &ProposedForward) -> Result<ForwardingOutcome, ReputationError> {
        let mut inner_lock = self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        let allocation_check =
            inner_lock.get_allocation_snapshot(&self.params.reputation_params, forward)?;

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
                if !inner_lock
                    .channels
                    .get_mut(&forward.incoming_ref.channel_id)
                    .ok_or(ReputationError::ErrIncomingNotFound(
                        forward.incoming_ref.channel_id,
                    ))?
                    .incoming_direction
                    .add_htlc(
                        forward.outgoing_channel_id,
                        forward.amount_in_msat,
                        fwd_sucess.bucket.clone(),
                    )?
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

        inner_lock
            .channels
            .get_mut(&incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                incoming_ref.channel_id,
            ))?
            .incoming_direction
            .remove_htlc(
                outgoing_channel,
                in_flight.incoming_amt_msat,
                in_flight.bucket.clone(),
                resolution == ForwardResolution::Settled,
                resolved_instant,
            )?;

        inner_lock
            .channels
            .get_mut(&outgoing_channel)
            .ok_or(ReputationError::ErrOutgoingNotFound(outgoing_channel))?
            .outgoing_direction
            .remove_outgoing_htlc(&in_flight, resolution, resolved_instant)?;

        if resolution == ForwardResolution::Failed {
            return Ok(());
        }

        // If the htlc was settled, update the incoming channel's revenue.
        let fee_i64 = i64::try_from(in_flight.fee_msat).unwrap_or(i64::MAX);
        inner_lock
            .channels
            .get_mut(&incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                incoming_ref.channel_id,
            ))?
            .incoming_direction
            .revenue
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
            let (incoming_slot_utilization, incoming_liquidity_utilization) =
                channel.incoming_direction.utilization_values(access_ins)?;

            reputations.insert(
                *scid,
                ChannelSnapshot {
                    capacity_msat: channel.capacity_msat,
                    non_general_slots: channel.incoming_direction.protected_bucket.slot_count
                        + channel.incoming_direction.congestion_bucket.slot_count,
                    outgoing_reputation: channel
                        .outgoing_direction
                        .outgoing_reputation(access_ins)?,
                    incoming_revenue: channel
                        .incoming_direction
                        .revenue
                        .value_at_instant(access_ins)?,
                    incoming_slot_utilization,
                    incoming_liquidity_utilization,
                },
            );
        }

        Ok(reputations)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::ForwardManagerParams;
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
            non_general_slots: 100,
            outgoing_reputation: 1000,
            incoming_revenue: 500,
            incoming_liquidity_utilization: 0.0,
            incoming_slot_utilization: 0.0,
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
        assert!(channels.get(&1).unwrap().incoming_revenue == 500);

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
            non_general_slots: 100,
            outgoing_reputation: 10_000_000,
            incoming_revenue: 1_000_000,
            incoming_liquidity_utilization: 0.0,
            incoming_slot_utilization: 0.0,
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
            non_general_slots: 100,
            outgoing_reputation: 10_000_000,
            incoming_revenue: 1_000_000,
            incoming_liquidity_utilization: 0.0,
            incoming_slot_utilization: 0.0,
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
