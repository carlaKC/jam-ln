use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{validate_msat, AccountableSignal, HtlcRef, ReputationError, ResourceBucketType};

#[derive(Clone, Debug)]
pub(super) struct InFlightHtlc {
    pub(super) outgoing_channel_id: u64,
    pub(super) fee_msat: u64,
    pub(super) hold_blocks: u32,
    pub(super) incoming_amt_msat: u64,
    pub(super) added_instant: Instant,
    pub(super) outgoing_accountable: AccountableSignal,
    pub(super) bucket: ResourceBucketType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReputationParams {
    /// The period of time that revenue should be tracked to determine the threshold for reputation decisions.
    pub revenue_window: Duration,
    /// The multiplier applied to [`revenue_window`] that determines the period that reputation is built over.
    pub reputation_multiplier: u8,
    /// The threshold above which htlcs will be penalized for slow resolution.
    pub resolution_period: Duration,
    /// Expected block speed, surfaced to allow test networks to set different durations, defaults to 10 minutes
    /// otherwise.
    pub expected_block_speed: Option<Duration>,
}

impl ReputationParams {
    /// Calculates the opportunity_cost of a htlc being held on our channel - allowing one [`reputation_period`]'s
    /// grace period, then charging for every subsequent period.
    pub(super) fn opportunity_cost(&self, fee_msat: u64, hold_time: Duration) -> u64 {
        (0_f64.max(
            (hold_time.as_secs_f64() - self.resolution_period.as_secs_f64())
                / self.resolution_period.as_secs_f64(),
        ) * (fee_msat as f64))
            .round() as u64
    }

    /// Calculates the worst case reputation damage of a htlc, assuming it'll be held for its full expiry_delta.
    pub(super) fn htlc_risk(&self, fee_msat: u64, expiry_delta: u32) -> u64 {
        let max_hold_time = self
            .expected_block_speed
            .unwrap_or_else(|| Duration::from_secs(60 * 10))
            * expiry_delta;

        self.opportunity_cost(fee_msat, max_hold_time)
    }

    /// Calculates the fee contribution of a htlc, based on its hold time, accountability and resolution.
    pub(super) fn effective_fees(
        &self,
        fee_msat: u64,
        hold_time: Duration,
        accountable: AccountableSignal,
        settled: bool,
    ) -> Result<i64, ReputationError> {
        // If the htlc was successful, its fees contribute to our effective fee.
        let paid_fees = if settled { validate_msat(fee_msat)? } else { 0 };

        let effective_fees = paid_fees.saturating_sub(
            i64::try_from(self.opportunity_cost(fee_msat, hold_time)).unwrap_or(i64::MAX),
        );

        // Unaccountable htlcs do not have a negative impact on reputation.
        if accountable == AccountableSignal::Unaccountable && effective_fees < 0 {
            return Ok(0);
        }

        Ok(effective_fees)
    }

    /// Returns the window over which reputation is assessed.
    pub fn reputation_window(&self) -> Duration {
        self.revenue_window * self.reputation_multiplier.into()
    }
}

pub enum ChannelFilter {
    #[allow(dead_code)]
    IncomingChannel(u64),
    OutgoingChannel(u64),
}

/// Responsible for tracking all currently in flight htlcs on the node's channels.
///
/// Centrally tracked decrease data duplication (otherwise htlc amount/expiry needs to be tracked on both the incoming
/// and outgoing link).
#[derive(Debug)]
pub(super) struct InFlightManager {
    in_flight: HashMap<HtlcRef, InFlightHtlc>,
    params: ReputationParams,
}

impl InFlightManager {
    pub(super) fn new(params: ReputationParams) -> Self {
        Self {
            in_flight: HashMap::new(),
            params,
        }
    }

    /// Adds a in flight htlc, returning [`ReputationError::ErrDuplicateHtlc`] if it has already been added.
    pub(super) fn add_htlc(
        &mut self,
        htlc_ref: HtlcRef,
        in_flight: InFlightHtlc,
    ) -> Result<(), ReputationError> {
        match self.in_flight.entry(htlc_ref) {
            Entry::Occupied(_) => Err(ReputationError::ErrDuplicateHtlc(htlc_ref)),
            Entry::Vacant(v) => {
                v.insert(in_flight);
                Ok(())
            }
        }
    }

    /// Removes an in flight htlc, returning [`ReputationError::ErrForwardNotFound`] if the htlc was not previously
    /// added using [`add_htlc`].
    pub(super) fn remove_htlc(
        &mut self,
        outgoing_channel: u64,
        incoming_ref: HtlcRef,
    ) -> Result<InFlightHtlc, ReputationError> {
        self.in_flight
            .remove(&incoming_ref)
            .ok_or(ReputationError::ErrForwardNotFound(
                outgoing_channel,
                incoming_ref,
            ))
    }

    /// Returns the total htlc risk of all the accountable htlcs that a channel currently has in-flight on our channels.
    pub(super) fn channel_in_flight_risk(&self, filter: ChannelFilter) -> u64 {
        self.in_flight
            .iter()
            .filter(|(k, v)| {
                // Unaccountable htlcs do not contribute to risk, so no option is given to count them.
                if v.outgoing_accountable == AccountableSignal::Unaccountable {
                    return false;
                }

                match filter {
                    ChannelFilter::IncomingChannel(scid) => k.channel_id == scid,
                    ChannelFilter::OutgoingChannel(scid) => v.outgoing_channel_id == scid,
                }
            })
            .map(|(_, v)| self.params.htlc_risk(v.fee_msat, v.hold_blocks))
            .sum()
    }

    /// Returns the total balance of htlcs in flight in the bucket provided.
    pub(super) fn bucket_in_flight_msat(
        &self,
        incoming_channel_id: u64,
        bucket: ResourceBucketType,
    ) -> u64 {
        self.in_flight
            .iter()
            .filter(|(incoming_ref, v)| {
                v.bucket == bucket && incoming_ref.channel_id == incoming_channel_id
            })
            .map(|(_, v)| v.incoming_amt_msat)
            .sum()
    }

    /// Returns the total number of htlcs in flight in the bucket provided.
    pub(super) fn bucket_in_flight_count(
        &self,
        incoming_channel_id: u64,
        bucket: ResourceBucketType,
    ) -> u16 {
        self.in_flight
            .iter()
            .filter(|(incoming_ref, v)| {
                v.bucket == bucket && incoming_ref.channel_id == incoming_channel_id
            })
            .count() as u16 // Safe because we have in protocol limit 483.
    }

    /// Returns false if the outgoing channel currently has any in-flight htlcs that are utilizing
    /// congestion resources.
    pub(super) fn congestion_eligible(&self, outgoing_channel_id: u64) -> bool {
        !self.in_flight.iter().any(|(_, v)| {
            v.bucket == ResourceBucketType::Congestion
                && v.outgoing_channel_id == outgoing_channel_id
        })
    }

    /// Calculates the worst case reputation damage of a htlc, assuming it'll be held for its full expiry_delta.
    pub(super) fn htlc_risk(&self, fee_msat: u64, expiry_delta: u32) -> u64 {
        self.params.htlc_risk(fee_msat, expiry_delta)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::htlc_manager::{ChannelFilter, InFlightManager};
    use crate::{
        AccountableSignal, HtlcRef, ReputationError, ReputationParams, ResourceBucketType,
    };

    use super::InFlightHtlc;

    fn get_test_manager() -> InFlightManager {
        InFlightManager::new(ReputationParams {
            revenue_window: Duration::from_secs(60 * 60 * 24), // 1 week
            reputation_multiplier: 10,
            resolution_period: Duration::from_secs(60),
            expected_block_speed: Some(Duration::from_secs(60 * 10)),
        })
    }

    fn get_test_htlc(
        outgoing_channel: u64,
        accountable: bool,
        bucket: ResourceBucketType,
        fee_msat: u64,
    ) -> InFlightHtlc {
        InFlightHtlc {
            outgoing_channel_id: outgoing_channel,
            hold_blocks: 1000,
            incoming_amt_msat: 2000,
            fee_msat,
            added_instant: Instant::now(),
            outgoing_accountable: if accountable {
                AccountableSignal::Accountable
            } else {
                AccountableSignal::Unaccountable
            },
            bucket,
        }
    }

    /// Tests adding and removal of HTLCs from the tracker.
    #[test]
    fn test_add_htlc() {
        let mut tracker = get_test_manager();
        let channel_0 = 0;
        let channel_1 = 1;

        // HTLC forwarded on 0 -> 1.
        let htlc_1_ref = HtlcRef {
            channel_id: channel_0,
            htlc_index: 0,
        };
        let htlc_1 = get_test_htlc(channel_1, true, ResourceBucketType::Protected, 1000);
        tracker.add_htlc(htlc_1_ref, htlc_1.clone()).unwrap();

        // Check that HTLC counts for buckets are correct.
        // One in-flight htlc in protected bucket for incoming channel.
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Protected),
            1
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::General),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::Protected),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::General),
            0
        );

        // Duplicate add fails.
        assert!(matches!(
            tracker.add_htlc(htlc_1_ref, htlc_1.clone()).err().unwrap(),
            ReputationError::ErrDuplicateHtlc(_)
        ));

        // HTLC forwarded on  1 -> 0.
        let htlc_2_ref = HtlcRef {
            channel_id: channel_1,
            htlc_index: 0,
        };
        let htlc_2 = get_test_htlc(channel_0, false, ResourceBucketType::General, 2000);

        // Remove unknown fails.
        assert!(matches!(
            tracker
                .remove_htlc(htlc_2.outgoing_channel_id, htlc_2_ref)
                .err()
                .unwrap(),
            ReputationError::ErrForwardNotFound(_, _)
        ));

        assert!(tracker.add_htlc(htlc_2_ref, htlc_2).is_ok());
        // Newly added htlc is incoming on channel_1 on general bucket.
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::General),
            1
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::Protected),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Protected),
            1
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::General),
            0
        );

        // Removing outgoing htlc updates buckets accordingly.
        assert!(tracker
            .remove_htlc(htlc_1.outgoing_channel_id, htlc_1_ref)
            .is_ok());

        // htlc_1 where incoming channel is channel_0, should be empty now since it was removed.
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Protected),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::General),
            0
        );
    }

    /// Tests calculation of in flight risk on outgoing channels.
    #[test]
    fn test_in_flight_risk() {
        let mut tracker = get_test_manager();
        let channel_0 = 0;
        let channel_1 = 1;
        let channel_2 = 2;

        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::OutgoingChannel(channel_0)),
            0
        );
        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::OutgoingChannel(channel_1)),
            0
        );

        // Accountable htlc contribute to in flight risk and count, 0 -> 1.
        let htlc_1_ref = HtlcRef {
            channel_id: channel_0,
            htlc_index: 0,
        };
        let htlc_1 = get_test_htlc(channel_1, true, ResourceBucketType::Protected, 1000);
        let htlc_1_risk = tracker
            .params
            .htlc_risk(htlc_1.fee_msat, htlc_1.hold_blocks);

        // Accountable htlc contribute to in flight risk and count despite general bucket, 0 -> 1.
        let htlc_2_ref = HtlcRef {
            channel_id: channel_1,
            htlc_index: 0,
        };
        let htlc_2 = get_test_htlc(channel_0, true, ResourceBucketType::General, 5000);
        let htlc_2_risk = tracker
            .params
            .htlc_risk(htlc_2.fee_msat, htlc_2.hold_blocks);

        // Unaccountable htlc no contribution to in flight risk, 1 -> 2.
        let htlc_3_ref = HtlcRef {
            channel_id: channel_1,
            htlc_index: 1,
        };
        let htlc_3 = get_test_htlc(channel_2, false, ResourceBucketType::General, 100000);

        // Accountable htlc in congestion bucket still contributes to risk, 1 -> 2.
        let htlc_4_ref = HtlcRef {
            channel_id: channel_1,
            htlc_index: 2,
        };
        let htlc_4 = get_test_htlc(channel_2, true, ResourceBucketType::Congestion, 1250);
        let htlc_4_risk = tracker
            .params
            .htlc_risk(htlc_4.fee_msat, htlc_4.hold_blocks);

        assert!(tracker.add_htlc(htlc_1_ref, htlc_1).is_ok());
        assert!(tracker.add_htlc(htlc_2_ref, htlc_2).is_ok());
        assert!(tracker.add_htlc(htlc_3_ref, htlc_3).is_ok());
        assert!(tracker.add_htlc(htlc_4_ref, htlc_4).is_ok());

        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::OutgoingChannel(channel_0)),
            htlc_2_risk,
        );
        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::OutgoingChannel(channel_1)),
            htlc_1_risk,
        );
        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::OutgoingChannel(channel_2)),
            htlc_4_risk, // Unaccountable does not contribute to risk, so no htlc_3.
        );

        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::IncomingChannel(channel_0)),
            htlc_1_risk,
        );
        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::IncomingChannel(channel_1)),
            htlc_2_risk + htlc_4_risk, // Unaccountable does not contribute to risk, so no htlc_3.
        );
        assert_eq!(
            tracker.channel_in_flight_risk(ChannelFilter::IncomingChannel(channel_2)),
            0,
        );
    }

    /// Tests tracking of in flight counts and liquidity in buckets.
    #[test]
    fn test_bucket_in_flight() {
        let mut tracker = get_test_manager();
        let channel_0 = 0;
        let channel_1 = 1;

        // Buckets always empty to start.
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Protected),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::General),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Congestion),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::Protected),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::General),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::Congestion),
            0
        );

        // Accountable htlc 0 -> 1.
        let htlc_1_ref = HtlcRef {
            channel_id: channel_0,
            htlc_index: 0,
        };
        let htlc_1 = get_test_htlc(channel_1, true, ResourceBucketType::Protected, 1000);
        assert!(tracker.add_htlc(htlc_1_ref, htlc_1.clone()).is_ok());

        // Newly added htlc_1 on protected bucket where incoming channel is channel_0 should now be
        // present.
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Protected),
            1
        );
        assert_eq!(
            tracker.bucket_in_flight_msat(channel_0, ResourceBucketType::Protected),
            htlc_1.incoming_amt_msat,
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Congestion),
            0
        );

        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::Protected),
            0
        );
        assert_eq!(
            tracker.bucket_in_flight_msat(channel_1, ResourceBucketType::Protected),
            0,
        );
        assert_eq!(
            tracker.bucket_in_flight_count(channel_1, ResourceBucketType::Congestion),
            0
        );

        let htlc_2_ref = HtlcRef {
            channel_id: channel_0,
            htlc_index: 1,
        };
        let htlc_2 = get_test_htlc(channel_1, false, ResourceBucketType::Protected, 20);

        assert!(tracker.add_htlc(htlc_2_ref, htlc_2.clone()).is_ok());
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Protected),
            2
        );
        assert_eq!(
            tracker.bucket_in_flight_msat(channel_0, ResourceBucketType::Protected),
            htlc_1.incoming_amt_msat + htlc_2.incoming_amt_msat,
        );

        // Removing htlc updates accordingly.
        assert!(tracker
            .remove_htlc(htlc_1.outgoing_channel_id, htlc_1_ref)
            .is_ok());
        assert_eq!(
            tracker.bucket_in_flight_count(channel_0, ResourceBucketType::Protected),
            1
        );
        assert_eq!(
            tracker.bucket_in_flight_msat(channel_0, ResourceBucketType::Protected),
            htlc_2.incoming_amt_msat,
        );
    }

    #[test]
    fn test_congestion_eligible() {
        let mut tracker = get_test_manager();
        let channel_0 = 0;
        let channel_1 = 1;

        assert!(tracker.congestion_eligible(channel_0));
        assert!(tracker.congestion_eligible(channel_1));

        // Accountable htlc 0 -> 1.
        let htlc_1_ref = HtlcRef {
            channel_id: channel_0,
            htlc_index: 0,
        };
        let htlc_1 = get_test_htlc(channel_1, true, ResourceBucketType::Congestion, 1000);
        assert!(tracker.add_htlc(htlc_1_ref, htlc_1.clone()).is_ok());

        // Congestion not eligible for outgoing channel.
        assert!(tracker.congestion_eligible(channel_0));
        assert!(!tracker.congestion_eligible(channel_1));

        // Re-eligible once htlc has been removed.
        assert!(tracker
            .remove_htlc(htlc_1.outgoing_channel_id, htlc_1_ref)
            .is_ok());
        assert!(tracker.congestion_eligible(channel_0));
        assert!(tracker.congestion_eligible(channel_1));
    }
}
