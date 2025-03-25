use std::ops::Sub;
use std::time::Instant;

use crate::decaying_average::DecayingAverage;
use crate::htlc_manager::{InFlightHtlc, ReputationParams};
use crate::{ForwardResolution, ReputationError};

/// Describes the size of a resource bucket.
#[derive(Clone, Debug)]
pub struct BucketParameters {
    /// The number of HTLC slots available in the bucket.
    pub slot_count: u16,
    /// The amount of liquidity available in the bucket.
    pub liquidity_msat: u64,
}

/// Tracks information about the usage of a channel when it utilized as the outgoing direction in
/// a htlc forward.
#[derive(Clone, Debug)]
pub(super) struct OutgoingChannel {
    params: ReputationParams,

    /// The reputation that the channel has accrued as the outgoing link in htlc forwards. Tracked as a decaying
    /// average over the reputation_window that the tracker is created with.
    outgoing_reputation: DecayingAverage,

    /// The resources available for htlcs that are not endorsed, or are not sent by a peer with sufficient reputation.
    pub(super) general_bucket: BucketParameters,

    /// The resources available for htlcs that are endorsed from peers that do not have sufficient reputation. This
    /// bucket is only used when the general bucket is full, and peers are limited to a single slot/liquidity block.
    pub(super) congestion_bucket: BucketParameters,
}

impl OutgoingChannel {
    pub(super) fn new(
        params: ReputationParams,
        general_bucket: BucketParameters,
        congestion_bucket: BucketParameters,
    ) -> Result<Self, ReputationError> {
        if params.reputation_multiplier <= 1 {
            return Err(ReputationError::ErrInvalidMultiplier);
        }

        Ok(Self {
            params,
            outgoing_reputation: DecayingAverage::new(
                params.revenue_window * params.reputation_multiplier.into(),
            ),
            general_bucket,
            congestion_bucket,
        })
    }

    /// Returns the reputation that the channel has earned in the outgoing direction over [`revenue_window *
    /// reputation_multiplier`].
    pub(super) fn outgoing_reputation(
        &mut self,
        access_instant: Instant,
    ) -> Result<i64, ReputationError> {
        self.outgoing_reputation.value_at_instant(access_instant)
    }

    /// Removes an in flight htlc, updating reputation to reflect impact of resolution.
    pub(super) fn remove_outgoing_htlc(
        &mut self,
        in_flight: &InFlightHtlc,
        resolution: ForwardResolution,
        resolved_instant: Instant,
    ) -> Result<(), ReputationError> {
        // Unendorsed payments only have a positive impact on reputation (no negative effective fees are applied),
        // and endorsed payments
        let settled = resolution == ForwardResolution::Settled;
        let effective_fees = self.params.effective_fees(
            in_flight.fee_msat,
            resolved_instant.sub(in_flight.added_instant),
            in_flight.incoming_endorsed,
            settled,
        )?;

        // Update reputation to reflect its reputation impact.
        self.outgoing_reputation
            .add_value(effective_fees, resolved_instant)?;

        Ok(())
    }

    pub(super) fn general_jam_channel(&mut self) {
        self.general_bucket = BucketParameters {
            slot_count: 0,
            liquidity_msat: 0,
        };
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::htlc_manager::ReputationParams;
    use crate::{EndorsementSignal, ForwardResolution, ResourceBucketType};

    use super::{BucketParameters, InFlightHtlc, OutgoingChannel};

    fn get_test_params() -> ReputationParams {
        ReputationParams {
            revenue_window: Duration::from_secs(60 * 60 * 24), // 1 week
            reputation_multiplier: 10,
            resolution_period: Duration::from_secs(60),
            expected_block_speed: Some(Duration::from_secs(60 * 10)),
        }
    }

    /// Returns a ReputationTracker with 100 general slots and 100_00 msat of general liquidity.
    fn get_test_tracker() -> OutgoingChannel {
        OutgoingChannel::new(
            get_test_params(),
            BucketParameters {
                slot_count: 100,
                liquidity_msat: 100_000,
            },
            BucketParameters {
                slot_count: 30,
                liquidity_msat: 50_000,
            },
        )
        .unwrap()
    }

    fn get_test_htlc(endorsed: EndorsementSignal, fee_msat: u64) -> InFlightHtlc {
        InFlightHtlc {
            outgoing_channel_id: 1,
            hold_blocks: 1000,
            outgoing_amt_msat: 2000,
            fee_msat,
            added_instant: Instant::now(),
            incoming_endorsed: endorsed,
            bucket: ResourceBucketType::General,
        }
    }

    #[test]
    fn test_opportunity_cost() {
        let params = get_test_params();
        // Less than resolution_period has zero cost.
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(10)), 0);

        // Equal to resolution_period or within one period is equal to fee.
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(60)), 100);
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(65)), 100);

        // Multiple periods above resolution_period charges multiples of fee.
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(600)), 1000);
    }

    #[test]
    fn test_effective_fees() {
        let params = get_test_params();
        let fast_resolve = params.resolution_period / 2;
        let slow_resolve = params.resolution_period * 3;

        let cases = vec![
            (
                1000,
                fast_resolve,
                EndorsementSignal::Endorsed,
                true,
                Ok(1000),
            ),
            (
                1000,
                slow_resolve,
                EndorsementSignal::Endorsed,
                true,
                Ok(-2000),
            ),
            (
                1000,
                fast_resolve,
                EndorsementSignal::Endorsed,
                false,
                Ok(0),
            ),
            (
                1000,
                slow_resolve,
                EndorsementSignal::Endorsed,
                false,
                Ok(-3000),
            ),
            (
                1000,
                fast_resolve,
                EndorsementSignal::Unendorsed,
                true,
                Ok(1000),
            ),
            (
                1000,
                slow_resolve,
                EndorsementSignal::Unendorsed,
                true,
                Ok(0),
            ),
            (
                1000,
                fast_resolve,
                EndorsementSignal::Unendorsed,
                false,
                Ok(0),
            ),
            (
                1000,
                slow_resolve,
                EndorsementSignal::Unendorsed,
                false,
                Ok(0),
            ),
        ];

        for (fee_msat, hold_time, endorsed, settled, expected) in cases {
            let result = params.effective_fees(fee_msat, hold_time, endorsed, settled);
            assert_eq!(result, expected, "Case failed: fee_msat={fee_msat:?}, hold_time={hold_time:?}, endorsed={endorsed:?}, settled={settled:?}");
        }
    }

    /// Tests update of outgoing reputation when htlcs are removed.
    #[test]
    fn test_remove_htlc() {
        let mut tracker = get_test_tracker();
        let htlc_1 = get_test_htlc(EndorsementSignal::Endorsed, 1000);

        tracker
            .remove_outgoing_htlc(&htlc_1, ForwardResolution::Settled, htlc_1.added_instant)
            .unwrap();

        assert_eq!(
            tracker.outgoing_reputation(htlc_1.added_instant).unwrap(),
            htlc_1.fee_msat as i64
        );

        let htlc_2 = get_test_htlc(EndorsementSignal::Endorsed, 5000);
        tracker
            .remove_outgoing_htlc(
                &htlc_2.clone().into(),
                ForwardResolution::Failed,
                htlc_2.added_instant,
            )
            .unwrap();

        assert_eq!(
            tracker.outgoing_reputation(htlc_1.added_instant).unwrap(),
            htlc_1.fee_msat as i64,
        );
    }
}
