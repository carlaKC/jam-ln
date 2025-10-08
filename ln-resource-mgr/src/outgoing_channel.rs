use std::ops::Sub;
use std::time::Instant;

use crate::decaying_average::DecayingAverage;
use crate::htlc_manager::{InFlightHtlc, ReputationParams};
use crate::{ForwardResolution, ReputationError, ResourceBucketType};

/// Tracks information about the usage of a channel when it utilized as the outgoing direction in
/// a htlc forward.
#[derive(Clone, Debug)]
pub(super) struct OutgoingChannel {
    params: ReputationParams,

    /// The reputation that the channel has accrued as the outgoing link in htlc forwards. Tracked as a decaying
    /// average over the reputation_window that the tracker is created with.
    outgoing_reputation: DecayingAverage,

    /// Tracks the last instant that the outgoing channel misused congested resources, if any.
    last_congestion_misuse: Option<Instant>,
}

impl OutgoingChannel {
    pub(super) fn new(
        params: ReputationParams,
        outgoing_reputation: Option<(i64, Instant)>,
    ) -> Result<Self, ReputationError> {
        if params.reputation_multiplier <= 1 {
            return Err(ReputationError::ErrInvalidMultiplier);
        }
        let outgoing_reputation = match outgoing_reputation {
            Some(value) => {
                let mut reputation = DecayingAverage::new(
                    params.revenue_window * params.reputation_multiplier.into(),
                );
                reputation.add_value(value.0, value.1)?;
                reputation
            }
            None => {
                DecayingAverage::new(params.revenue_window * params.reputation_multiplier.into())
            }
        };

        Ok(Self {
            params,
            outgoing_reputation,
            last_congestion_misuse: None,
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

    /// Returns true if the channel has never misused congestion resources, or sufficient time has passed since last
    /// abuse (set by ReputationParams.revenue_window, as this is the period we can be jammed for).
    pub(super) fn no_congestion_misuse(&self, access_ins: Instant) -> bool {
        if let Some(instant) = self.last_congestion_misuse {
            access_ins.duration_since(instant) > self.params.revenue_window
        } else {
            true
        }
    }

    /// Removes an in flight htlc, updating reputation to reflect impact of resolution.
    pub(super) fn remove_outgoing_htlc(
        &mut self,
        in_flight: &InFlightHtlc,
        resolution: ForwardResolution,
        resolved_instant: Instant,
    ) -> Result<(), ReputationError> {
        if in_flight.bucket == ResourceBucketType::Congestion
            && resolved_instant.duration_since(in_flight.added_instant)
                >= self.params.resolution_period
        {
            self.last_congestion_misuse = Some(resolved_instant)
        }

        // Unaccountable payments only have a positive impact on reputation (no negative effective fees are applied)
        let settled = resolution == ForwardResolution::Settled;
        let effective_fees = self.params.effective_fees(
            in_flight.fee_msat,
            resolved_instant.sub(in_flight.added_instant),
            in_flight.outgoing_accountable,
            settled,
        )?;

        // Update reputation to reflect its reputation impact.
        self.outgoing_reputation
            .add_value(effective_fees, resolved_instant)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::htlc_manager::ReputationParams;
    use crate::{AccountableSignal, ForwardResolution, ResourceBucketType};

    use super::{InFlightHtlc, OutgoingChannel};

    fn get_test_params() -> ReputationParams {
        ReputationParams {
            revenue_window: Duration::from_secs(60 * 60 * 24), // 1 week
            reputation_multiplier: 10,
            resolution_period: Duration::from_secs(60),
            expected_block_speed: Some(Duration::from_secs(60 * 10)),
        }
    }

    fn get_test_htlc(
        accountable: AccountableSignal,
        fee_msat: u64,
        bucket: ResourceBucketType,
    ) -> InFlightHtlc {
        InFlightHtlc {
            outgoing_channel_id: 1,
            hold_blocks: 1000,
            incoming_amt_msat: 2000,
            fee_msat,
            added_instant: Instant::now(),
            outgoing_accountable: accountable,
            bucket,
        }
    }

    #[test]
    fn test_opportunity_cost() {
        let params = get_test_params();
        // Less than resolution_period has zero cost.
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(10)), 0);

        // Above resolution period it is gradually incremented.
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(61)), 2);
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(90)), 50);
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(120)), 100);

        // Multiple periods above resolution_period charges multiples of fee.
        assert_eq!(params.opportunity_cost(100, Duration::from_secs(600)), 900);
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
                AccountableSignal::Accountable,
                true,
                Ok(1000),
            ),
            (
                1000,
                slow_resolve,
                AccountableSignal::Accountable,
                true,
                Ok(-1000),
            ),
            (
                1000,
                Duration::from_secs(90),
                AccountableSignal::Accountable,
                true,
                Ok(500),
            ),
            (
                1000,
                fast_resolve,
                AccountableSignal::Accountable,
                false,
                Ok(0),
            ),
            (
                1000,
                slow_resolve,
                AccountableSignal::Accountable,
                false,
                Ok(-2000),
            ),
            (
                1000,
                fast_resolve,
                AccountableSignal::Unaccountable,
                true,
                Ok(1000),
            ),
            (
                1000,
                slow_resolve,
                AccountableSignal::Unaccountable,
                true,
                Ok(0),
            ),
            (
                1000,
                fast_resolve,
                AccountableSignal::Unaccountable,
                false,
                Ok(0),
            ),
            (
                1000,
                slow_resolve,
                AccountableSignal::Unaccountable,
                false,
                Ok(0),
            ),
        ];

        for (fee_msat, hold_time, accountable, settled, expected) in cases {
            let result = params.effective_fees(fee_msat, hold_time, accountable, settled);
            assert_eq!(result, expected, "Case failed: fee_msat={fee_msat:?}, hold_time={hold_time:?}, accountable={accountable:?}, settled={settled:?}");
        }
    }

    /// Tests update of outgoing reputation when htlcs are removed.
    #[test]
    fn test_remove_htlc() {
        let mut tracker = OutgoingChannel::new(get_test_params(), None).unwrap();
        let htlc_1 = get_test_htlc(
            AccountableSignal::Accountable,
            1000,
            ResourceBucketType::General,
        );

        tracker
            .remove_outgoing_htlc(&htlc_1, ForwardResolution::Settled, htlc_1.added_instant)
            .unwrap();

        assert_eq!(
            tracker.outgoing_reputation(htlc_1.added_instant).unwrap(),
            htlc_1.fee_msat as i64
        );

        let htlc_2 = get_test_htlc(
            AccountableSignal::Accountable,
            5000,
            ResourceBucketType::General,
        );
        tracker
            .remove_outgoing_htlc(&htlc_2, ForwardResolution::Failed, htlc_2.added_instant)
            .unwrap();

        assert_eq!(
            tracker.outgoing_reputation(htlc_1.added_instant).unwrap(),
            htlc_1.fee_msat as i64,
        );
    }

    #[test]
    fn test_no_congestion_abuse() {
        let now = Instant::now();
        let test_params = get_test_params();
        let mut outgoing_channel = OutgoingChannel::new(test_params, None).unwrap();
        assert!(outgoing_channel.no_congestion_misuse(now));

        let htlc_1 = get_test_htlc(
            AccountableSignal::Accountable,
            100,
            ResourceBucketType::Congestion,
        );

        // Fast resolving HTLC does not trigger misuse.
        outgoing_channel
            .remove_outgoing_htlc(
                &htlc_1,
                ForwardResolution::Settled,
                now.checked_add(test_params.resolution_period / 2).unwrap(),
            )
            .unwrap();
        assert!(outgoing_channel.no_congestion_misuse(now));

        let htlc_2 = get_test_htlc(
            AccountableSignal::Accountable,
            100,
            ResourceBucketType::Congestion,
        );

        // Slow resolving HTLC does trigger misuse.
        let last_misuse = now.checked_add(test_params.resolution_period * 2).unwrap();
        outgoing_channel
            .remove_outgoing_htlc(&htlc_2, ForwardResolution::Settled, last_misuse)
            .unwrap();
        assert!(!outgoing_channel.no_congestion_misuse(now));

        // Only recover once the cooldown period has fully passed.
        let half_recovered = last_misuse
            .checked_add(test_params.revenue_window / 2)
            .unwrap();
        assert!(!outgoing_channel.no_congestion_misuse(half_recovered));

        let fully_recovered = last_misuse.checked_add(test_params.revenue_window).unwrap();
        assert!(!outgoing_channel.no_congestion_misuse(fully_recovered));
    }
}
