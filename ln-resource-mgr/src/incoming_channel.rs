use std::time::Instant;

use crate::htlc_manager::InFlightHtlc;
use crate::{ReputationParams, ResourceBucketType};

/// Tracks information about the usage of the channels when it is utilized as the incoming direction in a htlc forward.
#[derive(Debug)]
pub(super) struct IncomingChannel {
    params: ReputationParams,
    /// Tracks the last instant that the incoming channel misused use of congested resources, if any.
    last_congestion_misuse: Option<Instant>,
}

impl IncomingChannel {
    pub(super) fn new(params: ReputationParams) -> Self {
        Self {
            params,
            last_congestion_misuse: None,
        }
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

    /// Resolves an in flight htlc, updating use of congestion resources to reflect misuse, if any.
    pub(super) fn remove_incoming_htlc(&mut self, in_flight: &InFlightHtlc, resolved_ins: Instant) {
        if in_flight.bucket == ResourceBucketType::Congestion
            && resolved_ins.duration_since(in_flight.added_instant) >= self.params.resolution_period
        {
            self.last_congestion_misuse = Some(resolved_ins)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::IncomingChannel;
    use crate::htlc_manager::InFlightHtlc;
    use crate::{AccountableSignal, ReputationParams, ResourceBucketType};

    #[test]
    fn test_no_congestion_abuse() {
        let now = Instant::now();
        let params = ReputationParams {
            revenue_window: Duration::from_secs(60 * 60 * 24 * 14),
            reputation_multiplier: 12,
            resolution_period: Duration::from_secs(90),
            expected_block_speed: None,
        };
        let mut incoming_channel = IncomingChannel::new(params);

        assert!(incoming_channel.no_congestion_misuse(now));

        // Fast resolving HTLC does not trigger misuse.
        incoming_channel.remove_incoming_htlc(
            &InFlightHtlc {
                outgoing_channel_id: 1,
                fee_msat: 100,
                hold_blocks: 40,
                outgoing_amt_msat: 5000,
                added_instant: now,
                accountable: AccountableSignal::Accountable,
                bucket: ResourceBucketType::Congestion,
            },
            now.checked_add(params.resolution_period / 2).unwrap(),
        );
        assert!(incoming_channel.no_congestion_misuse(now));

        // Slow resolving HTLC does trigger misuse.
        let last_misuse = now.checked_add(params.resolution_period * 2).unwrap();
        incoming_channel.remove_incoming_htlc(
            &InFlightHtlc {
                outgoing_channel_id: 1,
                fee_msat: 100,
                hold_blocks: 40,
                outgoing_amt_msat: 5000,
                added_instant: now,
                accountable: AccountableSignal::Accountable,
                bucket: ResourceBucketType::Congestion,
            },
            last_misuse,
        );
        assert!(!incoming_channel.no_congestion_misuse(now));

        // Only recover once the cooldown period has fully passed.
        let half_recovered = last_misuse.checked_add(params.revenue_window / 2).unwrap();
        assert!(!incoming_channel.no_congestion_misuse(half_recovered));

        let fully_recovered = last_misuse.checked_add(params.revenue_window).unwrap();
        assert!(!incoming_channel.no_congestion_misuse(fully_recovered));
    }
}
