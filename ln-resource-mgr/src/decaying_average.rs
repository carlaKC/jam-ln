use std::ops::Add;
use std::time::{Duration, Instant};

use crate::ReputationError;

/// Defines the operations required for values tracked in decaying averages that use a f64 decay
/// factor.
pub(super) trait DecayingAverageOps: Copy + Add<Output = Self> + Default {
    fn mul_f64(self, rhs: f64) -> Self;
    fn saturating_add(self, rhs: Self) -> Self;
}

impl DecayingAverageOps for i64 {
    fn mul_f64(self, rhs: f64) -> Self {
        (self as f64 * rhs).round() as i64
    }
    fn saturating_add(self, rhs: Self) -> Self {
        self.saturating_add(rhs)
    }
}

impl DecayingAverageOps for f64 {
    fn mul_f64(self, rhs: f64) -> Self {
        self * rhs
    }
    fn saturating_add(self, rhs: Self) -> Self {
        // f64 type has a specially defined infinity value, at which is just loses precision
        // rather than overflowing.
        self + rhs
    }
}

/// Tracks a timestamped decaying average, which may be positive or negative. Acts
#[derive(Clone, Debug)]
pub(super) struct DecayingAverage<T> {
    value: T,
    last_updated: Option<Instant>,
    decay_rate: f64,
}

impl<T> DecayingAverage<T>
where
    T: DecayingAverageOps,
{
    pub(super) fn new(period: Duration) -> Self {
        DecayingAverage {
            value: T::default(),
            last_updated: None,
            decay_rate: Self::calc_decay_rate(period),
        }
    }

    fn calc_decay_rate(period: Duration) -> f64 {
        0.5f64.powf(2.0 / period.as_secs_f64())
    }

    /// Decays the tracked value to its value at the instant provided and returns the updated value. The access_instant
    /// must be after the last_updated time of the decaying average, tolerant to nanosecond differences.
    pub(super) fn value_at_instant(
        &mut self,
        access_instant: Instant,
    ) -> Result<T, ReputationError> {
        if let Some(last_updated) = self.last_updated {
            // Enforce that the access_instant must be after the last update on our average, but tolerate nanosecond
            // differences - these will just reflect as an update with the same update as last_updated.
            if access_instant < last_updated
                && last_updated.duration_since(access_instant).as_secs() > 0
            {
                return Err(ReputationError::ErrUpdateInPast(
                    last_updated,
                    access_instant,
                ));
            }

            let elapsed = access_instant.duration_since(last_updated).as_secs_f64();
            self.value = self.value.mul_f64(self.decay_rate.powf(elapsed))
        }

        self.last_updated = Some(access_instant);
        Ok(self.value)
    }

    /// Updates the current value of the decaying average and then adds the new value provided. The value provided
    /// will act as a saturating add if it exceeds i64::MAX.
    pub(super) fn add_value(
        &mut self,
        value: T,
        update_time: Instant,
    ) -> Result<T, ReputationError> {
        // Progress current value to the new timestamp so that it'll be appropriately decayed.
        self.value_at_instant(update_time)?;

        // No need to decay the new value as we're now at our last updated time.
        self.value = self.value.saturating_add(value);
        self.last_updated = Some(update_time);
        Ok(self.value)
    }
}

#[cfg(test)]
mod tests {
    use crate::ReputationError;

    use super::DecayingAverage;
    use std::ops::Add;
    use std::time::{Duration, Instant};

    /// The set decay period that we generated test values for.
    const TEST_PERIOD: Duration = Duration::from_secs(100);

    /// Tests creation of a decaying average and values when no updates have been made.
    #[test]
    fn test_new_decaying_average() {
        let ins_0 = Instant::now();
        let mut avg = DecayingAverage::new(TEST_PERIOD);
        assert_eq!(avg.value_at_instant(ins_0).unwrap(), 0);

        let ins_1 = ins_0.add(Duration::from_secs(10));
        assert_eq!(avg.value_at_instant(ins_1).unwrap(), 0);

        let ins_2 = ins_0.add(Duration::from_secs(15));
        assert_eq!(avg.add_value(1000, ins_2).unwrap(), 1000);
    }

    /// Tests updating of decaying average at various intervals. Values for this test were independently generated.
    #[test]
    fn test_decaying_average_values() {
        let ins_0 = Instant::now();
        let mut avg = DecayingAverage::new(TEST_PERIOD);

        // Set initial value on average.
        let ins_1 = ins_0 + Duration::from_secs(1000);
        assert_eq!(avg.add_value(1000, ins_1).unwrap(), 1000);

        // Advance the clock a few times and assert decay as expected.
        let ins_2 = ins_1 + Duration::from_secs(25);
        assert_eq!(avg.value_at_instant(ins_2).unwrap(), 707,);

        let ins_3 = ins_2 + Duration::from_secs(3);
        assert_eq!(avg.value_at_instant(ins_3).unwrap(), 678);

        // Add value without advancing time.
        assert_eq!(avg.add_value(2300, ins_3).unwrap(), 2978);

        // Add value with advancing time.
        let ins_4 = ins_3 + Duration::from_secs(50);
        assert_eq!(avg.value_at_instant(ins_4).unwrap(), 1489);
    }

    /// Test that edge cases with maximum/minimum values are appropriately handled.
    #[test]
    fn test_average_bounds() {
        let ins_0 = Instant::now();
        let mut avg = DecayingAverage::new(TEST_PERIOD);
        assert_eq!(avg.add_value(100, ins_0).unwrap(), 100);

        // Expect decay to zero when 1000x the decay period has passed.
        let ins_1 = ins_0.add(TEST_PERIOD * 1000);
        assert_eq!(avg.value_at_instant(ins_1).unwrap(), 0);

        // A very large value is properly represented, but overflowing i64::MAX is saturating.
        let ins_2 = ins_1.add(Duration::from_secs(15));
        let large_value = i64::MAX / 2;
        assert_eq!(avg.add_value(large_value, ins_2).unwrap(), large_value);
        assert_eq!(avg.add_value(i64::MAX, ins_2).unwrap(), i64::MAX);
    }

    // Tests that we can't update the decaying average with values in the past, but tolerate nanosecond differences and
    // treat them as an update at the current time.
    #[test]
    fn test_update_in_past_tolerance() {
        let ins_0 = Instant::now();
        let ins_1 = ins_0.add(Duration::from_secs(1));

        let mut avg = DecayingAverage::new(TEST_PERIOD);
        assert_eq!(avg.add_value(100, ins_1).unwrap(), 100);

        // One second in the past is above our tolerance, should fail.
        assert!(matches!(
            avg.add_value(500, ins_0),
            Err(ReputationError::ErrUpdateInPast(_, _))
        ));
        assert_eq!(avg.value_at_instant(ins_1).unwrap(), 100);

        // Half a second in the past is within our tolerance, should update average.
        let ins_2 = ins_0.add(Duration::from_secs(1) / 2);
        assert_eq!(avg.add_value(150, ins_2).unwrap(), 250);

        // One second in the future should decay our existing value.
        let ins_4 = ins_1.add(Duration::from_secs(1));
        assert!(avg.value_at_instant(ins_4).unwrap() < 250);
    }
}
