//! Tracks the gross cost incurred by the attacker over the course of a simulation.

use std::sync::atomic::{AtomicU64, Ordering};

use tokio_util::task::TaskTracker;

/// Approximate on-chain cost of opening a single channel, in msat (~200 sat). This is a rough
/// flat estimate; the real cost varies with fee rates and channel size.
pub const APPROX_CHANNEL_OPEN_COST_MSAT: u64 = 200_000;

/// Approximate on-chain cost the attacker pays to open `channels` channels in the graph.
pub fn channel_open_cost_msat(channels: usize) -> u64 {
    channels as u64 * APPROX_CHANNEL_OPEN_COST_MSAT
}

/// Accumulates the gross cost of attacker-dispatched payments during a simulation.
///
/// Channel-opening costs are tracked separately (graph channels are counted from the
/// attacktime network, jam-helper channels from [`super::AttackStatisitcs`]); this struct
/// covers only the fees paid on payments the attacker dispatches.
///
/// All counters increase monotonically, so atomics let the central payment-dispatch helper
/// record cost without holding an async lock.
#[derive(Debug, Default)]
pub struct AttackCost {
    payments_dispatched: AtomicU64,
    payments_succeeded: AtomicU64,
    success_case_fees_msat: AtomicU64,
    unconditional_fees_msat: AtomicU64,
    /// Tracks the background tasks that record each payment's resolution, so the simulation can
    /// wait for every in-flight payment's cost to be recorded before the totals are read.
    payment_tracker: TaskTracker,
}

impl AttackCost {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a payment that entered the network. Every dispatched payment incurs an
    /// unconditional fee of 1% of its routing fees, regardless of whether it later succeeds.
    pub fn record_dispatch(&self, fees_msat: u64) {
        self.payments_dispatched.fetch_add(1, Ordering::Relaxed);
        self.unconditional_fees_msat
            .fetch_add(fees_msat / 100, Ordering::Relaxed);
    }

    /// Records that a previously-dispatched payment succeeded, adding the success-case routing
    /// fees the attacker paid for it. Must be called at most once per [`Self::record_dispatch`].
    pub fn record_success(&self, fees_msat: u64) {
        self.payments_succeeded.fetch_add(1, Ordering::Relaxed);
        self.success_case_fees_msat
            .fetch_add(fees_msat, Ordering::Relaxed);
    }

    pub fn payments_dispatched(&self) -> u64 {
        self.payments_dispatched.load(Ordering::Relaxed)
    }

    pub fn payments_succeeded(&self) -> u64 {
        self.payments_succeeded.load(Ordering::Relaxed)
    }

    pub fn success_case_fees_msat(&self) -> u64 {
        self.success_case_fees_msat.load(Ordering::Relaxed)
    }

    pub fn unconditional_fees_msat(&self) -> u64 {
        self.unconditional_fees_msat.load(Ordering::Relaxed)
    }

    /// Total payment fees paid by the attacker: success-case fees plus unconditional fees.
    pub fn total_payment_fees_msat(&self) -> u64 {
        self.success_case_fees_msat() + self.unconditional_fees_msat()
    }

    /// The tracker that background payment-resolution tasks are spawned onto.
    pub(crate) fn tracker(&self) -> &TaskTracker {
        &self.payment_tracker
    }

    /// Waits for every in-flight attacker payment to resolve so the recorded cost is final. No
    /// payments should be dispatched after this is called; it must run before the cost totals
    /// are read.
    pub async fn wait_for_pending_payments(&self) {
        self.payment_tracker.close();
        self.payment_tracker.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{channel_open_cost_msat, AttackCost};

    /// Each opened channel costs a flat ~200 sat (200_000 msat) on-chain estimate.
    #[test]
    fn test_channel_open_cost() {
        assert_eq!(channel_open_cost_msat(0), 0);
        assert_eq!(channel_open_cost_msat(1), 200_000);
        assert_eq!(channel_open_cost_msat(5), 1_000_000);
    }

    /// A dispatched payment is counted and charged 1% of its routing fees as an unconditional
    /// fee, with no success-case fees until it is recorded as succeeding.
    #[test]
    fn test_record_dispatch_charges_unconditional_fee() {
        let cost = AttackCost::new();
        cost.record_dispatch(100_000);

        assert_eq!(cost.payments_dispatched(), 1);
        assert_eq!(cost.unconditional_fees_msat(), 1_000);
        assert_eq!(cost.payments_succeeded(), 0);
        assert_eq!(cost.success_case_fees_msat(), 0);
    }

    /// A succeeding payment is charged both its full routing fees and the unconditional fee.
    #[test]
    fn test_record_success_charges_success_case_fees() {
        let cost = AttackCost::new();
        cost.record_dispatch(100_000);
        cost.record_success(100_000);

        assert_eq!(cost.payments_succeeded(), 1);
        assert_eq!(cost.success_case_fees_msat(), 100_000);
        assert_eq!(cost.total_payment_fees_msat(), 101_000);
    }

    /// The unconditional fee is 1% truncated to whole msat, so fees under 100 msat round to zero.
    #[test]
    fn test_unconditional_fee_truncates() {
        let cost = AttackCost::new();
        cost.record_dispatch(150);
        cost.record_dispatch(99);

        assert_eq!(cost.payments_dispatched(), 2);
        assert_eq!(cost.unconditional_fees_msat(), 1);
    }

    /// Costs accumulate across many payments where only some succeed.
    #[test]
    fn test_accumulates_across_payments() {
        let cost = AttackCost::new();
        cost.record_dispatch(50_000);
        cost.record_dispatch(50_000);
        cost.record_dispatch(50_000);
        cost.record_success(50_000);

        assert_eq!(cost.payments_dispatched(), 3);
        assert_eq!(cost.payments_succeeded(), 1);
        assert_eq!(cost.success_case_fees_msat(), 50_000);
        assert_eq!(cost.unconditional_fees_msat(), 1_500);
        assert_eq!(cost.total_payment_fees_msat(), 51_500);
    }
}
