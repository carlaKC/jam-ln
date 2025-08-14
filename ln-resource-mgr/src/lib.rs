mod decaying_average;
pub mod forward_manager;
pub use htlc_manager::ReputationParams;
mod htlc_manager;
mod incoming_channel;
mod outgoing_channel;

use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::time::Instant;

/// The total supply of bitcoin expressed in millisatoshis.
const SUPPLY_CAP_MSAT: u64 = 21000000 * 100000000 * 1000;

/// The minimum size of the liquidity limit placed on htlcs that use congestion resources. This is
/// in place to prevent smaller channels from having unusably small liquidity limits.
const MINIMUM_CONGESTION_SLOT_LIQUDITY: u64 = 15_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReputationError {
    /// Indicates that the library has encountered an unrecoverable error.
    ErrUnrecoverable(String),
    /// Indicates that the incoming channel was not found.
    ErrIncomingNotFound(u64),
    /// Indicates that the outgoing channel was not found.
    ErrOutgoingNotFound(u64),
    /// Indicates that the htlc reference provided was not found.
    ErrForwardNotFound(u64, HtlcRef),
    /// Decaying average updated with an instant that is after the last time it was updated.
    ErrUpdateInPast(Instant, Instant),
    /// Htlc has been added twice.
    ErrDuplicateHtlc(HtlcRef),
    // Multiplier on revenue window is invalid.
    ErrInvalidMultiplier,
    /// The htlc amount exceeds the bitcoin supply cap.
    ErrAmountExceedsSupply(u64),
    /// Htlc has a negative fee.
    ErrNegativeFee(u64, u64),
    /// Htlc has a negative cltv delta.
    ErrNegativeCltvDelta(u32, u32),
    /// Channel has already been added.
    ErrChannelExists(u64),
    /// Channel has already been removed or was never tracked.
    ErrChannelNotFound(u64),
    /// Channel capacity does not match capacity in channel snapshot.
    ErrChannelCapacityMismatch(u64, u64),
    /// A HTLC has been removed from a bucket that doesn't hold enough for it to be removed.
    ErrBucketTooEmpty(u64),
}

impl Error for ReputationError {}

impl Display for ReputationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReputationError::ErrUnrecoverable(e) => write!(f, "unrecoverable error: {e}"),
            ReputationError::ErrIncomingNotFound(chan_id) => {
                write!(f, "incoming channel {chan_id} not found")
            }
            ReputationError::ErrOutgoingNotFound(chan_id) => {
                write!(f, "outgoing channel {chan_id} not found")
            }
            ReputationError::ErrForwardNotFound(chan_id, htlc_ref) => write!(
                f,
                "Outgoing htlc on {} with incoming ref {}:{} not found",
                chan_id, htlc_ref.channel_id, htlc_ref.htlc_index
            ),
            ReputationError::ErrUpdateInPast(last, given) => {
                write!(
                    f,
                    "last updated reputation at {:?}, read at {:?}",
                    last, given
                )
            }
            ReputationError::ErrDuplicateHtlc(htlc_ref) => {
                write!(
                    f,
                    "duplicated htlc {}:{}",
                    htlc_ref.channel_id, htlc_ref.htlc_index
                )
            }
            ReputationError::ErrInvalidMultiplier => write!(f, "invalid multiplier"),
            ReputationError::ErrAmountExceedsSupply(amt) => {
                write!(f, "msat amount {amt} exceeds bitcoin supply")
            }
            ReputationError::ErrNegativeFee(incoming, outgoing) => {
                write!(f, "incoming amount: {incoming} < outgoing {outgoing}")
            }
            ReputationError::ErrNegativeCltvDelta(incoming, outgoing) => {
                write!(f, "incoming cltv: {incoming} < outgoing {outgoing}")
            }
            ReputationError::ErrChannelExists(chan_id) => {
                write!(f, "channel {chan_id} already exists")
            }
            ReputationError::ErrChannelNotFound(chan_id) => {
                write!(f, "channel {chan_id} not found")
            }
            ReputationError::ErrChannelCapacityMismatch(capacity, snapshot_capacity) => {
                write!(f, "channel capacity {capacity} does not match snapshot capacity {snapshot_capacity}")
            }
            ReputationError::ErrBucketTooEmpty(amt_msat) => {
                write!(
                    f,
                    "HTLC amount {amt_msat} has been removed from bucket that doesn't contain it"
                )
            }
        }
    }
}

/// The different possible accountable signals on a htlc's update_add message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AccountableSignal {
    Unaccountable,
    Accountable,
}

impl Display for AccountableSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountableSignal::Accountable => write!(f, "accountable"),
            AccountableSignal::Unaccountable => write!(f, "unaccountable"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ForwardingOutcome {
    /// Forward the outgoing htlc with the accountable signal provided.
    Forward(AccountableSignal),
    /// Fail the incoming htlc back with the reason provided.
    Fail(FailureReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccessForwardOutcome {
    pub bucket: ResourceBucketType,
    pub accountable_signal: AccountableSignal,
}

impl Display for ForwardingOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardingOutcome::Forward(e) => write!(f, "forward as {e}"),
            ForwardingOutcome::Fail(r) => write!(f, "fail due to {r}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum FailureReason {
    /// There is no space in the incoming channel's general resource bucket, which is all the HTLC
    /// is eligible to use, so the htlc should be failed back.
    NoGeneralResources,
    /// There are no resources on the incoming channel, on any resource bucket, so the htlc should
    /// be failed back.
    NoResources,
    /// The outgoing peer has insufficient reputation for the htlc to occupy protected resources.
    NoReputation,
    /// The upgradable signal has been tampered with so we should fail back the htlc.
    UpgradableSignalModified,
}

/// A snapshot of the outgoing reputation and resources available for a forward.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AllocationCheck {
    /// The reputation values used to compare the incoming channel's revenue to the outgoing channel's reputation for
    /// the htlc proposed.
    pub reputation_check: ReputationCheck,
    /// Indicates whether the outgoing channel may use general resources for the HTLC.
    pub general_eligible: bool,
    /// Indicates whether the outgoing channel is eligible to consume congestion resources.
    pub congestion_eligible: bool,
    /// The resources available on the incoming channel.
    pub resource_check: ResourceCheck,
}

/// Represents the different resource buckets that htlcs can be assigned to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ResourceBucketType {
    Protected,
    Congestion,
    General,
}

impl ResourceBucketType {
    fn accountable_signal(&self) -> AccountableSignal {
        match self {
            ResourceBucketType::General => AccountableSignal::Unaccountable,
            ResourceBucketType::Congestion => AccountableSignal::Accountable,
            ResourceBucketType::Protected => AccountableSignal::Accountable,
        }
    }
}

impl AllocationCheck {
    /// The recommended action to be taken for the htlc forward.
    pub fn forwarding_outcome(
        &self,
        htlc_amt_msat: u64,
        incoming_accountable: AccountableSignal,
        incoming_upgradable: bool,
    ) -> ForwardingOutcome {
        match self.inner_forwarding_outcome(
            htlc_amt_msat,
            incoming_accountable,
            incoming_upgradable,
        ) {
            Ok(fwd_success) => ForwardingOutcome::Forward(fwd_success.accountable_signal),
            Err(fail_reason) => ForwardingOutcome::Fail(fail_reason),
        }
    }

    /// Returns the bucket assignment or failure reason for a htlc.
    // This forwarding outcome method is only made public for analysis purposes to report the
    // bucket outcome of the htlc.
    pub fn inner_forwarding_outcome(
        &self,
        htlc_amt_msat: u64,
        incoming_accountable: AccountableSignal,
        incoming_upgradable: bool,
    ) -> Result<SuccessForwardOutcome, FailureReason> {
        if !incoming_upgradable && incoming_accountable == AccountableSignal::Accountable {
            return Err(FailureReason::UpgradableSignalModified);
        }

        let bucket =
            self.bucket_outcome(htlc_amt_msat, incoming_accountable, incoming_upgradable)?;

        // If the incoming htlc is accountable, set as accountable regardless of which bucket it
        // was assigned.
        let accountable_signal = if incoming_accountable == AccountableSignal::Accountable {
            AccountableSignal::Accountable
        } else {
            bucket.accountable_signal()
        };

        Ok(SuccessForwardOutcome {
            bucket,
            accountable_signal,
        })
    }

    fn bucket_outcome(
        &self,
        htlc_amt_msat: u64,
        incoming_accountable: AccountableSignal,
        incoming_upgradable: bool,
    ) -> Result<ResourceBucketType, FailureReason> {
        let protected_resources_available = self
            .resource_check
            .protected_bucket
            .resources_available(htlc_amt_msat);

        let general_resources_available = self
            .resource_check
            .general_bucket
            .resources_available(htlc_amt_msat);

        match incoming_accountable {
            // When a HTLC is accountable, our reputation will be impacted by its resolution so
            // we drop it if the outgoing peer does not have sufficient reputation. The HTLC is
            // otherwise eligible to use any other bucket, provided it meets its restrictions.
            // We prefer the protected bucket so that we leave more space in general for peers
            // that don't have reputation, but will fall back in the unlikely case where
            // protected is full. We keep our eligibility requirements for general and congestion
            // buckets because it's possible that this peer is the one that's filling up our
            // resources, so we don't do them any additional favors beyond protected resources.
            AccountableSignal::Accountable => {
                if self.reputation_check.sufficient_reputation() {
                    if protected_resources_available {
                        Ok(ResourceBucketType::Protected)
                    } else if general_resources_available && self.general_eligible {
                        Ok(ResourceBucketType::General)
                    } else if incoming_upgradable
                        && self.congestion_eligible
                        && self.congestion_resources_available(htlc_amt_msat)
                    {
                        Ok(ResourceBucketType::Congestion)
                    } else {
                        Err(FailureReason::NoResources)
                    }
                } else {
                    Err(FailureReason::NoReputation)
                }
            }
            // When a HTLC is unaccountable, we have the option to upgrade it to accountable and
            // use protected resources if the peer has sufficient reputation. We'll only do this
            // if the peer can't use general resources, as upgrading to accountable will subject
            // downstream forwarding to stricter conditions (ie, being dropped if there isn't
            // reputation down the path).
            AccountableSignal::Unaccountable => {
                if general_resources_available && self.general_eligible {
                    Ok(ResourceBucketType::General)
                } else if self.reputation_check.sufficient_reputation()
                    && protected_resources_available
                    && incoming_upgradable
                {
                    Ok(ResourceBucketType::Protected)
                } else if incoming_upgradable
                    && self.congestion_eligible
                    && self.congestion_resources_available(htlc_amt_msat)
                {
                    Ok(ResourceBucketType::Congestion)
                } else {
                    Err(FailureReason::NoGeneralResources)
                }
            }
        }
    }

    /// If our general bucket is full, we'll consider a spot in our "congestion" bucket for the forward, because it's
    /// likely that we're under attack of some kind. This bucket is very strictly controlled -- liquidity is equally
    /// shared between slots (and no htlc can use more than this allocation) and the sending channel may only utilize
    /// one slot at a time.
    fn congestion_resources_available(&self, htlc_amt_msat: u64) -> bool {
        // If the congestion bucket is completely disabled by setting liquidity or slots to zero,
        // resources are not available.
        if self.resource_check.congestion_bucket.slots_available == 0
            || self
                .resource_check
                .congestion_bucket
                .liquidity_available_msat
                == 0
        {
            return false;
        }

        if self
            .resource_check
            .general_bucket
            .resources_available(htlc_amt_msat)
            || !self.congestion_eligible
            || !self
                .resource_check
                .congestion_bucket
                .resources_available(htlc_amt_msat)
        {
            return false;
        }

        // Divide liquidity in congestion bucket evenly between slots, unless the amount would be less than a
        // reasonable minimum amount.
        let liquidity_limit = u64::max(
            self.resource_check
                .congestion_bucket
                .liquidity_available_msat
                / self.resource_check.congestion_bucket.slots_available as u64,
            MINIMUM_CONGESTION_SLOT_LIQUDITY,
        );

        htlc_amt_msat <= liquidity_limit
    }
}

/// A snapshot of a reputation check for a htlc forward.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReputationCheck {
    pub reputation: i64,
    pub revenue_threshold: i64,
    pub in_flight_total_risk: u64,
    pub htlc_risk: u64,
}

impl ReputationCheck {
    /// Returns a boolean indicating whether the channel has sufficient reputation for this htlc to be
    /// forwarded.
    pub fn sufficient_reputation(&self) -> bool {
        self.reputation
            .saturating_sub(i64::try_from(self.in_flight_total_risk).unwrap_or(i64::MAX))
            .saturating_sub(i64::try_from(self.htlc_risk).unwrap_or(i64::MAX))
            > self.revenue_threshold
    }
}

/// A snapshot of the resource values to do a check on a htlc forward.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceCheck {
    pub general_bucket: BucketResources,
    pub congestion_bucket: BucketResources,
    pub protected_bucket: BucketResources,
}

/// Describes the resources currently used in a bucket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BucketResources {
    pub slots_used: u16,
    pub slots_available: u16,
    pub liquidity_used_msat: u64,
    pub liquidity_available_msat: u64,
}

impl BucketResources {
    fn resources_available(&self, htlc_amt_msat: u64) -> bool {
        if self.liquidity_used_msat + htlc_amt_msat > self.liquidity_available_msat {
            return false;
        }

        if self.slots_used + 1 > self.slots_available {
            return false;
        }

        true
    }
}

impl Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureReason::NoGeneralResources => write!(f, "no general resources"),
            FailureReason::NoResources => write!(f, "no resources"),
            FailureReason::NoReputation => write!(f, "no reputation"),
            FailureReason::UpgradableSignalModified => {
                write!(f, "upgradable signal has been modified")
            }
        }
    }
}

/// The resolution for a htlc received from the upstream peer (or decided locally).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardResolution {
    Settled,
    Failed,
}

impl From<bool> for ForwardResolution {
    fn from(settled: bool) -> Self {
        if settled {
            ForwardResolution::Settled
        } else {
            ForwardResolution::Failed
        }
    }
}

impl Display for ForwardResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardResolution::Settled => write!(f, "settled"),
            ForwardResolution::Failed => write!(f, "failed"),
        }
    }
}

/// A unique identifier for a htlc on a channel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct HtlcRef {
    pub channel_id: u64,
    /// The unique index used to refer to the htlc in update_add_htlc.
    pub htlc_index: u64,
}

/// A htlc that has been locked in on the incoming link and is proposed for outgoing forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedForward {
    pub incoming_ref: HtlcRef,
    pub outgoing_channel_id: u64,
    pub amount_in_msat: u64,
    pub amount_out_msat: u64,
    pub expiry_in_height: u32,
    pub expiry_out_height: u32,
    pub added_at: Instant,
    pub incoming_accountable: AccountableSignal,
    pub upgradable_accountability: bool,
}

impl Display for ProposedForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} {} -> {} with fee {} ({} -> {}) and cltv {} ({} -> {})",
            self.incoming_ref.channel_id,
            self.incoming_ref.htlc_index,
            self.incoming_accountable,
            self.outgoing_channel_id,
            self.amount_in_msat - self.amount_out_msat,
            self.amount_in_msat,
            self.amount_out_msat,
            self.expiry_in_height - self.expiry_out_height,
            self.expiry_in_height,
            self.expiry_out_height
        )
    }
}

impl ProposedForward {
    fn validate(&self) -> Result<(), ReputationError> {
        let _ = validate_msat(self.amount_out_msat)?;
        let _ = validate_msat(self.amount_in_msat)?;

        if self.amount_out_msat > self.amount_in_msat {
            return Err(ReputationError::ErrNegativeFee(
                self.amount_in_msat,
                self.amount_out_msat,
            ));
        }

        if self.expiry_in_height < self.expiry_out_height {
            return Err(ReputationError::ErrNegativeCltvDelta(
                self.expiry_in_height,
                self.expiry_out_height,
            ));
        }

        Ok(())
    }

    /// Only underflow safe after validation.
    fn fee_msat(&self) -> u64 {
        self.amount_in_msat - self.amount_out_msat
    }
}

/// Provides a snapshot of the reputation and revenue values tracked for a channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelSnapshot {
    pub capacity_msat: u64,
    pub outgoing_reputation: i64,
    pub bidirectional_revenue: i64,
}

/// Validates that an msat amount doesn't exceed the total supply cap of bitcoin and casts to i64 to be used in
/// places where we're dealing with negative numbers. Once we've validated that we're below the supply cap, we can
/// safely cast to i64 because [`u64::Max`] < total bitcoin supply cap.
pub fn validate_msat(amount_msat: u64) -> Result<i64, ReputationError> {
    debug_assert!(
        SUPPLY_CAP_MSAT < i64::MAX as u64,
        "supply cap: {SUPPLY_CAP_MSAT} overflows i64"
    );

    if amount_msat > SUPPLY_CAP_MSAT {
        return Err(ReputationError::ErrAmountExceedsSupply(amount_msat));
    }

    Ok(i64::try_from(amount_msat).unwrap_or(i64::MAX))
}

pub trait ReputationManager {
    /// Should be called to add a channel to the manager to track its reputation and revenue, must be called before
    /// any calls to [`get_forwarding_outcome`] or [`add_htlc`] reference the channel.
    fn add_channel(
        &self,
        channel_id: u64,
        capacity_msat: u64,
        add_ins: Instant,
        channel_reputation: Option<ChannelSnapshot>,
    ) -> Result<(), ReputationError>;

    /// Called to clean up a channel once it has been closed and is no longer usable for htlc forwards.
    fn remove_channel(&self, channel_id: u64) -> Result<(), ReputationError>;

    /// Returns a forwarding assessment for the proposed HTLC based on its accountable status and the reputation of
    /// the incoming and outgoing channel. This call can optionally be used to co-locate reputation checks with
    /// other forwarding checks (such as fee policies and expiry delta) so that the htlc can be failed early, saving
    /// the need to propagate it to the outgoing link. Using this method *does not* replace the need to call
    /// [`add_htlc`] before sending `update_add_htlc` on the outgoing link.
    /// NOTE: Use before [`add_htlc`]. The outcome will be different if the HTLC has already been
    /// added.
    fn get_allocation_snapshot(
        &self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError>;

    /// Checks the accountable signal and reputation of a proposed forward to determine whether a htlc should be
    /// forwarded on the outgoing link. If the htlc can be forwarded, it will be added to the internal state of
    /// the [`ReputationManager`], and it *must* be cleared out using [`resolve_htlc`]. If the htlc cannot
    /// be forwarded, no further action is expected. The [`outgoing_ref`] provided for the outgoing htlc *must*
    /// match `update_add_htlc` (so validation and non-strict forwarding logic must be applied before).
    ///
    /// Note that this API is not currently replay-safe, so any htlcs that are replayed on restart will return
    /// [`ReputationError::ErrDuplicateHtlc`].
    fn add_htlc(&self, forward: &ProposedForward) -> Result<ForwardingOutcome, ReputationError>;

    /// Resolves a htlc that was previously added using [`add_htlc`], returning
    /// [`ReputationError::ErrForwardNotFound`] if the htlc is not found.
    fn resolve_htlc(
        &self,
        outgoing_channel: u64,
        incoming_ref: HtlcRef,
        resolution: ForwardResolution,
        resolved_instant: Instant,
    ) -> Result<(), ReputationError>;

    /// Provides snapshots of per channel at the instant provided.
    fn list_channels(
        &self,
        access_ins: Instant,
    ) -> Result<HashMap<u64, ChannelSnapshot>, ReputationError>;
}

#[cfg(test)]
mod tests {
    use crate::{
        AccountableSignal, AllocationCheck, BucketResources, FailureReason, ReputationCheck,
        ResourceBucketType, ResourceCheck, SuccessForwardOutcome, MINIMUM_CONGESTION_SLOT_LIQUDITY,
    };

    /// Returns an AllocationCheck which is eligible for congestion resources.
    fn test_congestion_check() -> AllocationCheck {
        let check = AllocationCheck {
            reputation_check: ReputationCheck {
                reputation: 0,
                revenue_threshold: 0,
                in_flight_total_risk: 0,
                htlc_risk: 0,
            },
            general_eligible: true,
            congestion_eligible: true,
            resource_check: ResourceCheck {
                general_bucket: BucketResources {
                    slots_used: 10,
                    slots_available: 10,
                    liquidity_used_msat: 0,
                    liquidity_available_msat: 200_000_000,
                },
                congestion_bucket: BucketResources {
                    slots_used: 0,
                    slots_available: 10,
                    liquidity_used_msat: 0,
                    liquidity_available_msat: MINIMUM_CONGESTION_SLOT_LIQUDITY * 20,
                },
                protected_bucket: BucketResources {
                    slots_used: 0,
                    slots_available: 10,
                    liquidity_used_msat: 0,
                    liquidity_available_msat: 300_000_000,
                },
            },
        };
        assert!(check.congestion_resources_available(10));
        check
    }

    #[test]
    fn test_congestion_not_eligible() {
        let mut check = test_congestion_check();
        check.congestion_eligible = false;
        assert!(!check.congestion_resources_available(100));
    }

    #[test]
    fn test_congestion_general_available() {
        let mut check = test_congestion_check();
        check.resource_check.general_bucket.slots_used = 0;
        assert!(!check.congestion_resources_available(100));
    }

    #[test]
    fn test_congestion_bucket_full() {
        let mut check = test_congestion_check();
        check.resource_check.congestion_bucket.slots_used =
            check.resource_check.congestion_bucket.slots_available;
        assert!(!check.congestion_resources_available(100));
    }

    #[test]
    fn test_congestion_htlc_amount() {
        let check = test_congestion_check();
        let htlc_limit = check
            .resource_check
            .congestion_bucket
            .liquidity_available_msat
            / check.resource_check.congestion_bucket.slots_available as u64;

        assert!(check.congestion_resources_available(htlc_limit));
        assert!(!check.congestion_resources_available(htlc_limit + 1));
    }

    #[test]
    fn test_congestion_liquidity() {
        // Set liquidity such that we'll hit our minimum liquidity allowance.
        let mut check = test_congestion_check();
        check
            .resource_check
            .congestion_bucket
            .liquidity_available_msat = MINIMUM_CONGESTION_SLOT_LIQUDITY
            * check.resource_check.congestion_bucket.slots_available as u64
            / 2;

        assert!(check.congestion_resources_available(MINIMUM_CONGESTION_SLOT_LIQUDITY));
        assert!(!check.congestion_resources_available(MINIMUM_CONGESTION_SLOT_LIQUDITY + 1));
    }

    #[test]
    fn test_forwarding_outcome_congestion() {
        let check = test_congestion_check();

        // Unaccountable htlc that is congestion eligible gets access to congestion bucket and is
        // upgraded to accountable.
        assert!(
            check
                .inner_forwarding_outcome(10, AccountableSignal::Unaccountable, true)
                .unwrap()
                == SuccessForwardOutcome {
                    bucket: ResourceBucketType::Congestion,
                    accountable_signal: AccountableSignal::Accountable
                }
        );
    }

    #[test]
    fn test_forwarding_outcome_general() {
        let mut check = test_congestion_check();
        check.resource_check.general_bucket.slots_used = 0;

        // Unaccountable htlc with general resources available goes into general bucket and
        // forwarded as unaccountable.
        assert!(
            check
                .inner_forwarding_outcome(10, AccountableSignal::Unaccountable, true)
                .unwrap()
                == SuccessForwardOutcome {
                    bucket: ResourceBucketType::General,
                    accountable_signal: AccountableSignal::Unaccountable
                }
        );
    }

    #[test]
    fn test_forwarding_outcome_upgrade() {
        let mut check = test_congestion_check();
        check.reputation_check.reputation = 1000;
        check.resource_check.general_bucket.slots_available = 0;
        check.congestion_eligible = false;

        // Unaccountable htlc with no general or congestion resources available but with sufficient
        // reputation gets access to protected bucket and forwarded as accountable.
        assert!(
            check
                .inner_forwarding_outcome(10, AccountableSignal::Unaccountable, true)
                .unwrap()
                == SuccessForwardOutcome {
                    bucket: ResourceBucketType::Protected,
                    accountable_signal: AccountableSignal::Accountable
                }
        );
    }

    #[test]
    fn test_inner_forwarding_outcome_modified_signal() {
        let check = test_congestion_check();
        assert!(
            check
                .inner_forwarding_outcome(10, AccountableSignal::Accountable, false)
                .err()
                .unwrap()
                == FailureReason::UpgradableSignalModified
        );
    }

    #[test]
    fn test_bucket_outcome_table() {
        struct TestCase {
            name: &'static str,
            accountable: AccountableSignal,
            upgradable: bool,
            has_reputation: bool,
            general_eligible: bool,
            congestion_eligible: bool,
            protected_available: bool,
            general_available: bool,
            congestion_available: bool,
            expected: Result<ResourceBucketType, FailureReason>,
        }

        impl TestCase {
            /// Creates a default test case with the basic parameters provided. Will produce a test
            /// case where all buckets are available and the HTLC is eligible for them, except for
            /// congestion (which can't be available when general is).
            fn new(
                name: &'static str,
                accountable: AccountableSignal,
                expected: Result<ResourceBucketType, FailureReason>,
            ) -> Self {
                TestCase {
                    name,
                    accountable,
                    upgradable: true,
                    has_reputation: true,
                    general_eligible: true,
                    congestion_eligible: true,
                    protected_available: true,
                    general_available: true,
                    congestion_available: false,
                    expected,
                }
            }

            // Congestion resources are only available when general resources are NOT available,
            // so this value can't be true if general_available is true. It may still be false
            // when general_available is false, because there are multiple factors that may
            // contribute to the availability of general resources.
            fn set_congestion_available(&mut self) {
                self.congestion_available = true;
                self.general_available = false;
            }
        }

        let test_cases = vec![
            // Accountable cases
            TestCase::new(
                "accountable_with_reputation",
                AccountableSignal::Accountable,
                Ok(ResourceBucketType::Protected),
            ),
            {
                let mut case = TestCase::new(
                    "accountable_with_reputation_protected_full",
                    AccountableSignal::Accountable,
                    Ok(ResourceBucketType::General),
                );
                case.protected_available = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "accountable_with_reputation_general_ineligible",
                    AccountableSignal::Accountable,
                    Err(FailureReason::NoResources),
                );
                case.protected_available = false;
                case.general_eligible = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "accountable_with_reputation_general_full",
                    AccountableSignal::Accountable,
                    Err(FailureReason::NoResources),
                );
                case.protected_available = false;
                case.general_available = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "accountable_with_reputation_general_full_congestion_available",
                    AccountableSignal::Accountable,
                    Ok(ResourceBucketType::Congestion),
                );
                case.protected_available = false;
                case.set_congestion_available();
                case
            },
            {
                let mut case = TestCase::new(
                    "accountable_with_reputation_congestion_ineligible",
                    AccountableSignal::Accountable,
                    Err(FailureReason::NoResources),
                );
                case.protected_available = false;
                case.set_congestion_available();
                case.congestion_eligible = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "accountable_with_no_reputation",
                    AccountableSignal::Accountable,
                    Err(FailureReason::NoReputation),
                );
                case.has_reputation = false;
                case
            },
            // Unaccountable cases
            TestCase::new(
                "unaccountable_general_available",
                AccountableSignal::Unaccountable,
                Ok(ResourceBucketType::General),
            ),
            {
                let mut case = TestCase::new(
                    "unaccountable_general_ineligible_upgrades",
                    AccountableSignal::Unaccountable,
                    Ok(ResourceBucketType::Protected),
                );
                case.general_eligible = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "unaccountable_general_full_upgrades",
                    AccountableSignal::Unaccountable,
                    Err(FailureReason::NoGeneralResources),
                );
                case.general_eligible = false;
                case.upgradable = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "unaccountable_general_ineligible_no_reputation",
                    AccountableSignal::Unaccountable,
                    Err(FailureReason::NoGeneralResources),
                );
                case.general_eligible = false;
                case.has_reputation = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "unaccountable_congestion_available",
                    AccountableSignal::Unaccountable,
                    Ok(ResourceBucketType::Congestion),
                );
                case.has_reputation = false;
                case.set_congestion_available();
                case
            },
            {
                let mut case = TestCase::new(
                    "unaccountable_congestion_ineligible",
                    AccountableSignal::Unaccountable,
                    Err(FailureReason::NoGeneralResources),
                );
                case.has_reputation = false;
                case.congestion_eligible = false;
                case.set_congestion_available();
                case
            },
            {
                let mut case = TestCase::new(
                    "unaccountable_no_upgrade_congestion_available",
                    AccountableSignal::Unaccountable,
                    Err(FailureReason::NoGeneralResources),
                );
                case.upgradable = false;
                case.set_congestion_available();
                case
            },
            {
                let mut case = TestCase::new(
                    "unaccountable_upgrade_congestion_available",
                    AccountableSignal::Unaccountable,
                    Ok(ResourceBucketType::Congestion),
                );
                case.set_congestion_available();
                case.protected_available = false;
                case
            },
            {
                let mut case = TestCase::new(
                    "unaccountable_everything_full",
                    AccountableSignal::Unaccountable,
                    Err(FailureReason::NoGeneralResources),
                );
                case.protected_available = false;
                case.general_eligible = false;
                case
            },
        ];

        for test_case in test_cases {
            let check = AllocationCheck {
                reputation_check: ReputationCheck {
                    reputation: if test_case.has_reputation { 1000 } else { 0 },
                    revenue_threshold: 0,
                    in_flight_total_risk: 0,
                    htlc_risk: 0,
                },
                general_eligible: test_case.general_eligible,
                congestion_eligible: test_case.congestion_eligible,
                resource_check: ResourceCheck {
                    general_bucket: BucketResources {
                        slots_used: 0,
                        slots_available: if test_case.general_available { 10 } else { 0 },
                        liquidity_used_msat: 0,
                        liquidity_available_msat: if test_case.general_available {
                            100_000_000
                        } else {
                            0
                        },
                    },
                    congestion_bucket: BucketResources {
                        slots_used: 0,
                        slots_available: if test_case.congestion_available {
                            10
                        } else {
                            0
                        },
                        liquidity_used_msat: 0,
                        liquidity_available_msat: if test_case.congestion_available {
                            MINIMUM_CONGESTION_SLOT_LIQUDITY * 20
                        } else {
                            0
                        },
                    },
                    protected_bucket: BucketResources {
                        slots_used: 0,
                        slots_available: if test_case.protected_available { 10 } else { 0 },
                        liquidity_used_msat: 0,
                        liquidity_available_msat: if test_case.protected_available {
                            100_000_000
                        } else {
                            0
                        },
                    },
                },
            };

            if test_case.congestion_available {
                assert!(
                    !test_case.general_available,
                    "Congestion can't be available is general is, bad test case: {}",
                    test_case.name
                );
            }

            let result = check.bucket_outcome(1000, test_case.accountable, test_case.upgradable);
            assert_eq!(
                result, test_case.expected,
                "Test case '{}' failed. Expected {:?}, got {:?}",
                test_case.name, test_case.expected, result
            );
        }
    }
}
