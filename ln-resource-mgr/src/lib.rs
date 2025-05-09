mod decaying_average;
pub mod forward_manager;
use forward_manager::Reputation;
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
        }
    }
}

/// The different possible endorsement signals on a htlc's update_add message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum EndorsementSignal {
    Unendorsed,
    Endorsed,
}

impl Display for EndorsementSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndorsementSignal::Endorsed => write!(f, "endorsed"),
            EndorsementSignal::Unendorsed => write!(f, "unendorsed"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ForwardingOutcome {
    /// Forward the outgoing htlc with the endorsement signal provided.
    Forward(EndorsementSignal),
    /// Fail the incoming htlc back with the reason provided.
    Fail(FailureReason),
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
    /// There is no space in the outgoing channel's general resource bucket, so the htlc should be failed back. It
    /// may be retired with endorsement set to gain access to protected resources.
    NoResources,
    /// The outgoing peer has insufficient reputation for the htlc to occupy protected resources.
    NoReputation,
    /// The upgradable signal has been tampered with so we should fail back the htlc.
    UpgradableSignalModified,
}

/// A snapshot of the incoming and outgoing reputation and resources available for a forward.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AllocationCheck {
    /// The reputation values used to check the incoming and outgoing reputation for the htlc
    /// proposed.
    pub reputation_check: ReputationCheck,
    /// Indicates whether the incoming channel is eligible to consume congestion resources.
    pub congestion_eligible: bool,
    /// The resources available on the outgoing channel.
    pub resource_check: ResourceCheck,
}

/// Represents the different resource buckets that htlcs can be assigned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceBucketType {
    Protected,
    Congestion,
    General,
}

impl AllocationCheck {
    /// The recommended action to be taken for the htlc forward.
    pub fn forwarding_outcome(
        &self,
        htlc_amt_msat: u64,
        incoming_endorsed: EndorsementSignal,
        incoming_upgradable: bool,
        reputation_check: Reputation,
    ) -> ForwardingOutcome {
        match self.inner_forwarding_outcome(
            htlc_amt_msat,
            incoming_endorsed,
            incoming_upgradable,
            reputation_check,
        ) {
            Ok(bucket) => match bucket {
                ResourceBucketType::General => {
                    ForwardingOutcome::Forward(EndorsementSignal::Unendorsed)
                }
                ResourceBucketType::Congestion => {
                    ForwardingOutcome::Forward(EndorsementSignal::Unendorsed)
                }
                ResourceBucketType::Protected => {
                    ForwardingOutcome::Forward(EndorsementSignal::Endorsed)
                }
            },
            Err(fail_reason) => ForwardingOutcome::Fail(fail_reason),
        }
    }

    /// Returns the bucket assignment or failure reason for a htlc.
    fn inner_forwarding_outcome(
        &self,
        htlc_amt_msat: u64,
        incoming_endorsed: EndorsementSignal,
        incoming_upgradable: bool,
        reputation_check: Reputation,
    ) -> Result<ResourceBucketType, FailureReason> {
        if !incoming_upgradable && incoming_endorsed == EndorsementSignal::Endorsed {
            return Err(FailureReason::UpgradableSignalModified);
        }

        match incoming_endorsed {
            EndorsementSignal::Endorsed => {
                if reputation_check.sufficient_reputation(self) {
                    Ok(ResourceBucketType::Protected)
                } else {
                    // If the htlc was endorsed but the peer doesn't have reputation, we consider giving them a shot
                    // at our reserved congestion resources.
                    if self.congestion_resources_available(htlc_amt_msat) {
                        return Ok(ResourceBucketType::Congestion);
                    }

                    // If we are looking at incoming reputation only, we use our general resources
                    // if available because we are not held accountable for the behavior of
                    // downstream nodes. If we are looking at outgoing/bidirectional reputation, we
                    // drop the htlc to protect against downstream nodes possibly damaging our
                    // reputation with our upstream peer.
                    match reputation_check {
                        Reputation::Incoming => {
                            if self
                                .resource_check
                                .general_bucket
                                .resources_available(htlc_amt_msat)
                            {
                                Ok(ResourceBucketType::General)
                            } else {
                                Err(FailureReason::NoResources)
                            }
                        }
                        _ => Err(FailureReason::NoReputation),
                    }
                }
            }
            EndorsementSignal::Unendorsed => {
                if reputation_check.sufficient_reputation(self) && incoming_upgradable {
                    return Ok(ResourceBucketType::Protected);
                }

                if self
                    .resource_check
                    .general_bucket
                    .resources_available(htlc_amt_msat)
                {
                    Ok(ResourceBucketType::General)
                } else {
                    Err(FailureReason::NoResources)
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReputationCheck {
    /// Values used to check incoming reputation for the channel pair.
    pub incoming_reputation: ReputationValues,
    /// Values used to check outgoing reputation for the channel pair.
    pub outgoing_reputation: ReputationValues,
}

/// A snapshot of a reputation check for a htlc forward.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReputationValues {
    pub reputation: i64,
    pub revenue_threshold: i64,
    pub in_flight_total_risk: u64,
    pub htlc_risk: u64,
}

impl ReputationValues {
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
    pub incoming_endorsed: EndorsementSignal,
    pub upgradable_endorsement: bool,
}

impl Display for ProposedForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} {} -> {} with fee {} ({} -> {}) and cltv {} ({} -> {})",
            self.incoming_ref.channel_id,
            self.incoming_ref.htlc_index,
            self.incoming_endorsed,
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
    pub incoming_reputation: i64,
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

    /// Returns a forwarding assessment for the proposed HTLC based on its endorsement status and the reputation of
    /// the incoming and outgoing channel. This call can optionally be used to co-locate reputation checks with
    /// other forwarding checks (such as fee policies and expiry delta) so that the htlc can be failed early, saving
    /// the need to propagate it to the outgoing link. Using this method *does not* replace the need to call
    /// [`add_hltc`] before sending `update_add_htlc` on the outgoing link.
    fn get_forwarding_outcome(
        &self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError>;

    /// Checks the endorsement signal and reputation of a proposed forward to determine whether a htlc should be
    /// forwarded on the outgoing link. If the htlc can be forwarded, it will be added to the internal state of
    /// the [`ReputationManager`], and it *must* be cleared out using [`resolve_htlc`]. If the htlc cannot
    /// be forwarded, no further action is expected. The [`outgoing_ref`] provided for the outgoing htlc *must*
    /// match `update_add_htlc` (so validation and non-strict forwarding logic must be applied before).
    ///
    /// Note that this API is not currently replay-safe, so any htlcs that are replayed on restart will return
    /// [`ReputationError::ErrDuplicateHtlc`].
    fn add_htlc(&self, forward: &ProposedForward) -> Result<AllocationCheck, ReputationError>;

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
        forward_manager::Reputation, AllocationCheck, BucketResources, EndorsementSignal,
        FailureReason, ReputationCheck, ReputationValues, ResourceBucketType, ResourceCheck,
        MINIMUM_CONGESTION_SLOT_LIQUDITY,
    };

    /// Returns an AllocationCheck which is eligible for congestion resources.
    fn test_congestion_check() -> AllocationCheck {
        let reputation_values = ReputationValues {
            reputation: 0,
            revenue_threshold: 0,
            in_flight_total_risk: 0,
            htlc_risk: 0,
        };

        let check = AllocationCheck {
            reputation_check: ReputationCheck {
                incoming_reputation: reputation_values.clone(),
                outgoing_reputation: reputation_values,
            },
            congestion_eligible: true,
            resource_check: ResourceCheck {
                general_bucket: BucketResources {
                    slots_used: 10,
                    slots_available: 10,
                    liquidity_used_msat: 0,
                    liquidity_available_msat: 200_000,
                },
                congestion_bucket: BucketResources {
                    slots_used: 0,
                    slots_available: 10,
                    liquidity_used_msat: 0,
                    liquidity_available_msat: MINIMUM_CONGESTION_SLOT_LIQUDITY * 20,
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
    fn test_inner_forwarding_outcome_congestion() {
        let check = test_congestion_check();

        let test_inner_forwarding_outcome_congestion_for_reputation =
            |check: &AllocationCheck, scheme: Reputation| {
                // Endorsed htlc will be granted access to congestion resources.
                assert!(
                    check
                        .inner_forwarding_outcome(10, EndorsementSignal::Endorsed, true, scheme)
                        .unwrap()
                        == ResourceBucketType::Congestion
                );

                // Unendorsed htlc will not be granted access to congestion resources.
                assert!(
                    check
                        .inner_forwarding_outcome(10, EndorsementSignal::Unendorsed, true, scheme)
                        .err()
                        .unwrap()
                        == FailureReason::NoResources,
                );
            };

        test_inner_forwarding_outcome_congestion_for_reputation(&check, Reputation::Incoming);
        test_inner_forwarding_outcome_congestion_for_reputation(&check, Reputation::Outgoing);
        test_inner_forwarding_outcome_congestion_for_reputation(&check, Reputation::Bidirectional);
    }

    #[test]
    fn test_inner_forwarding_outcome_reputation() {
        let mut check = test_congestion_check();
        check.reputation_check.outgoing_reputation.reputation = 1000;
        check.resource_check.general_bucket.slots_used = 0;
        check.reputation_check.incoming_reputation.reputation = 1000;

        // Sufficient reputation and endorsed will go in the protected bucket.
        let test_forwarding_outcome_protected_for_reputation =
            |check: &AllocationCheck, scheme: Reputation| {
                assert!(
                    check
                        .inner_forwarding_outcome(10, EndorsementSignal::Endorsed, true, scheme)
                        .unwrap()
                        == ResourceBucketType::Protected,
                );
            };

        test_forwarding_outcome_protected_for_reputation(&check, Reputation::Incoming);
        test_forwarding_outcome_protected_for_reputation(&check, Reputation::Outgoing);
        test_forwarding_outcome_protected_for_reputation(&check, Reputation::Bidirectional);

        // Unendorsed htlc with sufficient reputation gets upgraded so it goes in the protected bucket.
        assert!(
            check
                .inner_forwarding_outcome(
                    10,
                    EndorsementSignal::Unendorsed,
                    true,
                    Reputation::Bidirectional
                )
                .unwrap()
                == ResourceBucketType::Protected,
        );
    }

    #[test]
    fn test_inner_forwarding_outcome_partial_reputation() {
        let mut check = test_congestion_check();
        check.reputation_check.outgoing_reputation.reputation = 1000;
        check.resource_check.general_bucket.slots_available = 0;
        check.resource_check.congestion_bucket.slots_available = 0;

        // Require reputation in both directions but only has outgoing.
        assert!(
            check
                .inner_forwarding_outcome(
                    10,
                    EndorsementSignal::Endorsed,
                    true,
                    Reputation::Bidirectional
                )
                .err()
                .unwrap()
                == FailureReason::NoReputation
        );

        check.reputation_check.incoming_reputation.reputation = 1000;
        check.reputation_check.outgoing_reputation.reputation = 0;

        // Require reputation in both directions but only has incoming.
        assert!(
            check
                .inner_forwarding_outcome(
                    10,
                    EndorsementSignal::Endorsed,
                    true,
                    Reputation::Bidirectional
                )
                .err()
                .unwrap()
                == FailureReason::NoReputation
        );
    }

    #[test]
    fn test_inner_forwarding_outcome_no_reputation() {
        let mut check = test_congestion_check();
        check.resource_check.general_bucket.slots_used = 0;

        // If reputation_check is Incoming and does not have reputation it will go to general
        // bucket
        assert!(
            check
                .inner_forwarding_outcome(
                    10,
                    EndorsementSignal::Endorsed,
                    true,
                    Reputation::Incoming
                )
                .unwrap()
                == ResourceBucketType::General
        );

        // If insufficient outgoing/bidirectional reputation and no congestion resources will fail.
        let test_no_reputation = |check: &AllocationCheck, scheme: Reputation| {
            assert!(
                check
                    .inner_forwarding_outcome(10, EndorsementSignal::Endorsed, true, scheme)
                    .err()
                    .unwrap()
                    == FailureReason::NoReputation,
            );
        };

        test_no_reputation(&check, Reputation::Outgoing);
        test_no_reputation(&check, Reputation::Bidirectional);

        // Unendorsed htlc with no reputation and available resources goes into general bucket.
        assert!(
            check
                .inner_forwarding_outcome(
                    10,
                    EndorsementSignal::Unendorsed,
                    true,
                    Reputation::Bidirectional
                )
                .unwrap()
                == ResourceBucketType::General
        );
    }

    #[test]
    fn test_inner_forwarding_outcome_modified_signal() {
        let check = test_congestion_check();

        // return error if htlc has an endorsement signal but is not marked as upgradable.
        assert!(
            check
                .inner_forwarding_outcome(
                    10,
                    EndorsementSignal::Endorsed,
                    false,
                    Reputation::Bidirectional
                )
                .err()
                .unwrap()
                == FailureReason::UpgradableSignalModified
        );
    }
}
