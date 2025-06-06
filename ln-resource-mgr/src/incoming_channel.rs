use crate::restricted_bucket::RestrictedBucket;
use crate::ReputationError;

/// Describes the size of a resource bucket.
#[derive(Clone, Debug)]
pub struct BucketParameters {
    /// The number of HTLC slots available in the bucket.
    pub slot_count: u16,
    /// The amount of liquidity available in the bucket.
    pub liquidity_msat: u64,
}

/// Tracks resources available on the channel when it is utilized as the incoming direction in a htlc forward.
#[derive(Debug)]
pub(super) struct IncomingChannel {
    /// The resources available for htlcs that are not accountable, or are not sent by a peer with sufficient reputation.
    pub(super) general_bucket: BucketParameters,

    /// The resources available for htlcs that are accountable from peers that do not have sufficient reputation. This
    /// bucket is only used when the general bucket is full, and peers are limited to a single slot/liquidity block.
    pub(super) congestion_bucket: BucketParameters,

    /// The resources available on the protected bucket. This will be used by htlcs that are
    /// accountable from peers that have sufficient reputation.
    pub(super) protected_bucket: BucketParameters,

    pub(super) general_resources: RestrictedBucket,
}

impl IncomingChannel {
    pub(super) fn new(
        scid: u64,
        general_bucket: BucketParameters,
        congestion_bucket: BucketParameters,
        protected_bucket: BucketParameters,
    ) -> Result<Self, ReputationError> {
        Ok(Self {
            general_bucket: general_bucket.clone(),
            congestion_bucket,
            protected_bucket,
            general_resources: RestrictedBucket::new(
                scid,
                general_bucket.liquidity_msat,
                general_bucket.slot_count,
            )?,
        })
    }

    pub(super) fn general_jam_channel(&mut self) {
        self.general_bucket = BucketParameters {
            slot_count: 0,
            liquidity_msat: 0,
        };
    }

    pub(super) fn general_eligible(
        &mut self,
        outgoing_scid: u64,
        incoming_amt_msat: u64,
    ) -> Result<bool, ReputationError> {
        self.general_resources
            .may_add_htlc(outgoing_scid, incoming_amt_msat)
    }

    pub(super) fn add_to_general(
        &mut self,
        outgoing_scid: u64,
        incoming_amt_msat: u64,
    ) -> Result<bool, ReputationError> {
        self.general_resources
            .add_htlc(outgoing_scid, incoming_amt_msat)
    }
}
