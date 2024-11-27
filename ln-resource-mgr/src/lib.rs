pub mod outgoing_reputation;

pub mod reputation {
    use std::fmt::Display;
    use std::time::Instant;

    /// The total supply of bitcoin expressed in millisatoshis.
    const SUPPLY_CAP_MSAT: u64 = 21000000 * 100000000 * 1000;

    #[derive(Debug)]
    pub enum ReputationError {
        /// Indicates that the incoming channel was not found.
        ErrIncomingNotFound(u64),
        /// Indicates that the outgoing channel was not found.
        ErrOutgoingNotFound(u64),
        /// Indicates that the htlc reference provided was not found.
        ErrForwardNotFound(u64, HtlcRef),
        /// Catchall unknown errors.
        ErrUnknown(String),
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

    impl Display for ReputationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
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
                ReputationError::ErrUnknown(e) => write!(f, "unknown error: {e}"),
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
    #[derive(PartialEq, Eq, Copy, Clone)]
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

    #[derive(Debug)]
    pub enum FailureReason {
        /// There is no space in the outgoing channel's general resource bucket, so the htlc should be failed back. It
        /// may be retired with endorsement set to gain access to protected resources.
        NoResources,
        /// The outgoing peer has insufficient reputation for the htlc to occupy protected resources.
        NoReputation,
    }

    /// A snapshot of the reputation and resources available for a forward.
    #[derive(Debug)]
    pub struct AllocatoinCheck {
        pub reputation_check: ReputationCheck,
        pub resource_check: ResourceCheck,
    }

    impl AllocatoinCheck {
        pub fn forwarding_outcome(
            &self,
            htlc_amt_msat: u64,
            incoming_endorsed: EndorsementSignal,
        ) -> ForwardingOutcome {
            match incoming_endorsed {
                EndorsementSignal::Endorsed => {
                    if self.reputation_check.sufficient_reputation() {
                        ForwardingOutcome::Forward(EndorsementSignal::Endorsed)
                    } else {
                        ForwardingOutcome::Fail(FailureReason::NoReputation)
                    }
                }
                EndorsementSignal::Unendorsed => {
                    if self
                        .resource_check
                        .general_resources_available(htlc_amt_msat)
                    {
                        ForwardingOutcome::Forward(EndorsementSignal::Unendorsed)
                    } else {
                        ForwardingOutcome::Fail(FailureReason::NoResources)
                    }
                }
            }
        }
    }

    /// A snapshot of a reputation check for a htlc forward.
    #[derive(Debug)]
    pub struct ReputationCheck {
        pub outgoing_reputation: i64,
        pub incoming_revenue: i64,
        pub in_flight_total_risk: u64,
        pub htlc_risk: u64,
    }

    impl ReputationCheck {
        /// Returns a boolean indicating whether the outgoing channel has sufficient reputation for this htlc to be
        /// forwarded to it.
        pub fn sufficient_reputation(&self) -> bool {
            self.outgoing_reputation
                .saturating_sub(i64::try_from(self.in_flight_total_risk).unwrap_or(i64::MAX))
                .saturating_sub(i64::try_from(self.htlc_risk).unwrap_or(i64::MAX))
                > self.incoming_revenue
        }
    }

    /// A snapshot of the resource check for a htlc forward.
    #[derive(Debug)]
    pub struct ResourceCheck {
        pub general_slots_used: u16,
        pub general_slots_availabe: u16,
        pub general_liquidity_msat_used: u64,
        pub general_liquidity_msat_available: u64,
    }

    impl ResourceCheck {
        pub fn general_resources_available(&self, htlc_amt_mast: u64) -> bool {
            if self.general_liquidity_msat_used + htlc_amt_mast
                > self.general_liquidity_msat_available
            {
                return false;
            }

            if self.general_slots_used + 1 > self.general_slots_availabe {
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
            }
        }
    }

    /// The resolution for a htlc received from the upstream peer (or decided locally).
    #[derive(PartialEq, Clone, Copy)]
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

    /// A unique identifier for a htlc on a channel (payment hash may be repeated for mpp payments).
    #[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
    pub struct HtlcRef {
        pub channel_id: u64,
        pub htlc_index: u64,
    }

    pub struct ProposedForward {
        pub incoming_ref: HtlcRef,
        pub outgoing_channel_id: u64,
        pub amount_in_msat: u64,
        pub amount_out_msat: u64,
        pub expiry_in_height: u32,
        pub expiry_out_height: u32,
        pub added_at: Instant,
        pub incoming_endorsed: EndorsementSignal,
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
        pub fn validate(&self) -> Result<(), ReputationError> {
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
        pub fn fee_msat(&self) -> u64 {
            self.amount_in_msat - self.amount_out_msat
        }

        /// Only underflow safe after validation.
        pub fn expiry_delta(&self) -> u32 {
            self.expiry_in_height - self.expiry_out_height
        }
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
        /// any calls to [`get_forwarding_outcome`] or [`add_outgoing_htlc`] reference the channel.
        fn add_channel(&self, channel_id: u64, capacity_msat: u64) -> Result<(), ReputationError>;

        /// Called to clean up a channel once it has been closed and is no longer usable for htlc forwards.
        fn remove_channel(&self, channel_id: u64) -> Result<(), ReputationError>;

        /// Returns a forwarding assessment for the proposed HTLC based on its endorsement status and the reputation of
        /// the incoming and outgoing channel. This call can optionally be used to co-locate reputation checks with
        /// other forwarding checks (such as fee policies and expiry delta) so that the htlc can be failed early, saving
        /// the need to propagate it to the outgoing link. Using this method *does not* replace the need to call
        /// [`add_outgoing_hltc`] before sending `update_add_htlc` on the outgoing link.
        fn get_forwarding_outcome(
            &self,
            forward: &ProposedForward,
        ) -> Result<AllocatoinCheck, ReputationError>;

        /// Checks the endorsement signal and reputation of a proposed forward to determine whether a htlc should be
        /// forwarded on the outgoing link. If the htlc can be forwarded, it will be added to the internal state of
        /// the [`ReputationManager`], and it *must* be cleared out using [`resolve_outgoing_htlc`]. If the htlc cannot
        /// be forwarded, no further action is expected. The [`outgoing_ref`] provided for the outgoing htlc *must*
        /// match `update_add_htlc` (so validation and non-strict forwarding logic must be applied before).
        ///
        /// Note that this API is not currently replay-safe, so any htlcs that are replayed on restart will return
        /// [`ReputationError::ErrDuplicateHtlc`].
        fn add_outgoing_hltc(
            &self,
            forward: &ProposedForward,
        ) -> Result<AllocatoinCheck, ReputationError>;

        /// Resolves a htlc that was previously added using [`add_outgoing_htlc`], returning
        /// [`ReputationError::ErrForwardNotFound`] if the htlc is not found.
        fn resolve_htlc(
            &self,
            outgoing_channel: u64,
            incoming_ref: HtlcRef,
            resolution: ForwardResolution,
            resolved_instant: Instant,
        ) -> Result<(), ReputationError>;
    }
}
