use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use rand::Rng;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

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
    pub(super) general_bucket: GeneralBucket,

    /// The resources available for htlcs that are accountable from peers that do not have sufficient reputation. This
    /// bucket is only used when the general bucket is full, and peers are limited to a single slot/liquidity block.
    pub(super) congestion_bucket: BucketParameters,

    /// The resources available on the protected bucket. This will be used by htlcs that are
    /// accountable from peers that have sufficient reputation.
    pub(super) protected_bucket: BucketParameters,
}

impl IncomingChannel {
    pub(super) fn new(
        scid: u64,
        general_bucket: BucketParameters,
        congestion_bucket: BucketParameters,
        protected_bucket: BucketParameters,
    ) -> Result<Self, ReputationError> {
        Ok(Self {
            general_bucket: GeneralBucket::new(scid, general_bucket)?,
            congestion_bucket,
            protected_bucket,
        })
    }

    pub(super) fn general_jam_channel(&mut self) {
        self.general_bucket.params = BucketParameters {
            slot_count: 0,
            liquidity_msat: 0,
        };
    }

    pub(super) fn congestion_jam_channel(&mut self) {
        self.congestion_bucket = BucketParameters {
            slot_count: 0,
            liquidity_msat: 0,
        };
    }
}

/// Defines the number of slots each candidate channel is allowed in the general bucket.
const ASSIGNED_SLOTS: usize = 5;

#[derive(Debug)]
pub(super) struct GeneralBucket {
    /// The resources available for htlcs that are not accountable, or are not sent by a peer with sufficient reputation.
    pub(super) params: BucketParameters,
    /// Short channel ID that represents the channel that the bucket belongs to.
    scid: u64,
    /// Tracks the occupancy of HTLC slots in the bucket.
    htlc_slots: Vec<bool>,
    /// Tracks the amount of liquidity allocated to each slot in the bucket.
    slot_size_msat: u64,
    /// Maps short channel IDs to an array of the slots that the channel is allowed to use, and their
    /// current usage state. This information is required to track exactly which slots to remove
    /// liquidity from.
    //
    // A u16 is used so that we can account for the possiblity that we assign our protocol max of
    // 483 slots, this can be changed to a u8 when only dealing with V3 channels.
    candidate_slots: HashMap<u64, [(u16, bool); ASSIGNED_SLOTS]>,
}

impl GeneralBucket {
    /// Creates a new general bucket.
    ///
    /// Note that the current implementation is not restart safe:
    /// - It assigns new salt every time a channel is added (should be persisted across restarts).
    /// - It assumes that the bucket is empty on start (should account for in-flight HTLCs).
    pub(super) fn new(scid: u64, params: BucketParameters) -> Result<Self, ReputationError> {
        let slot_size_msat = params.liquidity_msat / params.slot_count as u64;
        if slot_size_msat == 0 {
            return Err(ReputationError::ErrUnrecoverable(format!(
                "channel size: {} with {} slots results in zero liquidity bucket",
                params.liquidity_msat, params.slot_count
            )));
        }

        Ok(Self {
            params: params.clone(),
            scid,
            // Totally fill array so that we don't need to worry about checking length.
            htlc_slots: vec![false; params.slot_count as usize],
            slot_size_msat,
            candidate_slots: HashMap::new(),
        })
    }

    /// Removes a channel from internal state, returning a boolean indicating whether anything
    /// was remove from state.
    pub(super) fn remove_channel(&mut self, candidate_scid: u64) -> bool {
        self.candidate_slots.remove(&candidate_scid).is_some()
    }

    /// Produces the set of slots that a channel has permission to use.
    /// Assumes that [`self.htlc_slots`] has been initialized with values set for each slot.
    /// Retries up to ASSIGNED_SLOTS * 2 times to avoid duplicates, then fails (as it's highly
    /// improbably that we can't get non-duplicates after that many attempts).
    fn get_candidate_slots(
        &mut self,
        candidate_scid: u64,
    ) -> Result<[u16; ASSIGNED_SLOTS], ReputationError> {
        if candidate_scid == self.scid {
            return Err(ReputationError::ErrUnrecoverable(format!(
                "can't self-assign slots: {}",
                candidate_scid
            )));
        }

        match self.candidate_slots.entry(candidate_scid) {
            Entry::Occupied(entry) => Ok(entry.get().map(|slot| slot.0)),
            Entry::Vacant(entry) => {
                let mut rng = rand::rng();
                let mut salt = [0u8; 32];
                rng.fill(&mut salt);

                let mut result = [(0u16, false); ASSIGNED_SLOTS];
                let mut assigned_count = 0;

                // We hash the channel pair along with salt and an index to get our slots. We'll
                // add the index on each iteration below.
                let mut data = Vec::with_capacity(salt.len() + 8 + 8 + 8);
                data.extend_from_slice(&salt);
                data.extend_from_slice(&self.scid.to_be_bytes());
                data.extend_from_slice(&candidate_scid.to_be_bytes());
                let i_offset = data.len();
                data.resize(data.len() + 1, 0);

                let max_attempts = ASSIGNED_SLOTS * 2;
                for attempt in 0..max_attempts {
                    if assigned_count == ASSIGNED_SLOTS {
                        break;
                    }

                    data[i_offset] = attempt as u8;
                    let hash = Sha256dHash::hash(&data);

                    // It's okay to just use the first 8 bytes because we're just using this
                    // for indexing.
                    let hash_num = u64::from_be_bytes(hash[0..8].try_into().map_err(|_| {
                        ReputationError::ErrUnrecoverable(
                            "hash could not be converted to u64".to_string(),
                        )
                    })?);

                    let htlc_slot = (hash_num as usize % self.htlc_slots.len())
                        .try_into()
                        .map_err(|_| {
                            ReputationError::ErrUnrecoverable(format!(
                                "hash num: {} mod htlc slots {} is not a u16",
                                hash_num,
                                self.htlc_slots.len()
                            ))
                        })?;
                    let candidate_slot = (htlc_slot, false);

                    assert!((candidate_slot.0 as usize) < self.htlc_slots.len());

                    let mut is_duplicate = false;
                    for res in result.iter().take(assigned_count) {
                        if *res == candidate_slot {
                            is_duplicate = true;
                            break;
                        }
                    }

                    if !is_duplicate {
                        result[assigned_count] = candidate_slot;
                        assigned_count += 1;
                    }
                }

                if assigned_count < ASSIGNED_SLOTS {
                    return Err(ReputationError::ErrUnrecoverable(format!(
                        "Could not assign {} unique slots for channel {}, only found {}",
                        ASSIGNED_SLOTS, candidate_scid, assigned_count
                    )));
                }

                entry.insert(result);
                Ok(result.map(|slot| slot.0))
            }
        }
    }

    /// Returns the number of liquidity slots a HTLC requires.
    fn required_slot_count(&self, amount_msat: u64) -> u64 {
        u64::max(1, amount_msat.div_ceil(self.slot_size_msat))
    }

    /// Returns the indexes of a set of slots that can hold the payment amount provided.
    fn get_usable_slots(
        &mut self,
        candidate_scid: u64,
        amount_msat: u64,
    ) -> Result<Option<Vec<u16>>, ReputationError> {
        let required_slot_count = self.required_slot_count(amount_msat);
        let slots = self.get_candidate_slots(candidate_scid)?;

        let available_slots: Vec<u16> = slots
            .into_iter()
            .filter(|&index| !self.htlc_slots[index as usize])
            .collect();

        if (available_slots.len() as u64) < required_slot_count {
            Ok(None)
        } else {
            Ok(Some(
                available_slots
                    .into_iter()
                    .take(required_slot_count as usize)
                    .collect(),
            ))
        }
    }

    /// Checks whether there is space in the bucket to accommodate the HTLC amount.
    ///
    /// Requires a mutable reference because it may need to opportunistically allocate slots to the
    /// channel if it has never been used as the outgoing forwarding channel with this one. This
    /// is done "just in time" so that we don't need to pick slots for channels that we many never
    /// forward with.
    pub(super) fn may_add_htlc(
        &mut self,
        candidate_scid: u64,
        amount_msat: u64,
    ) -> Result<bool, ReputationError> {
        Ok(self
            .get_usable_slots(candidate_scid, amount_msat)?
            .is_some())
    }

    /// Adds a HTLC to the bucket, returning a boolean indicating whether the HTLC was sucessfully
    /// added.
    ///
    /// Requires a mutable reference because it may need to opportunistically allocate slots to the
    /// channel if it has never been used as the outgoing forwarding channel with this one. This
    /// is done "just in time" so that we don't need to pick slots for channels that we many never
    /// forward with.
    pub(super) fn add_htlc(
        &mut self,
        candidate_scid: u64,
        amount_msat: u64,
    ) -> Result<bool, ReputationError> {
        let available_slots = match self.get_usable_slots(candidate_scid, amount_msat)? {
            Some(slots) => slots,
            None => return Ok(false),
        };

        // When we add htlcs to a channel, we also need to track on the channel exactly which slots
        // we're going to use for this channel.
        let channel_slots = self
            .candidate_slots
            .get_mut(&candidate_scid)
            .ok_or(ReputationError::ErrChannelNotFound(candidate_scid))?;

        // Once we know there's enough liquidity available for the HTLC, we can go ahead and
        // reserve the specific channel slots we need.
        for index in available_slots.iter() {
            assert!(
                !self.htlc_slots[*index as usize],
                "assigning slot already taken"
            );
            self.htlc_slots[*index as usize] = true;

            let slot = channel_slots.iter_mut().find(|s| s.0 == *index).ok_or(
                ReputationError::ErrUnrecoverable(
                    "inconsistent slots assigned in general bucket".to_string(),
                ),
            )?;
            assert!(!slot.1, "assigning slot already taken");
            slot.1 = true;
        }

        Ok(true)
    }

    /// Removes a HTLC for the candidate channel. Should be called once the HTLC has been resolved.
    pub(super) fn remove_htlc(
        &mut self,
        candidate_scid: u64,
        amount_msat: u64,
    ) -> Result<(), ReputationError> {
        let required_slot_count = self.required_slot_count(amount_msat);

        let channel_slots = self
            .candidate_slots
            .get_mut(&candidate_scid)
            .ok_or(ReputationError::ErrChannelNotFound(candidate_scid))?;

        let occupied_slots: Vec<(u16, bool)> =
            channel_slots.iter().copied().filter(|s| s.1).collect();

        if (occupied_slots.len() as u64) < required_slot_count {
            return Err(ReputationError::ErrBucketTooEmpty(amount_msat));
        }

        for i in occupied_slots
            .into_iter()
            .take(required_slot_count as usize)
        {
            assert!(self.htlc_slots[i.0 as usize], "removing unassigned slot");
            self.htlc_slots[i.0 as usize] = false;

            let slot = channel_slots.iter_mut().find(|slot| slot.0 == i.0).ok_or(
                ReputationError::ErrUnrecoverable(
                    "inconsistent slots assigned in general bucket".to_string(),
                ),
            )?;
            assert!(slot.1, "removing unassigned slot");
            slot.1 = false;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const TEST_BUCKET_PARAMS: BucketParameters = BucketParameters {
        slot_count: 100,
        liquidity_msat: 1_000_000,
    };

    #[test]
    fn test_new_bucket() {
        let bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        assert_eq!(bucket.slot_size_msat, 10_000);
        assert_eq!(bucket.htlc_slots.len(), 100);
        assert!(bucket.htlc_slots.iter().all(|b| !*b));
    }

    #[test]
    fn test_channel_already_removed() {
        let scid = 456;
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        bucket.add_htlc(scid, 1).unwrap();
        assert!(bucket.remove_channel(scid));
        assert!(!bucket.remove_channel(scid));
    }

    #[test]
    fn test_new_bucket_zero_slot_size() {
        let result = GeneralBucket::new(
            123,
            BucketParameters {
                slot_count: 200,
                liquidity_msat: 100,
            },
        );
        assert!(matches!(result, Err(ReputationError::ErrUnrecoverable(_))));
    }

    #[test]
    fn test_candidate_slots_existing() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid = 456;
        let slots = [1, 2, 3, 4, 5];
        bucket
            .candidate_slots
            .insert(scid, slots.map(|slot| (slot, false)));
        assert_eq!(slots, bucket.get_candidate_slots(scid).unwrap())
    }

    #[test]
    fn test_candidate_slots_self() {
        let bucket_scid = 123;
        let mut bucket = GeneralBucket::new(bucket_scid, TEST_BUCKET_PARAMS).unwrap();
        assert!(matches!(
            bucket.get_candidate_slots(bucket_scid),
            Err(ReputationError::ErrUnrecoverable(_))
        ));
    }

    #[test]
    fn test_get_candidate_slots_consistency() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid = 789;
        let slots1 = bucket.get_candidate_slots(scid).unwrap();
        let slots2 = bucket.get_candidate_slots(scid).unwrap();
        assert_eq!(slots1, slots2);
    }

    #[test]
    fn test_get_candidate_slots_within_bounds_and_unique() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid = 789;
        let slots = bucket.get_candidate_slots(scid).unwrap();
        for &slot in &slots {
            assert!((slot as usize) < bucket.htlc_slots.len());
        }
        let unique: HashSet<u16> = slots.into_iter().collect();
        assert!(unique.len() <= ASSIGNED_SLOTS);
    }

    #[test]
    fn test_add_htlc_successful_allocation() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid = 456;
        let htlc_amt = 1000;

        for _ in 0..ASSIGNED_SLOTS {
            assert!(bucket.add_htlc(scid, htlc_amt).unwrap());
        }

        assert!(!bucket.add_htlc(scid, 100_000).unwrap());

        for _ in 0..ASSIGNED_SLOTS {
            bucket.remove_htlc(scid, htlc_amt).unwrap();
        }

        assert!(bucket.remove_htlc(scid, htlc_amt).is_err());
    }

    /// Tests that a single HTLC is allowed to take up all liquidity for all slots.
    #[test]
    fn test_liquidity_one_htlc() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid = 345;

        let max_htlc = bucket.slot_size_msat * ASSIGNED_SLOTS as u64;
        assert!(bucket.add_htlc(scid, max_htlc).unwrap());
        assert!(!bucket.add_htlc(scid, 1).unwrap());

        bucket.remove_htlc(scid, max_htlc).unwrap();
        assert!(bucket.add_htlc(scid, max_htlc).unwrap());
    }

    /// Tests that when a HTLC takes up a portion of a bucket, another HTLC is not allowed to
    /// share that liquidity.
    #[test]
    fn test_partial_liquidity_usage() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid = 345;

        let half_allocation = bucket.slot_size_msat * ASSIGNED_SLOTS as u64 / 2;
        assert!(bucket.add_htlc(scid, half_allocation).unwrap());

        // Reject a HTLC that needs 2.5 slots worth of liquidity, because the previous htlc
        // used up 3.
        assert!(!bucket.add_htlc(scid, half_allocation).unwrap());

        // Accept a HTLC that only needs 2 slots worth of liquidity.
        assert!(bucket.add_htlc(scid, bucket.slot_size_msat * 2).unwrap());

        // Finally, remove one half-liquidity HTLC and assert we can add another in its place.
        bucket.remove_htlc(scid, half_allocation).unwrap();
        assert!(bucket.add_htlc(scid, half_allocation).unwrap());
    }

    #[test]
    fn test_insufficient_liquidity() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid = 345;
        let htlc_too_big = bucket.slot_size_msat * ASSIGNED_SLOTS as u64 * 2;

        assert!(!bucket.add_htlc(scid, htlc_too_big).unwrap());
    }

    #[test]
    fn test_duplicate_remove_bug_addressed() {
        let mut bucket = GeneralBucket::new(123, TEST_BUCKET_PARAMS).unwrap();
        let scid_1 = 345;
        let scid_2 = 678;

        let scid_1_slots: [(u16, bool); 5] = [0, 3, 4, 5, 7].map(|slot| (slot, false));
        let scid_2_slots: [(u16, bool); 5] = [0, 1, 2, 6, 7].map(|slot| (slot, false));
        bucket.candidate_slots.insert(scid_1, scid_1_slots);
        bucket.candidate_slots.insert(scid_2, scid_2_slots);

        let htlc_amt = bucket.slot_size_msat * 2;
        assert!(bucket.add_htlc(scid_1, htlc_amt).unwrap());
        assert!(bucket.add_htlc(scid_2, htlc_amt).unwrap());

        bucket.remove_htlc(scid_2, htlc_amt).unwrap();
        bucket.remove_htlc(scid_1, htlc_amt).unwrap();
    }
}
