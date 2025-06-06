use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::hashes::Hash;
use rand::Rng;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::usize;

use crate::ReputationError;

/// Defines the number of slots each candidate channel is allowed in the restricted bucket.
const ASSIGNED_SLOTS: usize = 5;

#[derive(Debug)]
pub(super) struct RestrictedBucket {
    /// Short channel ID that represents the channel that the bucket belongs to.
    scid: u64,
    /// Tracks the occupancy of HTLC slots in the channel.
    htlc_slots: Vec<bool>,
    /// Tracks the amount of liquidity allocated to each slot in the channel.
    slot_size_msat: u64,
    /// Maps short channel IDs to the slot indexes that a candidate channel is granted access to.
    //
    // A u16 is used so that we can account for the possiblity that we assign our protocol max of
    // 483 slots, this can be changed to a u8 when only deling with V3 channels.
    candidate_slots: HashMap<u64, [u16; ASSIGNED_SLOTS]>,
}

impl RestrictedBucket {
    /// Creates a new restricted bucket.
    ///
    /// Note that the current implementation is not restart safe:
    /// - It assigns new salt every time a channel is added (should be persisted across restarts).
    /// - It assumes that the bucket is empty on start (should account for in-flight HTLCs).
    pub(super) fn new(
        scid: u64,
        liquidity_msat: u64,
        htlc_slots: u16,
    ) -> Result<Self, ReputationError> {
        let slot_size_msat = liquidity_msat / htlc_slots as u64;
        if slot_size_msat == 0 {
            return Err(ReputationError::ErrUnrecoverable(format!(
                "channel size: {} with {} slots results in zero liquidity bucket",
                liquidity_msat, htlc_slots
            )));
        }

        Ok(Self {
            scid,
            // Totally fill array so that we don't need to worry about checking length.
            htlc_slots: vec![false; htlc_slots as usize],
            slot_size_msat,
            candidate_slots: HashMap::new(),
        })
    }

    /// Produces the set of slots that a channel has permission to use.
    /// Assumes that [`self.htlc_slots`] was been initialized with values set for each slot.
    // TODO: check this for duplicates!
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
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let mut rng = rand::rng();
                let mut salt = [0u8; 32];
                rng.fill(&mut salt);

                let mut result = [0u16; ASSIGNED_SLOTS];

                // We hash the channel pair along with salt and an index to get our slots. We'll
                // add the index on each iteration below.
                let mut data = Vec::with_capacity(salt.len() + 8 + 8 + 8);
                data.extend_from_slice(&salt);
                data.extend_from_slice(&self.scid.to_be_bytes());
                data.extend_from_slice(&candidate_scid.to_be_bytes());
                let i_offset = data.len();
                data.resize(data.len() + 8, 0);

                for i in 0..ASSIGNED_SLOTS {
                    let i_bytes = (i as u64).to_be_bytes();
                    data[i_offset..i_offset + 8].copy_from_slice(&i_bytes);
                    let hash = Sha256dHash::hash(&data);

                    // It's okay to just use the first 8 bytes because we're just using this
                    // for indexing.
                    let hash_num = u64::from_be_bytes(hash[0..8].try_into().map_err(|_| {
                        ReputationError::ErrUnrecoverable(
                            "hash could not be converted to u64".to_string(),
                        )
                    })?);
                    result[i] = (hash_num as usize % self.htlc_slots.len())
                        .try_into()
                        .map_err(|_| {
                            ReputationError::ErrUnrecoverable(format!(
                                "hash num: {} mod htlc slots {} is not a u16",
                                hash_num,
                                self.htlc_slots.len()
                            ))
                        })?;

                    assert!((result[i] as usize) < self.htlc_slots.len());
                }

                entry.insert(result);
                Ok(result)
            }
        }
    }

    /// Returns the indexes of a set of slots that can hold the payment amount provided.
    fn get_usable_slots(
        &mut self,
        candidate_scid: u64,
        amount_msat: u64,
    ) -> Result<Option<Vec<u16>>, ReputationError> {
        let required_liquidity = u64::max(1, amount_msat.div_ceil(self.slot_size_msat));
        let slots = self.get_candidate_slots(candidate_scid)?;

        let available_slots: Vec<u16> = slots
            .into_iter()
            .filter(|&index| !self.htlc_slots[index as usize])
            .collect();

        if (available_slots.len() as u64) < required_liquidity {
            Ok(None)
        } else {
            Ok(Some(
                available_slots
                    .into_iter()
                    .take(required_liquidity as usize)
                    .collect(),
            ))
        }
    }

    pub(super) fn may_add_htlc(
        &mut self,
        candidate_scid: u64,
        amount_msat: u64,
    ) -> Result<bool, ReputationError> {
        Ok(self
            .get_usable_slots(candidate_scid, amount_msat)?
            .is_some())
    }

    pub(super) fn add_htlc(
        &mut self,
        candidate_scid: u64,
        amount_msat: u64,
    ) -> Result<bool, ReputationError> {
        let available_slots =
            if let Some(slots) = self.get_usable_slots(candidate_scid, amount_msat)? {
                slots
            } else {
                return Ok(false);
            };

        // Once we know there's enough liquidity available for the HTLC, we can go ahead and
        // reserve the slots we need.
        for index in available_slots.iter() {
            self.htlc_slots[*index as usize] = true;
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_new_bucket() {
        let bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();
        assert_eq!(bucket.slot_size_msat, 10_000);
        assert_eq!(bucket.htlc_slots.len(), 100);
        assert!(bucket.htlc_slots.iter().all(|b| !*b));
    }

    #[test]
    fn test_new_bucket_zero_slot_size() {
        let result = RestrictedBucket::new(123, 1000, 10_000);
        assert!(matches!(result, Err(ReputationError::ErrUnrecoverable(_))));
    }

    #[test]
    fn test_candidate_slots_existing() {
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();
        let slots = [1, 2, 3, 4, 5];
        bucket.candidate_slots.insert(456, slots);
        assert_eq!(slots, bucket.get_candidate_slots(456).unwrap())
    }

    #[test]
    fn test_candidate_slots_self() {
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();
        assert!(matches!(
            bucket.get_candidate_slots(123),
            Err(ReputationError::ErrUnrecoverable(_))
        ));
    }

    #[test]
    fn test_get_candidate_slots_consistency() {
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();
        let scid = 789;
        let slots1 = bucket.get_candidate_slots(scid).unwrap();
        let slots2 = bucket.get_candidate_slots(scid).unwrap();
        assert_eq!(slots1, slots2);
    }

    #[test]
    fn test_get_candidate_slots_within_bounds_and_unique() {
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();
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
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();
        let scid = 456;

        for _ in 0..ASSIGNED_SLOTS {
            assert!(bucket.add_htlc(scid, 1000).unwrap(),);
        }

        assert!(!bucket.add_htlc(scid, 100_000).unwrap());
    }

    /// Tests that a single HTLC is allowed to take up all liquidity for all slots.
    #[test]
    fn test_liquidity_one_htlc() {
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();

        let max_htlc = bucket.slot_size_msat * ASSIGNED_SLOTS as u64;
        assert!(bucket.add_htlc(345, max_htlc).unwrap());

        assert!(!bucket.add_htlc(345, 1).unwrap());
    }

    /// Tests that when a HTLC takes up a portion of a bucket, another HTLC is not allowed to
    /// share that liquidity.
    #[test]
    fn test_partial_liquidity_usage() {
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();

        let half_allocation = bucket.slot_size_msat * ASSIGNED_SLOTS as u64 / 2;
        assert!(bucket.add_htlc(345, half_allocation).unwrap());

        // Reject a HTLC that needs 2.5 slots worth of liquidity, because the previous htlc
        // used up 3.
        assert!(!bucket.add_htlc(345, half_allocation).unwrap());

        // Accept a HTLC that only needs 2 slots worth of liquidity.
        assert!(bucket.add_htlc(345, bucket.slot_size_msat * 2).unwrap());
    }

    #[test]
    fn test_insufficient_liquidity() {
        let mut bucket = RestrictedBucket::new(123, 1_000_000, 100).unwrap();
        let htlc_too_big = bucket.slot_size_msat * ASSIGNED_SLOTS as u64 * 2;

        assert!(!bucket.add_htlc(345, htlc_too_big).unwrap());
    }
}
