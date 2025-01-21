use ln_resource_mgr::{EndorsementSignal, ReputationError};
use simln_lib::sim_node::{CustomRecords, ForwardingError};
use std::collections::HashMap;
use std::error::Error;

pub mod clock;
pub mod parsing;
pub mod reputation_interceptor;
pub mod revenue_interceptor;
pub mod sink_interceptor;
pub(crate) mod test_utils;

pub type InterceptResult = Result<Result<HashMap<u64, Vec<u8>>, ForwardingError>, ReputationError>;

/// Error type for errors that can be erased, includes 'static so that down-casting is possible.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// The TLV type used to represent experimental endorsement signals.
pub const ENDORSEMENT_TYPE: u64 = 106823;

/// Converts a set of custom tlv records to an endorsement signal.
pub fn endorsement_from_records(records: &CustomRecords) -> EndorsementSignal {
    match records.get(&ENDORSEMENT_TYPE) {
        Some(endorsed) => {
            if endorsed.len() == 1 && endorsed[0] == 1 {
                EndorsementSignal::Endorsed
            } else {
                EndorsementSignal::Unendorsed
            }
        }
        None => EndorsementSignal::Unendorsed,
    }
}

/// Converts an endorsement signal to custom records using the blip-04 experimental TLV.
pub fn records_from_endorsement(endorsement: EndorsementSignal) -> CustomRecords {
    match endorsement {
        EndorsementSignal::Unendorsed => CustomRecords::default(),
        EndorsementSignal::Endorsed => {
            let mut records = CustomRecords::default();
            records.insert(ENDORSEMENT_TYPE, vec![1]);
            records
        }
    }
}
