use crate::BoxError;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::{AllocationCheck, ProposedForward};

pub mod batch_writer;
pub mod stats_writer;

/// Implemented to report forwards for analytics and data recording.
#[async_trait]
pub trait ForwardReporter: Send + Sync {
    async fn report_forward(
        &mut self,
        forwarding_node: PublicKey,
        decision: AllocationCheck,
        forward: ProposedForward,
    ) -> Result<(), BoxError>;

    async fn write(&mut self, force: bool) -> Result<(), BoxError>;
}
