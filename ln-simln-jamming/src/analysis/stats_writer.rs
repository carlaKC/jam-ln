use super::ForwardReporter;
use crate::BoxError;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use csv::{WriterBuilder, QuoteStyle};
use ln_resource_mgr::{AllocationCheck, ForwardingOutcome, ProposedForward};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct StatsWriter {
    path: PathBuf,
    outcome_statistics: HashMap<String, u16>,
}

impl StatsWriter {
    pub fn new(path: PathBuf) -> Self {
        StatsWriter {
            path,
            outcome_statistics: HashMap::new(),
        }
    }
}

// We settle for String over &'static str for the sake of not needing to write out each variant's
// name.
fn forward_outcome_str(outcome: ForwardingOutcome) -> String {
    match outcome {
        ForwardingOutcome::Forward(accountable) => accountable.to_string().replace(" ", "_"),
        ForwardingOutcome::Fail(reason) => reason.to_string().replace(" ", "_"),
    }
}

#[async_trait]
impl ForwardReporter for StatsWriter {
    async fn report_forward(
        &mut self,
        _forwarding_node: PublicKey,
        decision: AllocationCheck,
        forward: ProposedForward,
    ) -> Result<(), BoxError> {
        *self
            .outcome_statistics
            .entry(forward_outcome_str(decision.forwarding_outcome(
                forward.amount_in_msat,
                forward.incoming_accountable,
                forward.upgradable_accountability,
            )))
            .or_insert(0) += 1;
        Ok(())
    }

    /// Writes summary of network forwards when force is true. No-op when force is false, as this
    /// reporter tracks an amount of data that is trivial to store in memory.
    async fn write(&mut self, force: bool) -> Result<(), BoxError> {
        if !force {
            return Ok(());
        }

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path.join("network_stats.csv"))?;

        let mut writer = WriterBuilder::new()
            .has_headers(true)
            .quote_style(QuoteStyle::Never)
            .from_writer(file);

        writer.write_record(["outcome", "count"])?;

        for (outcome, count) in &self.outcome_statistics {
            writer.write_record([&format!("{:?}", outcome), &count.to_string()])?;
        }

        writer.flush()?;
        Ok(())
    }
}
