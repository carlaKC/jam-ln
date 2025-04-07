use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use simln_lib::sim_node::InterceptRequest;
use simln_lib::NetworkParser;

use crate::{endorsement_from_records, records_from_endorsement, BoxError};

mod sink;

// Defines an attack that can be mounted against the simulation framework.
#[async_trait]
pub trait JammingAttack {
    /// Validates the graph that has been loaded into the simulation.
    ///
    /// Should be used to validate any topology assumptions that the attack makes, to ensure that the simulation is
    /// running with a graph with the expected characteristics. The default implementation will return `Ok(())`.
    fn validate_network(&self, _network: &[NetworkParser]) -> Result<(), BoxError> {
        Ok(())
    }

    /// Returns the list of short channel ides that should be general jammed for the duration of the attack. The public
    /// key provided indicates the channel party whose outgoing resources should be general jammed.
    ///
    /// For example: a channel with ID 999 between A -- B will have general resources exhausted as follows:
    /// - (999, A): no general resources for A -> B
    /// - (999, B): no general resources for B -> A
    ///
    /// This method is provided as a convenience for attacks that don't wish to implement general jamming the cost of
    /// this general jamming will be accounted for at the end of the attack. The default implementation will not jam
    /// any channels.
    fn general_jammed_channels(&self) -> Result<Vec<(u64, PublicKey)>, BoxError> {
        Ok(vec![])
    }

    /// Called for evey HTLC that is forwarded through attacking nodes, to allow the attacker to take custom actions
    /// on HTLCs. This function may block, as it is spawned in a task, but *must* eventually send a response to the
    /// request
    ///
    /// The default implementation will forward HTLCs immediately, copying whatever incoming endorsement signal it
    /// received.
    async fn intercept_attacker_htlc(&self, req: InterceptRequest) -> Result<(), BoxError> {
        req.response
            .send(Ok(Ok(records_from_endorsement(endorsement_from_records(
                &req.incoming_custom_records,
            )))))
            .await
            .map_err(|e| e.into())
    }

    /// Returns a boolean that indicates whether a shutdown condition for the simulation has been reached.
    ///
    /// Should be used when there are shutdown conditions specific to the attack, the default implementation will
    /// return `Ok(false)`.
    fn simulation_completed(&self) -> Result<bool, BoxError> {
        Ok(false)
    }
}
