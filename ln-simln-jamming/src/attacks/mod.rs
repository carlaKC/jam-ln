use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use simln_lib::sim_node::InterceptRequest;

use crate::{accountable_from_records, records_from_signal, BoxError, NetworkReputation};

pub mod sink;

pub struct NetworkSetup {
    /// The identifier for channel edges that should be general jammed during the simulation.
    ///
    /// For example: a channel with ID 999 between A -- B will have general resources exhausted as follows:
    /// - (999, A): no general resources for A -> B
    /// - (999, B): no general resources for B -> A
    ///
    /// This option is provided as a convenience for attacks that don't wish to implement general jamming the cost of
    /// this general jamming will be accounted for at the end of the attack.
    pub general_jammed_nodes: Vec<(u64, PublicKey)>,
}

// Defines an attack that can be mounted against the simulation framework.
#[async_trait]
pub trait JammingAttack {
    /// Responsible for validating that the network provided meets any topological expectations for the attack, and
    /// returning network-specific setup instructions for the attack.
    ///
    /// The default implementation has no network setup and passes validation.
    fn setup_for_network(&self) -> Result<NetworkSetup, BoxError> {
        Ok(NetworkSetup {
            general_jammed_nodes: vec![],
        })
    }

    /// Called for evey HTLC that is forwarded through or to attacking nodes, to allow the attacker to take custom
    /// actions on HTLCs. This function may block, as it is spawned in a task, but *must* eventually send a response to
    /// the request.
    ///
    /// The default implementation will forward HTLCs immediately, copying whatever incoming accountable signal it
    /// received.
    async fn intercept_attacker_htlc(&self, req: InterceptRequest) -> Result<(), BoxError> {
        req.response
            .send(Ok(Ok(records_from_signal(accountable_from_records(
                &req.incoming_custom_records,
            )))))
            .await
            .map_err(|e| e.into())
    }

    /// Returns a boolean that indicates whether a shutdown condition for the simulation has been reached.
    ///
    /// Should be used when there are shutdown conditions specific to the attack, the default implementation will
    /// return `Ok(false)`.
    async fn simulation_completed(
        &self,
        _start_reputation: NetworkReputation,
    ) -> Result<bool, BoxError> {
        Ok(false)
    }
}
