use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use simln_lib::clock::SimulationClock;
use simln_lib::sim_node::{CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode};
use tokio::sync::Mutex;
use triggered::Listener;

use crate::{accountable_from_records, records_from_signal, BoxError, NetworkReputation};

pub mod fast_jam;
pub mod sink;
pub mod utils;

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

    /// Called for every HTLC that is forwarded through an attacking nodes, to allow the attacker to take custom
    /// actions on HTLCs. This function may block, as it is spawned in a task, but *must* eventually return a result.
    /// [`InterceptRequest::outgoing_channel_id`] can safely be unwrapped because this intercept is exclusively used
    /// for forwards that have an outgoing channel.
    ///
    /// The default implementation will forward HTLCs immediately, copying whatever incoming accountable signal it
    /// received.
    async fn intercept_attacker_htlc(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        return Ok(Ok(records_from_signal(accountable_from_records(
            &req.incoming_custom_records,
        ))));
    }

    /// Called for every HTLC that is received on an attacking nodes, to allow the attacker to take custom actions
    /// on HTLCs. This function may block, as it is spawned in a task, but *must* eventually return a result.
    ///
    /// The default implementation will forward HTLCs immediately with no custom records attached (as there's
    /// no outgoing htlc to attach them to anyway).
    async fn intercept_attacker_receive(
        &self,
        _req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        return Ok(Ok(CustomRecords::default()));
    }

    /// This method should perform the core actions of the attack, such as initiating custom
    /// payments, jam channels, or any other attack-specific behavior. Custom payments can be sent
    /// along a specific route with the [`SimNode::send_to_route`] method.
    ///
    /// The implementation is responsible for defining its own shutdown conditions and once it is
    /// complete, return from the method to trigger the simulation to shutdown. It should also
    /// listen for shutdown signals and terminate to avoid blocking the simulation shutdown.
    ///
    /// [`SimNode::send_to_route`]: simln_lib::sim_node::SimNode::send_to_route
    async fn run_attack(
        &self,
        _start_reputation: NetworkReputation,
        _attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>>,
        _shutdown_listener: Listener,
    ) -> Result<(), BoxError>;
}
