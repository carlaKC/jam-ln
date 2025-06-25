use std::{collections::HashMap, sync::Arc};

use bitcoin::secp256k1::PublicKey;
use lightning::{
    ln::{msgs::LightningError, PaymentHash},
    routing::{
        gossip::NetworkGraph,
        router::{build_route_from_hops, PaymentParameters, Route, RouteParameters},
    },
};
use rand::Rng;
use simln_lib::{
    clock::Clock,
    sim_node::{SimGraph, SimNode, WrappedLog},
};
use tokio::sync::Mutex;

use crate::{clock::InstantClock, reputation_interceptor::ReputationMonitor, BoxError};

pub fn build_custom_route(
    sender: &PublicKey,
    amount_msat: u64,
    hops: &[PublicKey],
    network_graph: &NetworkGraph<&WrappedLog>,
) -> Result<Route, LightningError> {
    let route_params = &RouteParameters {
        payment_params: PaymentParameters::from_node_id(hops[hops.len() - 1], 0)
            .with_max_total_cltv_expiry_delta(u32::MAX)
            .with_max_path_count(1)
            .with_max_channel_saturation_power_of_half(1),
        final_value_msat: amount_msat,
        max_total_routing_fee_msat: None,
    };

    build_route_from_hops(
        sender,
        hops,
        route_params,
        network_graph,
        &WrappedLog {},
        &[0; 32],
    )
}

/// Helper to build reputation for a specific incoming channel (target_channel)
/// by sending a batch of payments. The `routes` param is a map from sender node public keys to their
/// respective `Route`. This allows for building reputation from multiple senders e.g:
///
/// - Route 1: A → B → C
/// - Route 2: D → B → C
///
/// In both cases, the channel B <-> C is the outgoing channel for the last hop, and both senders
/// (A and D) will send payments through this channel.
///
/// The `target_channel` is channel for which reputation is being built. Here we should monitor the
/// outgoing channel reputation against the target_channel revenue.
pub async fn build_reputation<C: Clock + InstantClock, R: ReputationMonitor>(
    attacker_nodes: HashMap<PublicKey, Arc<Mutex<SimNode<SimGraph>>>>,
    routes: HashMap<PublicKey, Route>,
    target_channel: (PublicKey, u64),
    reputation_monitor: Arc<R>,
    clock: Arc<C>,
) -> Result<u64, BoxError> {
    let batch_payments = 20;
    let mut total_fees_paid = 0;

    for (sender, route) in routes {
        let sender_node = attacker_nodes.get(&sender).ok_or(format!(
            "sender {} not found in attacker_nodes",
            sender.to_string()
        ))?;

        let mut sender_node = sender_node.lock().await;
        for _ in 0..batch_payments {
            let hash = PaymentHash(get_random_bytes());
            if let Err(e) = sender_node.send_to_route(route.clone(), hash, None).await {
                return Err(e.to_string().into());
            }
        }

        let last_hop_channel = route.paths[0].hops.last().unwrap().short_channel_id;
        let target_channels = reputation_monitor
            .list_channels(target_channel.0, InstantClock::now(&*clock))
            .await
            .unwrap();

        let reputation_target_channel = target_channels.get(&target_channel.1).unwrap();
        let outgoing_channel = target_channels.get(&last_hop_channel).unwrap();

        // TODO: include in-flight htlc risk
        if outgoing_channel.outgoing_reputation >= reputation_target_channel.bidirectional_revenue {
            println!("FINISHED BUILDING REPUTATION!");
        }
    }

    Ok(total_fees_paid)
}

pub fn get_random_bytes() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    bytes
}
