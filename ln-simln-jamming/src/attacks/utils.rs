use std::{sync::Arc, thread, time::Duration};

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
    LightningNode,
};
use tokio::sync::Mutex;

use crate::{clock::InstantClock, reputation_interceptor::ReputationMonitor, BoxError};

pub fn build_custom_route(
    sender: &PublicKey,
    amount_msat: u64,
    hops: &[PublicKey],
    network_graph: &NetworkGraph<Arc<WrappedLog>>,
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

/// Helper to build reputation for a specific incoming channel (target_channel).
/// Arguments:
/// - `hops`: The route for the payment that should include the outgoing channel for which we are
/// building reputation with (do not include sender).
/// - htlcs: Vector of htlc amounts that we'd want to be able to have in the protected bucket. E.g
/// if [100_000] is passed, it will build enough reputation to have a 100_000 htlc in the protected
/// bucket for the target channel.
/// - target_channel: The public key and scid for the target channel that we are building
/// reputation for.
///
/// Example: `hops` could be the following route:
/// - A → B → C
///
/// The channel B <-> C is the outgoing channel that is building reputation.
/// The `target_channel` is channel for which reputation is being built. So we will monitor the
/// outgoing channel reputation (B <-> C) against the target_channel revenue.
/// If successful, it returns the total fees paid to build reputation.
#[allow(clippy::too_many_arguments)]
pub async fn build_reputation<C: Clock + InstantClock, R: ReputationMonitor>(
    attacker_node: Arc<Mutex<SimNode<SimGraph>>>,
    hops: &[PublicKey],
    network_graph: &NetworkGraph<Arc<WrappedLog>>,
    htlcs: Vec<u64>,
    risk_margin: u64,
    target_channel: (PublicKey, u64),
    reputation_monitor: Arc<Mutex<R>>,
    clock: Arc<C>,
) -> Result<u64, BoxError> {
    let mut total_fees_paid = 0;

    let mut attacker = attacker_node.lock().await;
    let current_target_revenue = reputation_monitor
        .lock()
        .await
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?
        .get(&target_channel.1)
        .ok_or(format!("target channel {} not found", target_channel.1))?
        .bidirectional_revenue;

    let attacker_pubkey = attacker.get_info().pubkey;
    let mut route =
        build_custom_route(&attacker_pubkey, 1000, hops, network_graph).map_err(|e| e.err)?;

    let last_hop_channel = route.paths[0]
        .hops
        .last()
        .ok_or("built invalid route")?
        .short_channel_id;

    let current_attacker_reputation = reputation_monitor
        .lock()
        .await
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?
        .get(&last_hop_channel)
        .ok_or(format!("channel {} not found", last_hop_channel))?
        .outgoing_reputation;

    let htlc_amounts: u64 = htlcs.iter().sum();
    for path in route.paths.iter_mut() {
        total_fees_paid += path.hops.iter().map(|hop| hop.fee_msat).sum::<u64>();
        let target_hop = match path
            .hops
            .iter_mut()
            .find(|hop| hop.pubkey == target_channel.0)
        {
            Some(hop) => hop,
            None => continue,
        };

        let threshold = if current_target_revenue - current_attacker_reputation > 0 {
            current_target_revenue - current_attacker_reputation
        } else {
            0
        };

        let fee_to_bump_reputation = threshold as u64 + htlc_amounts + risk_margin * 2;

        // Make a single payment with an inflated fee at the hop we are building reputation with
        target_hop.fee_msat += fee_to_bump_reputation;
        total_fees_paid += fee_to_bump_reputation;
    }

    let payment_hash = PaymentHash(get_random_bytes());
    if let Err(e) = attacker
        .send_to_route(route.clone(), payment_hash, None)
        .await
    {
        return Err(e.to_string().into());
    }

    thread::sleep(Duration::from_millis(400));

    // After making the payment with the inflated fee, check if reputation built over outgoing
    // channel is sufficient.
    let target_revenue = reputation_monitor
        .lock()
        .await
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?
        .get(&target_channel.1)
        .ok_or(format!("channel {} not found", target_channel.1))?
        .bidirectional_revenue;

    let attacker_reputation = reputation_monitor
        .lock()
        .await
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?
        .get(&last_hop_channel)
        .unwrap()
        .outgoing_reputation;

    if attacker_reputation as u64 > (target_revenue as u64 + htlc_amounts + risk_margin) {
        Ok(total_fees_paid)
    } else {
        Err("could not build reputation".into())
    }
}

pub fn get_random_bytes() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    bytes
}
