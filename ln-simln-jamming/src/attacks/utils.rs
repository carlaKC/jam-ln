use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use lightning::{
    ln::{msgs::LightningError, PaymentHash},
    routing::{
        gossip::NetworkGraph,
        router::{build_route_from_hops, PaymentParameters, Route, RouteParameters},
    },
};
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use simln_lib::{
    clock::Clock,
    sim_node::{SimGraph, SimNode, WrappedLog},
    LightningNode, PaymentOutcome,
};
use tokio::sync::Mutex;
use triggered::Listener;

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

pub struct BuildReputationParams<'a, C: Clock + InstantClock, R: ReputationMonitor> {
    pub attacker_node: Arc<Mutex<SimNode<SimGraph>>>,
    pub hops: &'a [PublicKey],
    pub network_graph: &'a NetworkGraph<Arc<WrappedLog>>,
    pub htlcs: Vec<u64>,
    pub target_channel: (PublicKey, u64),
    pub reputation_monitor: Arc<Mutex<R>>,
    pub payment_hash: PaymentHash,
    pub reputation_params: ForwardManagerParams,
    pub clock: Arc<C>,
    pub shutdown_listener: Listener,
}

/// Helper to build outgoing reputation towards the attacker with a specific target_channel.
/// Arguments:
/// - `hops`: The route for the payment that should include the outgoing channel for which we are
///     building reputation with (do not include sender).
/// - htlcs: Vector of htlc amounts that we'd want to be able to have in the protected bucket. E.g
///     if [100_000] is passed, it will build enough reputation to have a 100_000 htlc in the protected
///     bucket for the target channel.
/// - target_channel: The public key and scid for the target channel that we are building
///     reputation for.
/// - payment_hash: Hash to use for the payment that will be made to build the reputation.
/// - reputation_params: Params used to calculate opportunity cost of HTLC.
///     Can use [`ForwardManagerParams::default`].
///
/// Example: `hops` could be the following route:
/// - A → B → C
///
/// The channel B <-> C is the outgoing channel that is building reputation.
/// The `target_channel` is channel for which reputation is being built. So we will monitor the
/// outgoing channel reputation (B <-> C) against the target_channel revenue.
/// If successful, it returns the total fees paid to build reputation.
pub async fn build_reputation<C: Clock + InstantClock, R: ReputationMonitor>(
    params: BuildReputationParams<'_, C, R>,
) -> Result<u64, BoxError> {
    let mut total_fees_paid = 0;

    let reputation_monitor = params.reputation_monitor;
    let target_channel = params.target_channel;
    let clock = params.clock;

    let mut attacker = params.attacker_node.lock().await;
    let attacker_pubkey = attacker.get_info().pubkey;
    let mut route = build_custom_route(&attacker_pubkey, 1000, params.hops, params.network_graph)
        .map_err(|e| e.err)?;

    let last_hop_channel = route.paths[0]
        .hops
        .last()
        .ok_or("built invalid route")?
        .short_channel_id;

    let channels = reputation_monitor
        .lock()
        .await
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?;

    let current_target_revenue = channels
        .get(&target_channel.1)
        .ok_or(format!("target channel {} not found", target_channel.1))?
        .bidirectional_revenue;

    let current_attacker_reputation = channels
        .get(&last_hop_channel)
        .ok_or(format!("channel {} not found", last_hop_channel))?
        .outgoing_reputation;

    let htlc_amounts: u64 = params.htlcs.iter().sum();
    let mut htlc_risk = 0;
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

        htlc_risk = params
            .reputation_params
            .htlc_opportunity_cost(target_hop.fee_msat, target_hop.cltv_expiry_delta)
            * params.htlcs.len() as u64;
        // Add small buffer to account for decayed average when we check if we have built
        // sufficient reputation at the end.
        let buffer = 5_000;
        let fee_to_bump_reputation = threshold as u64 + htlc_amounts + htlc_risk + buffer;

        // Make a single payment with an inflated fee at the hop we are building reputation with
        target_hop.fee_msat += fee_to_bump_reputation;
        total_fees_paid += fee_to_bump_reputation;
    }

    if let Err(e) = attacker
        .send_to_route(route.clone(), params.payment_hash, None)
        .await
    {
        return Err(e.to_string().into());
    }

    let payment_result = attacker
        .track_payment(&params.payment_hash, params.shutdown_listener)
        .await?;

    match payment_result.payment_outcome {
        PaymentOutcome::Success => {}
        _ => return Err("payment to build reputation failed".into()),
    }

    // After making the payment with the inflated fee, check if reputation built over outgoing
    // channel is sufficient.
    let channels = reputation_monitor
        .lock()
        .await
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?;

    let target_revenue = channels
        .get(&target_channel.1)
        .ok_or(format!("target channel {} not found", target_channel.1))?
        .bidirectional_revenue;

    let attacker_reputation = channels
        .get(&last_hop_channel)
        .ok_or(format!("channel {} not found", last_hop_channel))?
        .outgoing_reputation;

    if attacker_reputation as u64 > (target_revenue as u64 + htlc_amounts + htlc_risk) {
        Ok(total_fees_paid)
    } else {
        Err("could not build reputation".into())
    }
}
