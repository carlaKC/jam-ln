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

    let mut htlc_amounts = 0;
    let mut htlc_routes = Vec::with_capacity(params.htlcs.len());
    for htlc in params.htlcs {
        htlc_amounts += htlc;

        let attacker_pubkey = params.attacker_node.lock().await.get_info().pubkey;
        let route = build_custom_route(&attacker_pubkey, htlc, params.hops, params.network_graph)
            .map_err(|e| e.err)?;

        htlc_routes.push((htlc, route));
    }

    let (total_fee, htlc_risk) = fee_to_build_reputation(
        htlc_routes,
        &params.reputation_params,
        target_channel.0,
        current_target_revenue,
        current_attacker_reputation,
        5000,
    );

    let total_fees_paid = total_fee + route.get_total_fees();
    for path in route.paths.iter_mut() {
        let target_hop = match path
            .hops
            .iter_mut()
            .find(|hop| hop.pubkey == target_channel.0)
        {
            Some(hop) => hop,
            None => continue,
        };

        // Make a single payment with an inflated fee at the hop we are building reputation with
        target_hop.fee_msat += total_fee;
    }

    if let Err(e) = attacker
        .send_to_route(route, params.payment_hash, None)
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

// Calculates the fee amount that will need to be paid to build sufficient reputation.
// Allows for small buffer to account for decayed average when a reputation check is done
// afterwards.
fn fee_to_build_reputation(
    htlcs: Vec<(u64, Route)>,
    forward_params: &ForwardManagerParams,
    target_hop_pubkey: PublicKey,
    channel_revenue: i64,
    peer_reputation: i64,
    fee_buffer: u64,
) -> (u64, u64) {
    let mut htlc_amounts = 0;
    let mut htlc_risk = 0;
    for (htlc, route) in &htlcs {
        for path in route.paths.iter() {
            let target_hop = match path.hops.iter().find(|hop| hop.pubkey == target_hop_pubkey) {
                Some(hop) => hop,
                None => continue,
            };

            htlc_amounts += htlc;

            htlc_risk += forward_params
                .htlc_opportunity_cost(target_hop.fee_msat, target_hop.cltv_expiry_delta);
        }
    }

    let threshold = if channel_revenue - peer_reputation > 0 {
        channel_revenue - peer_reputation
    } else {
        0
    } as u64;

    let fee_to_bump_reputation = threshold + htlc_amounts + htlc_risk + fee_buffer;

    (fee_to_bump_reputation, htlc_risk)
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::PublicKey;
    use lightning::{
        ln::features::{ChannelFeatures, NodeFeatures},
        routing::router::{Path, Route, RouteHop},
    };
    use ln_resource_mgr::forward_manager::ForwardManagerParams;

    use super::fee_to_build_reputation;
    use crate::test_utils::get_random_keypair;

    fn build_route_with_target_hop(
        target_pubkey: PublicKey,
        fee_msat: u64,
        cltv_expiry_delta: u32,
    ) -> Route {
        let hop = RouteHop {
            pubkey: target_pubkey,
            node_features: NodeFeatures::empty(),
            short_channel_id: 21,
            channel_features: ChannelFeatures::empty(),
            fee_msat,
            cltv_expiry_delta,
            maybe_announced_channel: true,
        };
        let path = Path {
            hops: vec![hop],
            blinded_tail: None,
        };
        Route {
            paths: vec![path],
            route_params: None,
        }
    }

    #[test]
    fn test_calculated_fee_to_build_reputation() {
        let (_, target_pubkey) = get_random_keypair();
        let fwd_params = ForwardManagerParams::default();

        let expiry_delta = 200;
        let htlc_amounts: Vec<u64> = vec![21_000, 42_000, 100_000];
        let fee_pct = 0.0001;

        let htlcs: Vec<(u64, Route)> = htlc_amounts
            .iter()
            .map(|amount| {
                let route = build_route_with_target_hop(
                    target_pubkey,
                    (*amount as f64 * fee_pct) as u64,
                    expiry_delta,
                );
                (*amount, route)
            })
            .collect();

        let channel_revenue = 1_000_000;
        let peer_reputation = 700_000;
        let fee_buffer = 1_000;

        let (fee_to_pay, total_htlc_risk) = fee_to_build_reputation(
            htlcs,
            &fwd_params,
            target_pubkey,
            channel_revenue,
            peer_reputation,
            fee_buffer,
        );

        let expected_htlc_risk = {
            let mut risk = 0;
            for htlc in htlc_amounts.iter() {
                risk +=
                    fwd_params.htlc_opportunity_cost((*htlc as f64 * fee_pct) as u64, expiry_delta);
            }
            risk
        };

        // The fee that we expect to pay is the sum of:
        // - Revenue/reputation diff -> 1000000 - 700000 = 300000
        // - Sum of htlc amounts -> 21000 + 42000 + 100000 = 163000
        // - Sum of risk of each htlc
        // - Fee buffer -> 1000
        let expected_fee = 300_000 + 163_000 + expected_htlc_risk + 1000;

        assert_eq!(fee_to_pay, expected_fee);
        assert_eq!(total_htlc_risk, expected_htlc_risk);
    }
}
