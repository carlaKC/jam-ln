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
    clock::SimulationClock,
    sim_node::{SimGraph, SimNode, WrappedLog},
    LightningNode, PaymentOutcome,
};
use tokio::sync::Mutex;
use triggered::Listener;

use crate::{clock::InstantClock, reputation_interceptor::ReputationMonitor, BoxError};

// When calculating the fee we should pay to build_reputation, we'll add this offset to account
// for the random one that LDK adds in `build_route_from_hops`.
const CLTV_OFFSET_LDK: u32 = 200;

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

pub struct BuildReputationParams<'a, R: ReputationMonitor> {
    pub attacker_node: Arc<Mutex<SimNode<SimGraph, SimulationClock>>>,
    pub hops: &'a [PublicKey],
    pub network_graph: &'a NetworkGraph<Arc<WrappedLog>>,
    pub htlcs: Vec<u64>,
    pub target_channel: (PublicKey, u64),
    pub reputation_monitor: Arc<R>,
    pub payment_hash: PaymentHash,
    pub reputation_params: ForwardManagerParams,
    pub clock: Arc<SimulationClock>,
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
pub async fn build_reputation<R: ReputationMonitor>(
    params: BuildReputationParams<'_, R>,
) -> Result<u64, BoxError> {
    let reputation_monitor = params.reputation_monitor;
    let target_channel = params.target_channel;
    let clock = params.clock;

    let mut attacker = params.attacker_node.lock().await;
    let attacker_pubkey = attacker.get_info().pubkey;
    let mut route = build_custom_route(&attacker_pubkey, 1_000, params.hops, params.network_graph)
        .map_err(|e| e.err)?;

    let last_hop_channel = route.paths[0]
        .hops
        .last()
        .ok_or("built invalid route")?
        .short_channel_id;

    let channels = reputation_monitor
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?;

    let current_target_revenue = channels
        .get(&target_channel.1)
        .ok_or(format!("target channel {} not found", target_channel.1))?
        .incoming_revenue;

    let current_attacker_reputation = channels
        .get(&last_hop_channel)
        .ok_or(format!("channel {} not found", last_hop_channel))?
        .outgoing_reputation;

    let mut htlc_routes = Vec::with_capacity(params.htlcs.len());
    for htlc in params.htlcs {
        let route = build_custom_route(&attacker_pubkey, htlc, params.hops, params.network_graph)
            .map_err(|e| e.err)?;
        htlc_routes.push(route);
    }

    let (total_fee, htlc_risk) = fee_to_build_reputation(
        &htlc_routes,
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
        .list_channels(target_channel.0, InstantClock::now(&*clock))
        .await?;

    let target_revenue = channels
        .get(&target_channel.1)
        .ok_or(format!("target channel {} not found", target_channel.1))?
        .incoming_revenue;

    let attacker_reputation = channels
        .get(&last_hop_channel)
        .ok_or(format!("channel {} not found", last_hop_channel))?
        .outgoing_reputation;

    if attacker_reputation as u64 > (target_revenue as u64 + htlc_risk) {
        Ok(total_fees_paid)
    } else {
        Err("could not build reputation".into())
    }
}

// Calculates the fee amount that will need to be paid to build sufficient reputation.
// Allows for small buffer to account for decayed average when a reputation check is done
// afterwards.
fn fee_to_build_reputation(
    htlc_routes: &[Route],
    forward_params: &ForwardManagerParams,
    target_hop_pubkey: PublicKey,
    channel_revenue: i64,
    peer_reputation: i64,
    fee_buffer: u32,
) -> (u64, u64) {
    let mut total_htlc_risk = 0;
    for route in htlc_routes {
        for path in &route.paths {
            if let Some(target_idx) = path
                .hops
                .iter()
                .position(|hop| hop.pubkey == target_hop_pubkey)
            {
                // Add up the cltv_delta(s) from the target hop to get the total number of blocks
                // until the htlc can be resolved. Here we assume the current height is 0.
                //
                // We use `build_route_from_hops` from LDK to build the routes for the
                // payments. However, that method adds a random CLTV offset so the route we got
                // here could have a different `cltv_expiry_delta` from a route we got another time
                // after we have built reputation. Differences in the cltv deltas in some cases
                // could cause the calculated fee here to not be enough. Hence, we default to
                // a reasonably higher value of `CLTV_OFFSET_LDK` which should be enough
                // to cover the random offset.
                let cltv_expiry: u32 = path.hops[target_idx..]
                    .iter()
                    .map(|h| h.cltv_expiry_delta)
                    .sum();

                let target_hop = &path.hops[target_idx];
                let current_htlc_risk = forward_params
                    .htlc_opportunity_cost(target_hop.fee_msat, cltv_expiry + CLTV_OFFSET_LDK);

                total_htlc_risk += current_htlc_risk;
            }
        }
    }

    let channel_revenue = u64::try_from(channel_revenue).unwrap_or(u64::MAX);
    let peer_reputation = u64::try_from(peer_reputation).unwrap_or(u64::MAX);

    let fee_to_bump_reputation = channel_revenue
        .saturating_add(total_htlc_risk)
        .saturating_add(fee_buffer as u64)
        .saturating_sub(peer_reputation);

    (fee_to_bump_reputation, total_htlc_risk)
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::{collections::HashMap, sync::Arc};

    use bitcoin::secp256k1::PublicKey;
    use lightning::{
        ln::{
            features::{ChannelFeatures, NodeFeatures},
            PaymentHash,
        },
        routing::router::{Path, Route, RouteHop},
    };
    use ln_resource_mgr::{
        forward_manager::{ForwardManager, ForwardManagerParams},
        AccountableSignal,
    };
    use sim_cli::parsing::{create_simulation_with_network, NetworkParser, SimParams};
    use simln_lib::{
        clock::SimulationClock,
        sim_node::{populate_network_graph, Interceptor, SimulatedChannel},
        LightningNode, PaymentOutcome, ShortChannelID, SimulationCfg,
    };
    use tokio_util::task::TaskTracker;
    use triggered::trigger;

    use super::fee_to_build_reputation;
    use crate::{
        analysis::BatchForwardWriter,
        attacks::utils::{
            build_custom_route, build_reputation, BuildReputationParams, CLTV_OFFSET_LDK,
        },
        records_from_signal,
        reputation_interceptor::{ChannelJammer, ReputationInterceptor},
        test_utils::{get_random_keypair, setup_test_edge},
    };

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

    /// Creates a four hop network: Alice - Bob - Carol - Dave
    /// It sets an extra channel: Alice - Carol for the purposes of the test setup needed here.
    /// Tests will try to jam the channel between Bob - Carol and use the channel Alice - Carol
    /// to build reputation.
    // Took mostly from `setup_three_hop_network_edges` but with the extra node and channel
    // specifically for the setup needed here.
    pub fn setup_four_hop_network_edges() -> (ForwardManagerParams, Vec<NetworkParser>) {
        let alice = get_random_keypair().1;
        let bob = get_random_keypair().1;
        let carol = get_random_keypair().1;
        let dave = get_random_keypair().1;

        let alice_bob = ShortChannelID::from(1);
        let alice_carol = ShortChannelID::from(2);
        let bob_carol = ShortChannelID::from(3);
        let carol_dave = ShortChannelID::from(4);

        let params = ForwardManagerParams::default();

        let edges = vec![
            setup_test_edge(alice_bob, alice, bob),
            setup_test_edge(alice_carol, alice, carol),
            setup_test_edge(bob_carol, bob, carol),
            setup_test_edge(carol_dave, carol, dave),
        ];

        (params, edges)
    }

    #[test]
    fn test_calculated_fee_to_build_reputation() {
        struct TestCase {
            htlc_amounts: Vec<u64>,
            channel_revenue: i64,
            peer_reputation: i64,
            fee_buffer: u32,
            expected_fee: u64,
            expected_risk: u64,
        }

        let (_, target_pubkey) = get_random_keypair();
        let fwd_params = ForwardManagerParams::default();

        let expiry_delta = 80;
        let fee_pct = 0.0001;

        let htlc_amounts = vec![21_000, 42_000, 100_000];
        let htlc_risk = {
            let mut risk = 0;
            for htlc in htlc_amounts.iter() {
                risk += fwd_params.htlc_opportunity_cost(
                    (*htlc as f64 * fee_pct) as u64,
                    expiry_delta + CLTV_OFFSET_LDK,
                );
            }
            risk
        };

        let cases = vec![
            // The fee that we expect to pay is the sum of:
            // - Revenue/reputation diff -> 1000000 - 700000 = 300000
            // - Sum of htlc risks
            // - Fee buffer -> 1000
            TestCase {
                htlc_amounts: htlc_amounts.clone(),
                channel_revenue: 1_000_000,
                peer_reputation: 700_000,
                fee_buffer: 1_000,
                expected_fee: 300_000 + htlc_risk + 1_000,
                expected_risk: htlc_risk,
            },
            // In this case we have sufficient reputation so we don't expect to pay any additional
            // fee
            TestCase {
                htlc_amounts: htlc_amounts.clone(),
                channel_revenue: 1_000_000,
                peer_reputation: 1_500_000,
                fee_buffer: 1_000,
                expected_fee: 0,
                expected_risk: htlc_risk,
            },
            // Case where we have partial reputation needed to cover the payment.
            TestCase {
                htlc_amounts,
                channel_revenue: 1_000_000,
                peer_reputation: 1_010_000,
                fee_buffer: 1_000,
                expected_fee: htlc_risk + 1_000 - 10_000,
                expected_risk: htlc_risk,
            },
        ];

        for test in cases {
            let htlc_routes: Vec<Route> = test
                .htlc_amounts
                .iter()
                .map(|amount| {
                    build_route_with_target_hop(
                        target_pubkey,
                        (*amount as f64 * fee_pct) as u64,
                        expiry_delta,
                    )
                })
                .collect();

            let (fee_to_pay, total_htlc_risk) = fee_to_build_reputation(
                &htlc_routes,
                &fwd_params,
                target_pubkey,
                test.channel_revenue,
                test.peer_reputation,
                test.fee_buffer,
            );

            assert_eq!(fee_to_pay, test.expected_fee);
            assert_eq!(total_htlc_risk, test.expected_risk);
        }
    }

    #[tokio::test]
    async fn test_build_reputation() {
        // Alice - Bob - Carol - Dave
        // Here we will build reputation for the Carol - Dave channel to be able to forward
        // payments over Bob - Carol target channel.
        let (params, edges) = setup_four_hop_network_edges();

        let attacker_sender_pubkey = edges[0].node_1.pubkey;
        let target_peer_pubkey = edges[0].node_2.pubkey;
        let target_pubkey = edges[1].node_2.pubkey;
        let attacker_receiver_pubkey = edges[3].node_2.pubkey;

        let target_channel_id: u64 = edges[2].scid.into();

        let clock = Arc::new(SimulationClock::new(1).unwrap());
        let reputation_interceptor: ReputationInterceptor<BatchForwardWriter, ForwardManager> =
            ReputationInterceptor::new_for_network(params, &edges, Arc::clone(&clock), None)
                .unwrap();

        let network_graph = {
            let channels = edges
                .clone()
                .into_iter()
                .map(|c| SimulatedChannel::new(c.capacity_msat, c.scid, c.node_1, c.node_2, false))
                .collect::<Vec<SimulatedChannel>>();

            Arc::new(populate_network_graph(channels, Arc::clone(&clock)).unwrap())
        };

        let sim_params = SimParams {
            nodes: vec![],
            sim_network: edges.clone(),
            activity: vec![],
            exclude: vec![],
        };

        let reputation_interceptor = Arc::new(reputation_interceptor);
        let simulation_reputation_interceptor = Arc::clone(&reputation_interceptor);
        let interceptors: Vec<Arc<dyn Interceptor>> = vec![simulation_reputation_interceptor];
        let sim_cfg = SimulationCfg::new(None, 3_800_000, 2.0, None, Some(13995354354227336701));
        let (simulation, validated_activities, sim_nodes) = create_simulation_with_network(
            sim_cfg,
            &sim_params,
            Arc::clone(&clock),
            TaskTracker::new(),
            interceptors,
            HashMap::default(),
        )
        .await
        .unwrap();

        let simulation_shutdown = simulation.clone();

        tokio::spawn(async move {
            simulation.run(&validated_activities).await.unwrap();
        });

        let shutdown = trigger();
        let attacker_node = sim_nodes.get(&attacker_sender_pubkey).unwrap();
        let target_channel = (target_pubkey, target_channel_id);
        let hops = vec![target_pubkey, attacker_receiver_pubkey];

        let reputation_monitor: Arc<ReputationInterceptor<BatchForwardWriter, ForwardManager>> =
            Arc::clone(&reputation_interceptor);

        let hops_with_target_channel =
            vec![target_peer_pubkey, target_pubkey, attacker_receiver_pubkey];

        // Before we have built reputation, check that an accountable HTLC fails.
        let route = build_custom_route(
            &attacker_sender_pubkey,
            1_000_000,
            &hops_with_target_channel,
            &network_graph,
        )
        .unwrap();

        let records_with_accountable = records_from_signal(AccountableSignal::Accountable);
        let mut attacker_node_lock = attacker_node.lock().await;
        let payment_hash = PaymentHash(rand::random());
        attacker_node_lock
            .send_to_route(route, payment_hash, Some(records_with_accountable))
            .await
            .unwrap();

        let payment_result = attacker_node_lock
            .track_payment(&payment_hash, shutdown.1.clone())
            .await
            .unwrap();

        if let PaymentOutcome::Success = payment_result.payment_outcome {
            panic!("Expected payment with insufficient reputation to fail")
        };

        drop(attacker_node_lock);

        let build_rep_params = BuildReputationParams {
            attacker_node: Arc::clone(attacker_node),
            hops: &hops,
            target_channel,
            // build reputation for this payment amount
            htlcs: vec![21_000],
            network_graph: &network_graph,
            payment_hash: PaymentHash(rand::random()),
            reputation_monitor,
            reputation_params: ForwardManagerParams::default(),
            clock: Arc::clone(&clock),
            shutdown_listener: shutdown.1.clone(),
        };

        let _ = build_reputation(build_rep_params).await.unwrap();

        // After building reputation, jam resources on the target channel to then check if further
        // payment can be forwarded as expected.
        reputation_interceptor
            .jam_general_resources(&target_pubkey, target_channel_id)
            .await
            .unwrap();

        reputation_interceptor
            .jam_congestion_resources(&target_pubkey, target_channel_id)
            .await
            .unwrap();

        // Resources on target channel are jammed but payment for our targeted amount should
        // succeed after building reputation.
        let route = build_custom_route(
            &attacker_sender_pubkey,
            21_000,
            &hops_with_target_channel,
            &network_graph,
        )
        .unwrap();

        let mut attacker_node_lock = attacker_node.lock().await;
        let hash_1 = PaymentHash(rand::random());
        attacker_node_lock
            .send_to_route(route, hash_1, None)
            .await
            .unwrap();

        let payment_result = attacker_node_lock
            .track_payment(&hash_1, shutdown.1.clone())
            .await
            .unwrap();

        match payment_result.payment_outcome {
            PaymentOutcome::Success => {}
            _ => {
                panic!("Expected payment with sufficient reputation to succeed")
            }
        };

        simulation_shutdown.shutdown();
    }
}
