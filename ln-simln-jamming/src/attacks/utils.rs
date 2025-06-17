use bitcoin::secp256k1::PublicKey;
use lightning::{
    ln::msgs::LightningError,
    routing::{
        gossip::NetworkGraph,
        router::{build_route_from_hops, PaymentParameters, Route, RouteParameters},
    },
};
use simln_lib::sim_node::WrappedLog;

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
