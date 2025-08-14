#![cfg(test)]
use std::time::Instant;

use crate::reputation_interceptor::{BootstrapForward, ReputationMonitor};
use crate::revenue_interceptor::PeacetimeRevenueMonitor;
use crate::{records_from_signal, BoxError};
use async_trait::async_trait;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning::ln::PaymentHash;
use ln_resource_mgr::{
    AccountableSignal, AllocationCheck, BucketResources, ChannelSnapshot, ForwardingOutcome,
    ProposedForward, ReputationCheck, ResourceCheck,
};
use mockall::mock;
use rand::Rng;
use sim_cli::parsing::NetworkParser;
use simln_lib::sim_node::{
    ChannelPolicy, CriticalError, CustomRecords, ForwardingError, InterceptRequest,
    InterceptResolution, Interceptor,
};
use simln_lib::ShortChannelID;
use std::collections::HashMap;

mock! {
    pub ReputationInterceptor{}

    #[async_trait]
    impl Interceptor for ReputationInterceptor{
        async fn intercept_htlc(&self, req: InterceptRequest) -> Result<Result<CustomRecords, ForwardingError>, CriticalError>;
        async fn notify_resolution(&self,_res: InterceptResolution) -> Result<(), CriticalError>;
        fn name(&self) -> String;
    }

    #[async_trait]
    impl ReputationMonitor for ReputationInterceptor{
        async fn list_channels(&self, node: PublicKey, access_ins: Instant) -> Result<HashMap<u64, ChannelSnapshot>, BoxError>;
    }
}

mock! {
    pub PeacetimeMonitor{}

    #[async_trait]
    impl PeacetimeRevenueMonitor for PeacetimeMonitor {
        async fn get_revenue_difference(&self) -> crate::revenue_interceptor::RevenueSnapshot;
    }
}

pub fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut bytes = vec![0u8; size];
    rng.fill(&mut bytes[..]);
    bytes.to_vec()
}

pub fn get_random_keypair() -> (SecretKey, PublicKey) {
    loop {
        if let Ok(sk) = SecretKey::from_slice(&get_random_bytes(32)) {
            return (sk, PublicKey::from_secret_key(&Secp256k1::new(), &sk));
        }
    }
}

#[allow(clippy::type_complexity)]
pub fn setup_test_request(
    forwarding_node: PublicKey,
    channel_in: u64,
    channel_out: u64,
    incoming_accountable: AccountableSignal,
) -> InterceptRequest {
    InterceptRequest {
        forwarding_node,
        payment_hash: PaymentHash([1; 32]),
        incoming_htlc: simln_lib::sim_node::HtlcRef {
            channel_id: channel_in.into(),
            index: 0,
        },
        incoming_custom_records: records_from_signal(incoming_accountable),
        outgoing_channel_id: Some(ShortChannelID::from(channel_out)),
        incoming_amount_msat: 100,
        outgoing_amount_msat: 50,
        incoming_expiry_height: 600_010,
        outgoing_expiry_height: 600_000,
        shutdown_listener: triggered::trigger().1,
    }
}

pub fn test_allocation_check(forward_succeeds: bool) -> AllocationCheck {
    let check = AllocationCheck {
        reputation_check: ReputationCheck {
            reputation: 100_000,
            revenue_threshold: if forward_succeeds { 0 } else { 200_000 },
            in_flight_total_risk: 0,
            htlc_risk: 0,
        },
        general_eligible: true,
        congestion_eligible: true,
        resource_check: ResourceCheck {
            general_bucket: BucketResources {
                slots_used: 0,
                slots_available: 10,
                liquidity_used_msat: 0,
                liquidity_available_msat: 100_000,
            },
            congestion_bucket: BucketResources {
                slots_used: 0,
                slots_available: 5,
                liquidity_used_msat: 0,
                liquidity_available_msat: 50_000,
            },
            protected_bucket: BucketResources {
                slots_used: 0,
                slots_available: 10,
                liquidity_used_msat: 0,
                liquidity_available_msat: 100_000,
            },
        },
    };

    assert!(
        matches!(
            check.forwarding_outcome(0, AccountableSignal::Accountable, true),
            ForwardingOutcome::Forward(_)
        ) == forward_succeeds
    );

    check
}

pub fn test_proposed_forward(id: u64) -> ProposedForward {
    ProposedForward {
        incoming_ref: ln_resource_mgr::HtlcRef {
            channel_id: 1,
            htlc_index: id,
        },
        outgoing_channel_id: 2,
        amount_in_msat: 2000,
        amount_out_msat: 1000,
        expiry_in_height: 80,
        expiry_out_height: 40,
        added_at: Instant::now(),
        incoming_accountable: AccountableSignal::Accountable,
        upgradable_accountability: true,
    }
}

pub fn test_bootstrap_forward(
    added_ns: u64,
    settled_ns: u64,
    channel_in_id: u64,
    channel_out_id: u64,
) -> BootstrapForward {
    BootstrapForward {
        incoming_amt: 100_000,
        outgoing_amt: 90_000,
        incoming_expiry: 150,
        outgoing_expiry: 120,
        added_ns,
        settled_ns,
        forwarding_node: get_random_keypair().1,
        channel_in_id,
        channel_out_id,
    }
}

pub fn get_test_policy(pubkey: PublicKey) -> ChannelPolicy {
    ChannelPolicy {
        pubkey,
        alias: "test_node".into(),
        max_htlc_count: 483,
        max_in_flight_msat: 100_000,
        min_htlc_size_msat: 1000,
        max_htlc_size_msat: 100_000,
        cltv_expiry_delta: 40,
        base_fee: 1000,
        fee_rate_prop: 1,
    }
}

fn setup_test_policy(node: PublicKey) -> ChannelPolicy {
    ChannelPolicy {
        pubkey: node,
        alias: "".to_string(),
        max_htlc_count: 483,
        max_in_flight_msat: 1_000_000_000,
        min_htlc_size_msat: 1,
        max_htlc_size_msat: 1_000_000_000,
        cltv_expiry_delta: 40,
        base_fee: 1000,
        fee_rate_prop: 2000,
    }
}

pub fn setup_test_edge(
    scid: ShortChannelID,
    node_1: PublicKey,
    node_2: PublicKey,
) -> NetworkParser {
    NetworkParser {
        scid,
        capacity_msat: 1_000_000_000,
        node_1: setup_test_policy(node_1),
        node_2: setup_test_policy(node_2),
    }
}
