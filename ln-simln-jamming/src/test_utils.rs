use std::error::Error;
use std::time::Instant;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning::ln::PaymentHash;
use ln_resource_mgr::{
    AllocationCheck, BucketResources, EndorsementSignal, ForwardingOutcome, ProposedForward,
    ReputationCheck, ResourceCheck,
};
use rand::{distributions::Uniform, Rng};
use simln_lib::sim_node::{CustomRecords, ForwardingError, InterceptRequest};
use simln_lib::ShortChannelID;

use crate::records_from_endorsement;
use crate::reputation_interceptor::BootstrapForward;

#[allow(dead_code)]
pub fn get_random_bytes(size: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(Uniform::new(u8::MIN, u8::MAX))
        .take(size)
        .collect()
}

#[allow(dead_code)]
pub fn get_random_keypair() -> (SecretKey, PublicKey) {
    loop {
        if let Ok(sk) = SecretKey::from_slice(&get_random_bytes(32)) {
            return (sk, PublicKey::from_secret_key(&Secp256k1::new(), &sk));
        }
    }
}

#[allow(dead_code, clippy::type_complexity)]
pub fn setup_test_request(
    forwarding_node: PublicKey,
    channel_in: u64,
    channel_out: u64,
    incoming_endorsed: EndorsementSignal,
) -> (
    InterceptRequest,
    tokio::sync::mpsc::Receiver<
        Result<Result<CustomRecords, ForwardingError>, Box<dyn Error + Send + Sync + 'static>>,
    >,
) {
    let (response, receiver) = tokio::sync::mpsc::channel(1);

    (
        InterceptRequest {
            forwarding_node,
            payment_hash: PaymentHash([1; 32]),
            incoming_htlc: simln_lib::sim_node::HtlcRef {
                channel_id: channel_in.into(),
                index: 0,
            },
            incoming_custom_records: records_from_endorsement(incoming_endorsed),
            outgoing_channel_id: Some(ShortChannelID::from(channel_out)),
            incoming_amount_msat: 100,
            outgoing_amount_msat: 50,
            incoming_expiry_height: 600_010,
            outgoing_expiry_height: 600_000,
            response,
        },
        receiver,
    )
}

#[allow(dead_code)]
pub fn test_allocation_check(forward_succeeds: bool) -> AllocationCheck {
    let check = AllocationCheck {
        reputation_check: ReputationCheck {
            outgoing_reputation: 100_000,
            incoming_revenue: if forward_succeeds { 0 } else { 200_000 },
            in_flight_total_risk: 0,
            htlc_risk: 0,
        },
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
        },
    };

    assert!(
        matches!(
            check.forwarding_outcome(0, EndorsementSignal::Endorsed),
            ForwardingOutcome::Forward(_)
        ) == forward_succeeds
    );

    check
}

#[allow(dead_code)]
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
        incoming_endorsed: EndorsementSignal::Endorsed,
    }
}

#[allow(dead_code)]
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
