use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::{AccountableSignal, ChannelSnapshot, ReputationParams};
use simln_lib::sim_node::{CustomRecords, InterceptRequest};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;

use self::reputation_interceptor::ReputationMonitor;

pub mod analysis;
pub mod attack_interceptor;
pub mod attacks;
pub mod clock;
pub mod parsing;
pub mod reputation_interceptor;
pub mod revenue_interceptor;
pub(crate) mod test_utils;

/// Error type for errors that can be erased, includes 'static so that down-casting is possible.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// The TLV type used to represent experimental accountable signals.
pub const ACCOUNTABLE_TYPE: u64 = 106823;

/// The TLV type used to represent upgradable accountability signal. In real life this will be in
/// the onion.
pub const UPGRADABLE_TYPE: u64 = 106825;

/// Converts a set of custom tlv records to an accountable signal.
pub fn accountable_from_records(records: &CustomRecords) -> AccountableSignal {
    match records.get(&ACCOUNTABLE_TYPE) {
        Some(accountable) => {
            if accountable.len() == 1 && accountable[0] == 1 {
                AccountableSignal::Accountable
            } else {
                AccountableSignal::Unaccountable
            }
        }
        None => AccountableSignal::Unaccountable,
    }
}

/// Converts a set of custom tlv records to a bool signaling if the accountable signal is
/// upgradable.
pub fn upgradable_from_records(records: &CustomRecords) -> bool {
    match records.get(&UPGRADABLE_TYPE) {
        Some(upgradable) => upgradable.len() == 1 && upgradable[0] == 1,
        None => false,
    }
}

/// Converts an accountable signal to custom records using the blip-04 experimental TLV. Note that
/// we add by default the upgradable accountability signal to the custom records returned.
pub fn records_from_signal(signal: AccountableSignal) -> CustomRecords {
    let mut records = CustomRecords::default();
    records.insert(UPGRADABLE_TYPE, vec![1]);
    match signal {
        AccountableSignal::Unaccountable => records,
        AccountableSignal::Accountable => {
            records.insert(ACCOUNTABLE_TYPE, vec![1]);
            records
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetworkReputation {
    pub target_reputation: usize,
    pub target_pair_count: usize,
    pub attacker_reputation: usize,
    pub attacker_pair_count: usize,
}

#[allow(clippy::too_many_arguments)]
pub async fn get_network_reputation<R: ReputationMonitor>(
    reputation_params: &ReputationParams,
    reputation_monitor: Arc<R>,
    target_pubkey: PublicKey,
    attacker_pubkeys: &[PublicKey],
    target_channels: &HashMap<u64, PublicKey>,
    margin_blocks: u32,
    margin_msat: u64,
    access_ins: Instant,
) -> Result<NetworkReputation, BoxError> {
    let target_channels_snapshot = reputation_monitor
        .list_channels(target_pubkey, access_ins)
        .await?;

    let mut network_reputation = NetworkReputation {
        attacker_reputation: 0,
        attacker_pair_count: 0,
        target_pair_count: 0,
        target_reputation: 0,
    };

    for (scid, pubkey) in target_channels {
        // If we've got a chanel with the attacker, we want to get a snapshot of what its reputation is with the
        // target node. Otherwise, we'll get a snapshot of what the target node's reputation is with its peers.
        let (channels, is_attacker) = if attacker_pubkeys.contains(pubkey) {
            (&target_channels_snapshot, true)
        } else {
            (
                &reputation_monitor
                    .list_channels(*pubkey, access_ins)
                    .await?,
                false,
            )
        };

        let repuation_pairs = count_reputation_pairs(
            reputation_params,
            channels,
            *scid,
            margin_blocks,
            margin_msat,
        )?;
        let total_paris = channels.len() - 1;

        if is_attacker {
            network_reputation.attacker_reputation += repuation_pairs;
            network_reputation.attacker_pair_count += total_paris;
        } else {
            network_reputation.target_reputation += repuation_pairs;
            network_reputation.target_pair_count += total_paris;
        }
    }

    Ok(network_reputation)
}

/// Counts the number of pairs that the outgoing channel has reputation for.
fn count_reputation_pairs(
    reputation_params: &ReputationParams,
    channels: &HashMap<u64, ChannelSnapshot>,
    outgoing_channel: u64,
    margin_blocks: u32,
    margin_msat: u64,
) -> Result<usize, BoxError> {
    let outgoing_channel_snapshot = channels
        .get(&outgoing_channel)
        .ok_or(format!("outgoing channel: {} not found", outgoing_channel))?;

    Ok(channels
        .iter()
        .filter(|(scid, snapshot)| {
            // Reputation is assessed for a channel pair and a specific HTLC that's being proposed.
            // To assess whether pairs have reputation, we'll use LND's default fee policy to get
            // the HTLC risk for our configured htlc size and hold time.
            //
            // TODO: deduplicate this logic with incoming_channel.
            let capacicty_utilization =
                snapshot.incoming_liquidity_utilization / snapshot.capacity_msat as f64;
            let slot_utilization =
                snapshot.incoming_slot_utilization.max(1.0) / snapshot.non_general_slots as f64;
            let risk_margin = reputation_params.opportunity_cost_from_blocks(
                1000 + (0.0001 * margin_msat as f64) as u64,
                margin_blocks,
            ) as f64
                * slot_utilization.max(capacicty_utilization);

            **scid != outgoing_channel
                && outgoing_channel_snapshot.outgoing_reputation
                    >= snapshot.incoming_revenue + risk_margin.round() as i64
        })
        .count())
}

/// Prints the details of an interception request.
fn print_request(req: &InterceptRequest) -> String {
    format!(
        "{}:{} {} -> {} with fee {} ({} -> {}) and cltv {} ({} -> {})",
        u64::from(req.incoming_htlc.channel_id),
        req.incoming_htlc.index,
        accountable_from_records(&req.incoming_custom_records),
        if let Some(outgoing_chan) = req.outgoing_channel_id {
            outgoing_chan.into()
        } else {
            0
        },
        req.incoming_amount_msat - req.outgoing_amount_msat,
        req.incoming_amount_msat,
        req.outgoing_amount_msat,
        req.incoming_expiry_height - req.outgoing_expiry_height,
        req.incoming_expiry_height,
        req.outgoing_expiry_height
    )
}

#[cfg(test)]
mod tests {
    use crate::get_network_reputation;
    use crate::reputation_interceptor::ReputationMonitor;
    use crate::test_utils::get_random_keypair;
    use crate::{BoxError, NetworkReputation};
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use ln_resource_mgr::{ChannelSnapshot, ReputationParams};
    use mockall::mock;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;

    mock! {
        Monitor{}

        #[async_trait]
        impl ReputationMonitor for Monitor{
            async fn list_channels(&self, node: PublicKey, access_ins: Instant) -> Result<HashMap<u64, ChannelSnapshot>, BoxError>;
        }
    }

    /// Tests fetching network reputation pairs for the following topology:
    ///
    /// --(4) --+
    ///         |
    /// --(5)-- P1 --(1) ---+
    ///				        |
    /// --(6)-- P2 --(2) -- Target --(0) -- Attacker
    ///				        |
    ///         P3 --(3) ---+
    #[tokio::test]
    async fn test_get_network_reputation() {
        let mut mock_monitor = MockMonitor::new();
        let now = Instant::now();

        let target_pubkey = get_random_keypair().1;
        let attacker_pubkey = vec![get_random_keypair().1];

        let peer_1 = get_random_keypair().1;
        let peer_2 = get_random_keypair().1;
        let peer_3 = get_random_keypair().1;
        let target_channels: HashMap<u64, PublicKey> = vec![
            (0, attacker_pubkey[0]),
            (1, peer_1),
            (2, peer_2),
            (3, peer_3),
        ]
        .into_iter()
        .collect();

        mock_monitor
            .expect_list_channels()
            .returning(move |pubkey, _| {
                let data = if pubkey == target_pubkey {
                    vec![
                        (
                            0,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 100,
                                incoming_revenue: 15,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                        (
                            1,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 150,
                                incoming_revenue: 110,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                        (
                            2,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 200,
                                incoming_revenue: 90,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                        (
                            3,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 75,
                                incoming_revenue: 100,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                    ]
                } else if pubkey == peer_1 {
                    vec![
                        (
                            1,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 500,
                                incoming_revenue: 15,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                        (
                            4,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 150,
                                incoming_revenue: 600,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                        (
                            5,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 200,
                                incoming_revenue: 250,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                    ]
                } else if pubkey == peer_2 {
                    vec![
                        (
                            2,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 1000,
                                incoming_revenue: 50,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                        (
                            6,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                non_general_slots: 100,
                                outgoing_reputation: 350,
                                incoming_revenue: 800,
                                incoming_liquidity_utilization: 0.0,
                                incoming_slot_utilization: 0.0,
                            },
                        ),
                    ]
                } else if pubkey == peer_3 {
                    vec![(
                        3,
                        ChannelSnapshot {
                            capacity_msat: 200_000,
                            non_general_slots: 100,
                            outgoing_reputation: 1000,
                            incoming_revenue: 50,
                            incoming_liquidity_utilization: 0.0,
                            incoming_slot_utilization: 0.0,
                        },
                    )]
                } else {
                    panic!("unexpected pubkey");
                };

                Ok(data.into_iter().collect())
            });

        let expected_reputation = NetworkReputation {
            target_reputation: 2,
            target_pair_count: 3,
            attacker_reputation: 2,
            attacker_pair_count: 3,
        };
        let network_reputation = get_network_reputation(
            &ReputationParams::default(),
            Arc::new(mock_monitor),
            target_pubkey,
            &attacker_pubkey,
            &target_channels,
            0,
            0,
            now,
        )
        .await
        .unwrap();

        assert_eq!(expected_reputation, network_reputation);
    }
}
