use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::AccountableSignal;
use simln_lib::sim_node::{CustomRecords, InterceptRequest};
use std::collections::hash_map::Entry;
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
pub struct ReputationPair {
    pub incoming_revenue: i64,
    pub outgoing_reputation: i64,
    pub scid: u64,
}

pub async fn get_reputation_pairs<R: ReputationMonitor>(
    reputation_monitor: Arc<R>,
    channels: &[(PublicKey, u64)],
    access_ins: Instant,
) -> Result<HashMap<PublicKey, HashMap<u64, Vec<ReputationPair>>>, BoxError> {
    let mut reputation_view = HashMap::new();

    // For each our of our node's channels with its peers.
    for (peer_pubkey, our_channel) in channels.iter() {
        // Look up the peer's reputation scores for all of its channels.
        let peer_channels = reputation_monitor
            .list_channels(*peer_pubkey, access_ins)
            .await?;

        let our_channel_reputation = peer_channels
            .get(our_channel)
            .ok_or(format!(
                "our channel: {our_channel} not found with peer: {peer_pubkey}"
            ))?
            .outgoing_reputation;

        // Create reputation pairs for our channel with each one of the peer's other channels.
        let mut reputation_pairs = Vec::with_capacity(peer_channels.len() - 1);
        for (pair_scid, reputation_snapshot) in peer_channels {
            // We don't need to make a reputation pair with our own channel.
            if pair_scid == *our_channel {
                continue;
            }

            reputation_pairs.push(ReputationPair {
                incoming_revenue: reputation_snapshot.bidirectional_revenue,
                outgoing_reputation: our_channel_reputation,
                scid: pair_scid,
            });
        }

        // We should allow multiple channels per peer, but should not allow adding the same
        // channel more than once.
        match reputation_view
            .entry(*peer_pubkey)
            .or_insert_with(HashMap::new)
            .entry(*our_channel)
        {
            Entry::Occupied(_) => {
                return Err(format!("unexpected duplicate scid: {our_channel}").into())
            }
            Entry::Vacant(e) => {
                e.insert(reputation_pairs);
            }
        }
    }

    Ok(reputation_view)
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetworkReputation {
    pub target_reputation: usize,
    pub target_pair_count: usize,
    pub attacker_reputation: usize,
    pub attacker_pair_count: usize,
}

/// Provides a summary of the following reputation statistics:
/// - Target's reputation with honest peers: the reputation that the target has with any honest
///   peers, filtering out the attacker.
/// - Attacker's reputation with target: the reputation that the attacker has on any channels
///   with the target, filtering out any honest peers.
#[allow(clippy::too_many_arguments)]
pub async fn get_network_reputation<R: ReputationMonitor>(
    reputation_monitor: Arc<R>,
    target_pubkey: PublicKey,
    attacker_pubkeys: Vec<PublicKey>,
    target_chanels: &[(PublicKey, u64)],
    attacker_channels: &[(PublicKey, u64)],
    risk_margin: u64,
    access_ins: Instant,
) -> Result<NetworkReputation, BoxError> {
    let mut peers_view_of_target =
        get_reputation_pairs(reputation_monitor.clone(), target_chanels, access_ins).await?;
    let peers_view_of_attacker =
        get_reputation_pairs(reputation_monitor, attacker_channels, access_ins).await?;

    // We don't care what the attacker's opinion of the target's reputation is, so we filter out
    // any attacker nodes from the view of the target.
    for pk in attacker_pubkeys.iter() {
        peers_view_of_target.remove(pk);
    }

    // TODO: make this more generic, checking attacker's reputation with all its peers.
    let target_view_of_attacker = peers_view_of_attacker
        .get(&target_pubkey)
        .ok_or("attacker does not have a channel with the target")?;

    Ok(NetworkReputation {
        target_reputation: peers_view_of_target
            .values()
            .flat_map(|scid_map| scid_map.values().flatten())
            .filter(|pair| pair.outgoing_reputation >= pair.incoming_revenue + risk_margin as i64)
            .count(),
        target_pair_count: peers_view_of_target
            .values()
            .flat_map(|scid_map| scid_map.values())
            .flat_map(|pairs| pairs.iter())
            .count(),
        attacker_reputation: target_view_of_attacker
            .iter()
            .flat_map(|pairs| pairs.1)
            .filter(|pair| pair.outgoing_reputation >= pair.incoming_revenue + risk_margin as i64)
            .count(),
        attacker_pair_count: target_view_of_attacker
            .iter()
            .flat_map(|pairs| pairs.1.iter())
            .count(),
    })
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
    use ln_resource_mgr::ChannelSnapshot;
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
    /// --(6)-- P2 --(2) -- Target --(0) -- Attacker -- (7) -- P4
    ///				        |
    ///         P3 --(3) ---+
    #[tokio::test]
    async fn test_get_network_reputation() {
        let mut mock_monitor = MockMonitor::new();
        let now = Instant::now();

        let target_pubkey = get_random_keypair().1;
        let attacker_pubkey = get_random_keypair().1;

        let peer_1 = get_random_keypair().1;
        let peer_2 = get_random_keypair().1;
        let peer_3 = get_random_keypair().1;
        let peer_4 = get_random_keypair().1;
        let target_channels: Vec<(PublicKey, u64)> =
            vec![(peer_1, 1), (peer_2, 2), (peer_3, 3), (attacker_pubkey, 0)];

        let attacker_channels: Vec<(PublicKey, u64)> = vec![(target_pubkey, 0), (peer_4, 7)];

        mock_monitor
            .expect_list_channels()
            .returning(move |pubkey, _| {
                let data = if pubkey == target_pubkey {
                    vec![
                        (
                            0,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 100,
                                bidirectional_revenue: 15,
                            },
                        ),
                        (
                            1,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 150,
                                bidirectional_revenue: 110,
                            },
                        ),
                        (
                            2,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 200,
                                bidirectional_revenue: 90,
                            },
                        ),
                        (
                            3,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 75,
                                bidirectional_revenue: 100,
                            },
                        ),
                    ]
                } else if pubkey == attacker_pubkey {
                    vec![
                        (
                            0,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                // The target will have reputation with the attacker, but this
                                // shouldn't matter because we trim the attacking channel from our
                                // results.
                                outgoing_reputation: 900_000,
                                bidirectional_revenue: 0,
                            },
                        ),
                        (
                            7,
                            ChannelSnapshot {
                                capacity_msat: 500_000,
                                outgoing_reputation: 0,
                                bidirectional_revenue: 0,
                            },
                        ),
                    ]
                } else if pubkey == peer_1 {
                    vec![
                        (
                            1,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 500,
                                bidirectional_revenue: 15,
                            },
                        ),
                        (
                            4,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 150,
                                bidirectional_revenue: 600,
                            },
                        ),
                        (
                            5,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 200,
                                bidirectional_revenue: 250,
                            },
                        ),
                    ]
                } else if pubkey == peer_2 {
                    vec![
                        (
                            2,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 1000,
                                bidirectional_revenue: 50,
                            },
                        ),
                        (
                            6,
                            ChannelSnapshot {
                                capacity_msat: 200_000,
                                outgoing_reputation: 350,
                                bidirectional_revenue: 800,
                            },
                        ),
                    ]
                } else if pubkey == peer_3 {
                    vec![(
                        3,
                        ChannelSnapshot {
                            capacity_msat: 200_000,
                            outgoing_reputation: 1000,
                            bidirectional_revenue: 50,
                        },
                    )]
                } else if pubkey == peer_4 {
                    vec![(
                        7,
                        ChannelSnapshot {
                            capacity_msat: 500_000,
                            // The attacker has reputation with peer_3, but this value should
                            // be trimmed because we only care about the target's opinion.
                            outgoing_reputation: 5000,
                            bidirectional_revenue: 0,
                        },
                    )]
                } else {
                    panic!(
                        "unexpected pubkey: {}, expect: target {} or 1: {} or 2: {} or 3: {}",
                        pubkey, target_pubkey, peer_1, peer_2, peer_3
                    );
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
            Arc::new(mock_monitor),
            target_pubkey,
            vec![attacker_pubkey],
            &target_channels,
            &attacker_channels,
            0,
            now,
        )
        .await
        .unwrap();

        assert_eq!(expected_reputation, network_reputation);
    }
}
