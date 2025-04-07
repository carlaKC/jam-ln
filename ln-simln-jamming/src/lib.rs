use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::{ChannelSnapshot, EndorsementSignal};
use simln_lib::sim_node::CustomRecords;
use std::collections::HashMap;
use std::error::Error;
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

/// The TLV type used to represent experimental endorsement signals.
pub const ENDORSEMENT_TYPE: u64 = 106823;

/// Converts a set of custom tlv records to an endorsement signal.
pub fn endorsement_from_records(records: &CustomRecords) -> EndorsementSignal {
    match records.get(&ENDORSEMENT_TYPE) {
        Some(endorsed) => {
            if endorsed.len() == 1 && endorsed[0] == 1 {
                EndorsementSignal::Endorsed
            } else {
                EndorsementSignal::Unendorsed
            }
        }
        None => EndorsementSignal::Unendorsed,
    }
}

/// Converts an endorsement signal to custom records using the blip-04 experimental TLV.
pub fn records_from_endorsement(endorsement: EndorsementSignal) -> CustomRecords {
    match endorsement {
        EndorsementSignal::Unendorsed => CustomRecords::default(),
        EndorsementSignal::Endorsed => {
            let mut records = CustomRecords::default();
            records.insert(ENDORSEMENT_TYPE, vec![1]);
            records
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct NetworkReputation {
    pub target_reputation: usize,
    pub target_pair_count: usize,
    pub attacker_reputation: usize,
    pub attacker_pair_count: usize,
}

#[allow(clippy::too_many_arguments)]
pub async fn get_network_reputation<R: ReputationMonitor>(
    target_pubkey: PublicKey,
    reputation_monitor: &R,
    attacker_channel: u64,
    honest_channels: &[(u64, PublicKey)],
    risk_margin: u64,
    access_ins: Instant,
) -> Result<NetworkReputation, BoxError> {
    let target_channels = reputation_monitor
        .list_channels(target_pubkey, access_ins)
        .await?;
    let mut network_reputation = NetworkReputation {
        attacker_reputation: count_reputation_pairs(
            &target_channels,
            attacker_channel,
            risk_margin,
        )?,
        // The attacker will be the outgoing channel for each one of the target's channels, except for itself.
        attacker_pair_count: target_channels.len() - 1,
        target_pair_count: 0,
        target_reputation: 0,
    };

    for (scid, pubkey) in honest_channels {
        let peer_channels = reputation_monitor
            .list_channels(*pubkey, access_ins)
            .await?;

        network_reputation.target_reputation +=
            count_reputation_pairs(&peer_channels, *scid, risk_margin)?;

        // The target will be the outgoing channel for each one of the peer's channels, except for itself.
        network_reputation.target_pair_count += peer_channels.len() - 1;
    }

    log::info!(
        "Attacker has {} out of {} pairs with reputation",
        network_reputation.attacker_reputation,
        network_reputation.attacker_pair_count,
    );

    log::info!(
        "Target has {}/{} pairs with reputation with its peers",
        network_reputation.target_reputation,
        network_reputation.target_pair_count,
    );

    Ok(network_reputation)
}

/// Counts the number of pairs that the outgoing channel has reputation for.
fn count_reputation_pairs(
    channels: &HashMap<u64, ChannelSnapshot>,
    outgoing_channel: u64,
    risk_margin: u64,
) -> Result<usize, BoxError> {
    let outgoing_channel_snapshot = channels
        .get(&outgoing_channel)
        .ok_or(format!("outgoing channel: {} not found", outgoing_channel))?;

    Ok(channels
        .iter()
        .filter(|(scid, snapshot)| {
            **scid != outgoing_channel
                && outgoing_channel_snapshot.outgoing_reputation
                    >= snapshot.bidirectional_revenue + risk_margin as i64
        })
        .count())
}

#[cfg(test)]
mod tests {
    use crate::reputation_interceptor::{HtlcAdd, ReputationMonitor};
    use crate::test_utils::get_random_keypair;
    use crate::{count_reputation_pairs, get_network_reputation};
    use crate::{BoxError, NetworkReputation};
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use ln_resource_mgr::{AllocationCheck, ChannelSnapshot, ReputationError};
    use mockall::mock;
    use std::collections::HashMap;
    use std::time::Instant;

    mock! {
        Monitor{}

        #[async_trait]
        impl ReputationMonitor for Monitor{
            async fn list_channels(&self, node: PublicKey, access_ins: Instant) -> Result<HashMap<u64, ChannelSnapshot>, BoxError>;
           async fn check_htlc_outcome(&self,htlc_add: HtlcAdd) -> Result<AllocationCheck, ReputationError>;
        }
    }

    /// Tests counting the number of pairs that an outgoing channel has good reputation on. Uses a zero risk margin
    /// to simplify test values.
    #[test]
    fn test_count_reputation_pairs() {
        let channels = vec![
            (
                0,
                ChannelSnapshot {
                    outgoing_reputation: 100_000,
                    bidirectional_revenue: 20_000,
                },
            ),
            (
                1,
                ChannelSnapshot {
                    outgoing_reputation: 45_000,
                    bidirectional_revenue: 50_000,
                },
            ),
            (
                2,
                ChannelSnapshot {
                    outgoing_reputation: 15_000,
                    bidirectional_revenue: 80_000,
                },
            ),
        ]
        .into_iter()
        .collect();

        // Channel not found.
        assert!(count_reputation_pairs(&channels, 999, 0).is_err());

        assert_eq!(count_reputation_pairs(&channels, 0, 0).unwrap(), 2);
        assert_eq!(count_reputation_pairs(&channels, 1, 0).unwrap(), 1);
        assert_eq!(count_reputation_pairs(&channels, 2, 0).unwrap(), 0);
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
        let attacker_channel = 0;

        let peer_1 = get_random_keypair().1;
        let peer_2 = get_random_keypair().1;
        let peer_3 = get_random_keypair().1;
        let honest_channels = vec![(1, peer_1), (2, peer_2), (3, peer_3)];

        mock_monitor
            .expect_list_channels()
            .returning(move |pubkey, _| {
                let data = if pubkey == target_pubkey {
                    vec![
                        (
                            0,
                            ChannelSnapshot {
                                outgoing_reputation: 100,
                                bidirectional_revenue: 15,
                            },
                        ),
                        (
                            1,
                            ChannelSnapshot {
                                outgoing_reputation: 150,
                                bidirectional_revenue: 110,
                            },
                        ),
                        (
                            2,
                            ChannelSnapshot {
                                outgoing_reputation: 200,
                                bidirectional_revenue: 90,
                            },
                        ),
                        (
                            3,
                            ChannelSnapshot {
                                outgoing_reputation: 75,
                                bidirectional_revenue: 100,
                            },
                        ),
                    ]
                } else if pubkey == peer_1 {
                    vec![
                        (
                            1,
                            ChannelSnapshot {
                                outgoing_reputation: 500,
                                bidirectional_revenue: 15,
                            },
                        ),
                        (
                            4,
                            ChannelSnapshot {
                                outgoing_reputation: 150,
                                bidirectional_revenue: 600,
                            },
                        ),
                        (
                            5,
                            ChannelSnapshot {
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
                                outgoing_reputation: 1000,
                                bidirectional_revenue: 50,
                            },
                        ),
                        (
                            6,
                            ChannelSnapshot {
                                outgoing_reputation: 350,
                                bidirectional_revenue: 800,
                            },
                        ),
                    ]
                } else if pubkey == peer_3 {
                    vec![(
                        3,
                        ChannelSnapshot {
                            outgoing_reputation: 1000,
                            bidirectional_revenue: 50,
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
            target_pubkey,
            &mock_monitor,
            attacker_channel,
            &honest_channels,
            0,
            now,
        )
        .await
        .unwrap();

        assert_eq!(expected_reputation, network_reputation);
    }
}
