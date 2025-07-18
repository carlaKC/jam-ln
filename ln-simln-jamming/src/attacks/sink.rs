use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::AccountableSignal;
use sim_cli::parsing::NetworkParser;
use simln_lib::clock::Clock;
use simln_lib::sim_node::{CustomRecords, ForwardingError, InterceptRequest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::Mutex;
use triggered::Listener;

use crate::clock::InstantClock;
use crate::reputation_interceptor::ReputationMonitor;
use crate::revenue_interceptor::PeacetimeRevenueMonitor;
use crate::{
    accountable_from_records, get_network_reputation, print_request, records_from_signal, BoxError,
    NetworkReputation,
};

use super::{JammingAttack, NetworkSetup};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetChannelType {
    Attacker,
    Peer,
}

#[derive(Clone)]
pub struct SinkAttack<C, R, M>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
{
    clock: Arc<C>,
    target_pubkey: PublicKey,
    attacker_pubkey: PublicKey,
    target_channels: HashMap<u64, (PublicKey, String)>,
    risk_margin: u64,
    reputation_monitor: Arc<Mutex<R>>,
    peacetime_revenue: Arc<M>,
    listener: Listener,
}

impl<
        C: Clock + InstantClock,
        R: ReputationMonitor + Send + Sync,
        M: PeacetimeRevenueMonitor + Send + Sync,
    > SinkAttack<C, R, M>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<C>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        attacker_pubkey: PublicKey,
        risk_margin: u64,
        reputation_monitor: Arc<Mutex<R>>,
        peacetime_revenue: Arc<M>,
        listener: Listener,
    ) -> Self {
        Self {
            clock,
            target_pubkey,
            attacker_pubkey,
            target_channels: HashMap::from_iter(network.iter().filter_map(|channel| {
                if channel.node_1.pubkey == target_pubkey {
                    Some((
                        channel.scid.into(),
                        (channel.node_2.pubkey, channel.node_2.alias.clone()),
                    ))
                } else if channel.node_2.pubkey == target_pubkey {
                    Some((
                        channel.scid.into(),
                        (channel.node_1.pubkey, channel.node_1.alias.clone()),
                    ))
                } else {
                    None
                }
            })),
            risk_margin,
            reputation_monitor,
            peacetime_revenue,
            listener,
        }
    }

    /// Validates that there's only one channel between the target and the attacking node.
    fn validate(&self) -> Result<(), BoxError> {
        let target_to_attacker_len = self
            .target_channels
            .iter()
            .filter_map(|(scid, (pk, _))| {
                if *pk == self.attacker_pubkey {
                    Some(*scid)
                } else {
                    None
                }
            })
            .count();

        if target_to_attacker_len != 1 {
            return Err(format!(
                "expected one target -> attacker channel, got: {}",
                target_to_attacker_len,
            )
            .into());
        }

        Ok(())
    }

    /// Intercepts payments flowing from target -> attacker, holding the htlc for the maximum allowable time to
    /// trash its reputation if the htlc is accountable. We do not use our underlying jamming mitigation interceptor
    /// at all because the attacker is not required to run the mitigation.
    async fn intercept_attacker_incoming(
        &self,
        req: InterceptRequest,
    ) -> Result<CustomRecords, ForwardingError> {
        // Exit early if not accountable, no point in holding.
        if accountable_from_records(&req.incoming_custom_records)
            == AccountableSignal::Unaccountable
        {
            log::info!(
                "HTLC from target -> attacker not accountable, releasing: {}",
                print_request(&req)
            );

            return Ok(records_from_signal(AccountableSignal::Unaccountable));
        }

        // Get maximum hold time assuming 10 minute blocks, assuming a zero block height (simulator doesn't track
        // height).
        let max_hold_secs = Duration::from_secs((req.incoming_expiry_height * 10 * 60).into());

        log::info!(
            "HTLC from target -> attacker accountable, holding for {:?}: {}",
            max_hold_secs,
            print_request(&req),
        );

        // If the htlc is accountable, then we go ahead and hold the htlc for as long as we can only exiting if we
        // get a shutdown signal elsewhere.
        select! {
            _ = self.listener.clone() => Err(ForwardingError::InterceptorError("shutdown signal received".to_string())),
            _ = self.clock.sleep(max_hold_secs) => Ok(records_from_signal(AccountableSignal::Accountable))
        }
    }
}

/// Pulled into its own function to allow testing without having to mock out calls that will yield the
/// NetworkReputation values we want.
fn inner_simulation_completed(
    start_reputation: &NetworkReputation,
    current_reputation: &NetworkReputation,
) -> Result<bool, BoxError> {
    if current_reputation.attacker_reputation == 0 {
        log::error!("Attacker has no more reputation with the target");

        if current_reputation.target_reputation >= start_reputation.target_reputation {
            log::error!("Attacker has no more reputation with target and the target's reputation is similar to simulation start");
            return Ok(true);
        }

        log::info!("Attacker has no more reputation with target but target's reputation is worse than start count ({} < {}), continuing simulation to monitor recovery", current_reputation.target_reputation, start_reputation.target_reputation);
    }

    Ok(false)
}

#[async_trait]
impl<C, R, M> JammingAttack for SinkAttack<C, R, M>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    M: PeacetimeRevenueMonitor + Send + Sync,
{
    fn setup_for_network(&self) -> Result<NetworkSetup, BoxError> {
        self.validate()?;

        Ok(NetworkSetup {
            // Jam all non-attacking channels with the target in both directions.
            general_jammed_nodes: self
                .target_channels
                .iter()
                .flat_map(|(scid, (pk, _))| {
                    if *pk != self.attacker_pubkey {
                        let scid = *scid;
                        vec![(scid, *pk), (scid, self.target_pubkey)]
                    } else {
                        vec![]
                    }
                })
                .collect(),
        })
    }

    /// Intercepts attacker forwads from the target node to jam them, otherwise forwards unrelated
    /// traffic in the hopes of continuing to be chosen in pathfinding (it can't hurt).
    async fn intercept_attacker_htlc(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        if req.forwarding_node != self.attacker_pubkey {
            return Err(format!(
                "intercept_attacker_htlc received forward not on attacking node: {}",
                req.forwarding_node
            )
            .into());
        }

        // If the htlc is incoming to the attacker, we're interested in hodling it.
        if self
            .target_channels
            .contains_key(&req.incoming_htlc.channel_id.into())
        {
            return Ok(self.intercept_attacker_incoming(req).await);
        }

        // If the payment is going to the target node, we'll drop it to deprive them of the revenue.
        if let Some(outgoing_channel) = req.outgoing_channel_id {
            if self.target_channels.contains_key(&outgoing_channel.into()) {
                return Ok(Err(ForwardingError::InterceptorError(
                    "attacker failing".into(),
                )));
            }
        }

        // Otherwise, we're forwarding a payment unrelated to the target so we'll just forward it - there's nothing to
        // lose here, and it's probably best to remain in other nodes good pathfinding books.
        Ok(Ok(records_from_signal(accountable_from_records(
            &req.incoming_custom_records,
        ))))
    }

    /// Errors if called, because sink attacks rely on passive payment forwarding and should not
    /// receive any payments themselves.
    async fn intercept_attacker_receive(
        &self,
        _req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        return Err("HTLC receive not expected in passive sink attack".into());
    }

    /// Shuts down the simulation if the target node has lost revenue compared to its projected
    /// peacetime revenue, or the attacker has lost reputation without being able to compromise
    /// the target's reputation.
    async fn simulation_completed(
        &self,
        start_reputation: NetworkReputation,
    ) -> Result<bool, BoxError> {
        let snapshot = self.peacetime_revenue.get_revenue_difference().await;
        if snapshot.peacetime_revenue_msat > snapshot.simulation_revenue_msat {
            log::error!(
                "Peacetime revenue: {} exceeds simulation revenue: {} after: {:?}",
                snapshot.peacetime_revenue_msat,
                snapshot.simulation_revenue_msat,
                snapshot.runtime
            );

            return Ok(true);
        }

        log::trace!(
            "Peacetime revenue: {} less than simulation revenue: {} after: {:?}",
            snapshot.peacetime_revenue_msat,
            snapshot.simulation_revenue_msat,
            snapshot.runtime
        );

        let current_reputation = get_network_reputation(
            self.reputation_monitor.clone(),
            self.target_pubkey,
            self.attacker_pubkey,
            &self
                .target_channels
                .iter()
                .map(|(k, v)| (*k, v.0))
                .collect(),
            self.risk_margin,
            InstantClock::now(&*self.clock),
        )
        .await?;

        inner_simulation_completed(&start_reputation, &current_reputation)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::attacks::sink::inner_simulation_completed;
    use crate::attacks::JammingAttack;
    use crate::test_utils::{
        get_random_keypair, get_test_policy, setup_test_request, MockPeacetimeMonitor,
        MockReputationInterceptor,
    };
    use crate::{accountable_from_records, NetworkReputation};
    use bitcoin::secp256k1::PublicKey;
    use ln_resource_mgr::AccountableSignal;
    use sim_cli::parsing::NetworkParser;
    use simln_lib::clock::SimulationClock;
    use simln_lib::sim_node::ForwardingError;
    use tokio::sync::Mutex;

    use super::SinkAttack;

    fn setup_test_attack(
        target: PublicKey,
        attacker: PublicKey,
        network: &[NetworkParser],
    ) -> SinkAttack<SimulationClock, MockReputationInterceptor, MockPeacetimeMonitor> {
        let (_shutdown, listener) = triggered::trigger();

        SinkAttack::new(
            Arc::new(SimulationClock::new(1).unwrap()),
            network,
            target,
            attacker,
            0,
            Arc::new(Mutex::new(MockReputationInterceptor::new())),
            Arc::new(MockPeacetimeMonitor::new()),
            listener,
        )
    }

    /// Creates a test network with the following topology, returning an attack and the scid of the
    /// target <--> attacker channel:
    /// P1 --+
    ///      |
    ///    target -- attacker
    ///      |
    /// P2 --+
    fn setup_test_network() -> (
        SinkAttack<SimulationClock, MockReputationInterceptor, MockPeacetimeMonitor>,
        u64,
    ) {
        let target = get_random_keypair().1;
        let attacker = get_random_keypair().1;
        let regular_1 = get_random_keypair().1;
        let regular_2 = get_random_keypair().1;

        let network = vec![
            NetworkParser {
                scid: 0.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(target),
                node_2: get_test_policy(regular_1),
            },
            NetworkParser {
                scid: 1.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(target),
                node_2: get_test_policy(regular_2),
            },
            NetworkParser {
                scid: 2.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(target),
                node_2: get_test_policy(attacker),
            },
        ];

        (setup_test_attack(target, attacker, &network), 2)
    }

    #[test]
    fn test_setup_network() {
        let target = get_random_keypair().1;
        let attacker = get_random_keypair().1;
        let regular_1 = get_random_keypair().1;
        let regular_2 = get_random_keypair().1;

        let network = vec![
            NetworkParser {
                scid: 0.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(target),
                node_2: get_test_policy(regular_1),
            },
            NetworkParser {
                scid: 1.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(target),
                node_2: get_test_policy(regular_2),
            },
            NetworkParser {
                scid: 2.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(target),
                node_2: get_test_policy(attacker),
            },
            NetworkParser {
                scid: 2.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(attacker),
                node_2: get_test_policy(regular_1),
            },
            NetworkParser {
                scid: 4.into(),
                capacity_msat: 100_000,
                node_1: get_test_policy(target),
                node_2: get_test_policy(attacker),
            },
        ];

        // Two target <--> attacker channels should fail.
        let attack = setup_test_attack(target, attacker, &network);
        assert!(attack.setup_for_network().is_err());

        // No target <--> attacker should fail.
        let attack = setup_test_attack(target, attacker, &network[0..1]);
        assert!(attack.setup_for_network().is_err());

        // It's okay for the target to have multiple channels with other nodes.
        let attack = setup_test_attack(target, attacker, &network[0..3]);
        let setup = attack.setup_for_network().unwrap();

        // Expect that all of the target's non-attacker channels are jammed, order doesn't matter.
        let general_jammed_nodes: HashSet<(u64, PublicKey)> =
            vec![(0, regular_1), (0, target), (1, regular_2), (1, target)]
                .into_iter()
                .collect();

        assert_eq!(
            general_jammed_nodes,
            setup.general_jammed_nodes.iter().cloned().collect()
        );
    }

    /// Tests that bad requests to the attacking interceptor will fail.
    #[tokio::test]
    async fn test_attacker_bad_intercepts() {
        let (attack, _) = setup_test_network();
        let pubkey = get_random_keypair().1;

        // Request is not forwarded by the attacking node.
        let request = setup_test_request(pubkey, 101, 100, AccountableSignal::Unaccountable);
        assert!(attack.intercept_attacker_htlc(request).await.is_err());
    }

    /// Tests that HTLCs that are not incoming from the target are just failed, covering forwards
    /// outwards to the target and receives to the attacker.
    #[tokio::test]
    async fn test_intercept_attacker_outgoing() {
        let (attack, attacker_scid) = setup_test_network();
        let mut request = setup_test_request(
            attack.attacker_pubkey,
            100,
            attacker_scid,
            AccountableSignal::Unaccountable,
        );

        assert!(matches!(
            attack
                .intercept_attacker_htlc(request.clone())
                .await
                .unwrap()
                .err()
                .unwrap(),
            ForwardingError::InterceptorError(_)
        ));

        // Receives to the attacker or forwards unrelated to the target succeed.
        request.outgoing_channel_id = None;
        assert!(
            attack
                .intercept_attacker_htlc(request.clone())
                .await
                .unwrap()
                .unwrap()
                == request.incoming_custom_records
        );

        let request = setup_test_request(
            attack.attacker_pubkey,
            101,
            100,
            AccountableSignal::Unaccountable,
        );
        assert!(attack.intercept_attacker_htlc(request).await.is_ok());
    }

    /// Tests that unaccountable HTLCs incoming from the target are not held by the attacker.
    #[tokio::test]
    async fn test_intercept_attacker_incoming() {
        let (attack, attacker_scid) = setup_test_network();
        let request = setup_test_request(
            attack.attacker_pubkey,
            attacker_scid,
            100,
            AccountableSignal::Unaccountable,
        );

        // Unaccountable HTLCs won't be held, they're just let through to help build our reputation.
        let res = attack.intercept_attacker_htlc(request).await;
        assert!(res.unwrap().is_ok());
    }

    /// Tests that accountable HTLCs incoming from the target are held by the attacker.
    #[tokio::test]
    async fn test_intercept_incoming_hold() {
        let (attack, attacker_scid) = setup_test_network();
        let mut request = setup_test_request(
            attack.attacker_pubkey,
            attacker_scid,
            100,
            AccountableSignal::Accountable,
        );

        // Set our incoming expiry to zero so that our "hold" is actually zero in the test.
        request.incoming_expiry_height = 0;

        let res = attack
            .intercept_attacker_htlc(request)
            .await
            .unwrap()
            .unwrap();
        assert!(accountable_from_records(&res) == AccountableSignal::Accountable);
    }

    /// Tests stop conditions for simulation. Does not cover simulation_completed to avoid needing
    /// to do complicated mocking for the get_network_reputation call.
    #[tokio::test]
    async fn test_inner_simulation_completed() {
        let start_reputation = NetworkReputation {
            target_reputation: 1,
            target_pair_count: 2,
            attacker_reputation: 5,
            attacker_pair_count: 7,
        };
        let current_reputation = start_reputation.clone();

        // When attacker has not lost reputation, we should not shut down.
        assert!(!inner_simulation_completed(&start_reputation, &current_reputation).unwrap());

        // When attacker has lost reputation and target is the same, we should shut down.
        let current_reputation = NetworkReputation {
            target_reputation: 1,
            target_pair_count: 2,
            attacker_reputation: 0,
            attacker_pair_count: 7,
        };
        assert!(inner_simulation_completed(&start_reputation, &current_reputation).unwrap());

        // When the attacker has lost reputation, but the target has too we should not shut down.
        let current_reputation = NetworkReputation {
            target_reputation: 0,
            target_pair_count: 2,
            attacker_reputation: 0,
            attacker_pair_count: 0,
        };
        assert!(!inner_simulation_completed(&start_reputation, &current_reputation).unwrap());
    }
}
