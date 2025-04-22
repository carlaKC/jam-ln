use crate::attacks::JammingAttack;
use crate::clock::InstantClock;
use crate::reputation_interceptor::{HtlcAdd, ReputationMonitor};
use crate::{
    endorsement_from_records, print_request, records_from_endorsement, send_intercept_result,
    BoxError,
};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::{EndorsementSignal, ForwardingOutcome, HtlcRef, ProposedForward};
use simln_lib::clock::Clock;
use simln_lib::sim_node::{InterceptRequest, InterceptResolution, Interceptor};
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use triggered::Trigger;

/// Wraps an innner reputation interceptor (which is responsible for implementing a mitigation to
/// channel jamming) in an outer interceptor which can be used to take custom actions for attacks.
#[derive(Clone)]
pub struct AttackInterceptor<C, R, A>
where
    C: InstantClock + Clock,
    R: Interceptor + ReputationMonitor,
    A: JammingAttack,
{
    clock: Arc<C>,
    attacker_pubkey: PublicKey,
    target_pubkey: PublicKey,
    /// Keeps track of the target's channels for custom behavior, including any channels with the attacking node.
    target_channels: HashSet<u64>,
    /// Inner reputation monitor that implements jamming mitigation.
    reputation_interceptor: Arc<Mutex<R>>,
    /// The attack that will be launched.
    attack: Arc<Mutex<A>>,
    /// Used to control shutdown.
    shutdown: Trigger,
}

impl<C, R, A> AttackInterceptor<C, R, A>
where
    C: InstantClock + Clock,
    R: Interceptor + ReputationMonitor,
    A: JammingAttack + Sync + Send,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<C>,
        attacker_pubkey: PublicKey,
        target_pubkey: PublicKey,
        target_channels: HashSet<u64>,
        reputation_interceptor: Arc<Mutex<R>>,
        attack: Arc<Mutex<A>>,
        shutdown: Trigger,
    ) -> Self {
        Self {
            clock,
            attacker_pubkey,
            target_pubkey,
            target_channels,
            reputation_interceptor,
            attack,
            shutdown,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_network(
        clock: Arc<C>,
        attacker_pubkey: PublicKey,
        target_pubkey: PublicKey,
        target_channels: HashSet<u64>,
        reputation_interceptor: Arc<Mutex<R>>,
        attack: Arc<Mutex<A>>,
        shutdown: Trigger,
    ) -> Self {
        Self::new(
            clock,
            attacker_pubkey,
            target_pubkey,
            target_channels,
            reputation_interceptor,
            attack,
            shutdown,
        )
    }

    /// Intercepts payments flowing from peer -> target, simulating a general jamming attack by failing any
    /// unendorsed payments.
    async fn intercept_peer_outgoing(&self, mut req: InterceptRequest) -> Result<(), BoxError> {
        log::info!(
            "HTLC from peer -> target, general jamming if unendorsed: {}",
            print_request(&req),
        );

        // If htlc is endorsed, perform regular checks with reputation interceptor.
        // If the htlc is not endorsed, it may be subject to general jamming. Since we don't have the ability to
        // endorse htlcs on the sender using our simulator, we need to apply "just in time" endorsement:
        // - If the htlc would be forwarded if it was endorsed, we bump the endorsement up and forward onwards.
        // - If the htlc would not be forwarded if it was endorsed, we drop the htlc to mimic general jamming.
        //
        // It's okay for us to bump our endorsement signal up, because we know that endorsement can't go from
        // 1 -> 0 along the path (ie, we're not bumping the endorsement of a htlc that was previous dropped down),
        // because our existing algorithm drops any endorsed htlcs that don't have enough reputation.
        //
        // By bumping endorsement on the peer, we manage to deliver endorsed htlcs to the target which will then
        // be forwarded by the target as endorsed if the next hop has sufficient reputation. So, while this behavior
        // is odd, it represents what we want in the attacker's neighborhood.
        match endorsement_from_records(&req.incoming_custom_records) {
            EndorsementSignal::Endorsed => {
                self.reputation_interceptor
                    .lock()
                    .await
                    .intercept_htlc(req)
                    .await
            }
            EndorsementSignal::Unendorsed => {
                let allocation_check = match self
                    .reputation_interceptor
                    .lock()
                    .await
                    .check_htlc_outcome(HtlcAdd {
                        forwarding_node: req.forwarding_node,
                        htlc: ProposedForward {
                            incoming_ref: HtlcRef {
                                channel_id: req.incoming_htlc.channel_id.into(),
                                htlc_index: req.incoming_htlc.index,
                            },
                            outgoing_channel_id: req
                                .outgoing_channel_id
                                .ok_or("no outgoing channel id")?
                                .into(),
                            amount_in_msat: req.incoming_amount_msat,
                            amount_out_msat: req.outgoing_amount_msat,
                            expiry_in_height: req.incoming_expiry_height,
                            expiry_out_height: req.outgoing_expiry_height,
                            added_at: InstantClock::now(&*self.clock),
                            incoming_endorsed: EndorsementSignal::Endorsed,
                        },
                    })
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        send_intercept_result!(req, Err(Box::new(e.clone())), self.shutdown);
                        return Err(Box::new(e));
                    }
                };

                // Query forwarding outcome as if the htlc was endorsed to see whether we'd make the cut.
                match allocation_check
                    .forwarding_outcome(req.outgoing_amount_msat, EndorsementSignal::Endorsed)
                {
                    ForwardingOutcome::Forward(_) => {
                        log::info!("HTLC from peer -> target has sufficient reputation, forwarding endorsed");

                        // If the htlc can be upgraded, go ahead and add it to the reputation interceptor as if its
                        // incoming htlc was endorsed.
                        req.incoming_custom_records =
                            records_from_endorsement(EndorsementSignal::Endorsed);
                    }
                    ForwardingOutcome::Fail(_) => {
                        log::info!(
                            "HTLC from peer -> target has insufficient reputation, general jamming"
                        );
                    }
                };

                self.reputation_interceptor
                    .lock()
                    .await
                    .intercept_htlc(req)
                    .await;
            }
        };

        Ok(())
    }
}

#[async_trait]
impl<C, R, A> Interceptor for AttackInterceptor<C, R, A>
where
    C: InstantClock + Clock,
    R: Interceptor + ReputationMonitor,
    A: JammingAttack + Send + Sync,
{
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        // Intercept payments on the attacking node. If they're incoming from the target, jam them. Otherwise just
        // fail other htlcs, they're not that interesting to us.

        if req.forwarding_node == self.attacker_pubkey {
            if let Err(e) = self.attack.lock().await.intercept_attacker_htlc(req).await {
                log::error!("Could not intercept attacker htlc: {e}");
                self.shutdown.trigger();
            }
            return;
        }

        // Intercept payments from peers -> target. If there's no outgoing_channel_id, the intercepting node is
        // the recipient so we take no action.
        if let Some(outgoing_channel_id) = req.outgoing_channel_id {
            if self.target_channels.contains(&outgoing_channel_id.into())
                && req.forwarding_node != self.target_pubkey
            {
                if let Err(e) = self.intercept_peer_outgoing(req.clone()).await {
                    log::error!("Could not intercept peer outgoing: {e}");
                    self.shutdown.trigger();
                }

                return;
            }
        }

        // We only expect endorsed htlcs to be able to reach the target node, so we upgrade to endorsed and then
        // proceed to use the reputation interceptor as usual. This addresses an edge case where the target's incoming
        // peer is the sender of the htlc, so it was not upgraded to endorsed at the peer (because we only intercept
        // forwards, not the original sender).
        let mut req_clone = req.clone();
        if req.forwarding_node == self.target_pubkey {
            req_clone.incoming_custom_records =
                records_from_endorsement(EndorsementSignal::Endorsed);
        }

        // The target is not involved in the forward at all, just use jamming interceptor to implement reputation
        // and bucketing.
        self.reputation_interceptor
            .lock()
            .await
            .intercept_htlc(req_clone)
            .await
    }

    /// Notifies the underlying jamming interceptor of htlc resolution, as our attacking interceptor doesn't need
    /// to handle notifications.
    async fn notify_resolution(
        &self,
        res: InterceptResolution,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        // If this was a payment forwarded through the attacker, it was not handled by the reputation interceptor
        // so we don't need to handle it (it hasn't seen the htlc add to begin with).
        if res.forwarding_node == self.attacker_pubkey {
            return Ok(());
        }

        self.reputation_interceptor
            .lock()
            .await
            .notify_resolution(res)
            .await
    }

    fn name(&self) -> String {
        "sink attack".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::convert::From;
    use std::sync::Arc;

    use crate::attacks::JammingAttack;
    use crate::reputation_interceptor::HtlcAdd;
    use crate::test_utils::{
        get_random_keypair, setup_test_request, test_allocation_check, MockReputationInterceptor,
    };
    use crate::{records_from_endorsement, BoxError, NetworkReputation};
    use async_trait::async_trait;
    use ln_resource_mgr::EndorsementSignal;
    use mockall::mock;
    use mockall::predicate::function;
    use simln_lib::clock::SimulationClock;
    use simln_lib::sim_node::{InterceptRequest, Interceptor};
    use tokio::sync::Mutex;

    use super::AttackInterceptor;

    mock! {
        Attack{}

        #[async_trait]
        impl JammingAttack for Attack {
            fn setup_for_network(&self) -> Result<crate::attacks::NetworkSetup, BoxError>;
            async fn intercept_attacker_htlc(&self, req: InterceptRequest) -> Result<(), BoxError>;
            async fn simulation_completed(&self, _start_reputation: NetworkReputation) -> Result<bool, BoxError>;
        }
    }

    fn setup_interceptor_test(
    ) -> AttackInterceptor<SimulationClock, MockReputationInterceptor, MockAttack> {
        let target_pubkey = get_random_keypair().1;
        let attacker_pubkey = get_random_keypair().1;

        let target_channels = HashSet::from([0, 1, 2, 3]);

        let (shutdown, _listener) = triggered::trigger();
        let mock = MockReputationInterceptor::new();
        AttackInterceptor::new(
            Arc::new(SimulationClock::new(1).unwrap()),
            target_pubkey,
            attacker_pubkey,
            target_channels,
            Arc::new(Mutex::new(mock)),
            Arc::new(Mutex::new(MockAttack::new())),
            shutdown,
        )
    }

    /// Primes the mock to expect intercept_htlc called with the request provided.
    async fn mock_intercept_htlc(
        interceptor: Arc<Mutex<MockReputationInterceptor>>,
        req: &InterceptRequest,
    ) {
        let expected_incoming = req.incoming_htlc.channel_id;
        let expected_outgoing = req.outgoing_channel_id.unwrap();

        interceptor
            .lock()
            .await
            .expect_intercept_htlc()
            .with(function(move |args: &InterceptRequest| {
                args.incoming_htlc.channel_id == expected_incoming
                    && args.outgoing_channel_id.unwrap() == expected_outgoing
            }))
            .return_once(|_| {});
    }

    /// Tests that any attacker htlc are forwarded through to the attacker.
    #[tokio::test]
    async fn test_attacker_intercept() {
        let interceptor = setup_interceptor_test();
        interceptor
            .attack
            .lock()
            .await
            .expect_intercept_attacker_htlc()
            .returning(|_| Ok(()))
            .times(2);

        // Intercepted on attacker: target -(0)-> attacker -(5)-> node.
        let (target_to_attacker, _) = setup_test_request(
            interceptor.attacker_pubkey,
            0,
            5,
            EndorsementSignal::Unendorsed,
        );
        interceptor.intercept_htlc(target_to_attacker).await;

        // Intercepted on attacker: node -(5)-> attacker -(0)-> target.
        let (attacker_to_target, _) = setup_test_request(
            interceptor.attacker_pubkey,
            5,
            0,
            EndorsementSignal::Unendorsed,
        );
        interceptor.intercept_htlc(attacker_to_target).await;
    }

    #[tokio::test]
    async fn test_peer_to_target_endorsed() {
        let interceptor = setup_interceptor_test();

        // Intercepted on target's peer: node -(5) -> peer -(1)-> target, endorsed payments just passed through.
        let peer_pubkey = get_random_keypair().1;
        let (peer_to_target, _) =
            setup_test_request(peer_pubkey, 5, 1, EndorsementSignal::Endorsed);

        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &peer_to_target).await;
        interceptor.intercept_htlc(peer_to_target).await;
    }

    /// Tests that payments forwarded from peer -> target are optimistically upgraded to endorsed if they have
    /// sufficient reputation.
    #[tokio::test]
    async fn test_peer_to_target_upgraded() {
        let interceptor = setup_interceptor_test();

        let peer_pubkey = get_random_keypair().1;
        let (peer_to_target, _) =
            setup_test_request(peer_pubkey, 5, 1, EndorsementSignal::Unendorsed);

        // Expect a reputation check that passes, then pass the htlc on to the reputation interceptor endorsed.
        interceptor
            .reputation_interceptor
            .lock()
            .await
            .expect_check_htlc_outcome()
            .with(function(move |req: &HtlcAdd| {
                req.htlc.incoming_ref.channel_id == peer_to_target.incoming_htlc.channel_id.into()
                    && req.htlc.outgoing_channel_id
                        == peer_to_target.outgoing_channel_id.unwrap().into()
                    && req.htlc.incoming_endorsed == EndorsementSignal::Endorsed
            }))
            .return_once(|_| Ok(test_allocation_check(true)));
        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &peer_to_target).await;

        interceptor.intercept_htlc(peer_to_target).await;
    }

    /// Tests that payments forwarded from peer -> target are dropped if they don't have sufficient reputation to
    /// be upgraded to endorsed.
    #[tokio::test]
    async fn test_peer_to_target_general_jammed() {
        let interceptor = setup_interceptor_test();

        let peer_pubkey = get_random_keypair().1;
        let (peer_to_target, _) =
            setup_test_request(peer_pubkey, 5, 1, EndorsementSignal::Unendorsed);

        // Expect a reputation check that fails, then an interceptor response.
        interceptor
            .reputation_interceptor
            .lock()
            .await
            .expect_check_htlc_outcome()
            .with(function(move |req: &HtlcAdd| {
                req.htlc.incoming_ref.channel_id == peer_to_target.incoming_htlc.channel_id.into()
                    && req.htlc.outgoing_channel_id
                        == peer_to_target.outgoing_channel_id.unwrap().into()
                    && req.htlc.incoming_endorsed == EndorsementSignal::Endorsed
            }))
            .return_once(|_| Ok(test_allocation_check(false)));

        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &peer_to_target).await;
        interceptor.intercept_htlc(peer_to_target).await;
    }

    /// Tests that forwards through the target node to its peers will be upgraded to endorsed.
    #[tokio::test]
    async fn test_target_to_peer() {
        let interceptor = setup_interceptor_test();

        let (target_forward, _) = setup_test_request(
            interceptor.target_pubkey,
            1, // Honest channel
            2, // Honest channel
            EndorsementSignal::Unendorsed,
        );

        let mut expected_req = target_forward.clone();
        expected_req.incoming_custom_records =
            records_from_endorsement(EndorsementSignal::Endorsed);
        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &expected_req).await;
        interceptor.intercept_htlc(target_forward).await;
    }

    /// Tests that forwards through the target node to the attacker will be upgraded to endorsed.
    #[tokio::test]
    async fn test_target_to_attacker() {
        let interceptor = setup_interceptor_test();

        let (target_forward, _) = setup_test_request(
            interceptor.target_pubkey,
            1, // Honest channel
            0, // Attacker
            EndorsementSignal::Unendorsed,
        );

        let mut expected_req = target_forward.clone();
        expected_req.incoming_custom_records =
            records_from_endorsement(EndorsementSignal::Endorsed);
        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &expected_req).await;
        interceptor.intercept_htlc(target_forward).await;
    }

    /// Tests that forwards by the target sent from attacker -> target are handled like any other target payment.
    #[tokio::test]
    async fn test_target_from_attacker() {
        let interceptor = setup_interceptor_test();

        let (not_actually_attacker, _) =
            setup_test_request(interceptor.target_pubkey, 0, 3, EndorsementSignal::Endorsed);

        // This tests hangs; the target is actually jamming the attacker lol because we don't check the direction
        mock_intercept_htlc(
            interceptor.reputation_interceptor.clone(),
            &not_actually_attacker,
        )
        .await;
        interceptor.intercept_htlc(not_actually_attacker).await;
    }
}
