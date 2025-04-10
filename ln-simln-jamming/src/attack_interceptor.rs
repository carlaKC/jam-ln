use crate::attacks::JammingAttack;
use crate::clock::InstantClock;
use crate::reputation_interceptor::{HtlcAdd, ReputationMonitor};
use crate::{endorsement_from_records, records_from_endorsement, BoxError};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::{EndorsementSignal, ForwardingOutcome, HtlcRef, ProposedForward};
use simln_lib::clock::Clock;
use simln_lib::sim_node::{InterceptRequest, InterceptResolution, Interceptor};
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use triggered::Trigger;

/// Wraps an innner reputation interceptor (which is responsible for implementing a mitigation to
/// channel jamming) in an outer interceptor which can be used to take custom actions for attacks.
#[derive(Clone)]
pub struct AttackInterceptor<C, R, A>
where
    C: InstantClock + Clock,
    R: Interceptor + ReputationMonitor,
{
    clock: Arc<C>,
    attacker_pubkey: PublicKey,
    target_pubkey: PublicKey,
    /// Keeps track of the target's channels for custom behavior.
    target_honest_channels: HashSet<u64>,
    /// Inner reputation monitor that implements jamming mitigation.
    pub reputation_interceptor: R,
    /// The attack that will be launched.
    attack: A,
    /// Used to control shutdown.
    shutdown: Trigger,
}

macro_rules! send_intercept_result {
    ($req:expr, $result:expr, $shutdown:expr) => {
        if let Err(e) = $req.response.send($result).await {
            log::error!("Could not send to interceptor: {e}");
            $shutdown.trigger();
        }
    };
}

fn print_request(req: &InterceptRequest) -> String {
    format!(
        "{}:{} {} -> {} with fee {} ({} -> {}) and cltv {} ({} -> {})",
        u64::from(req.incoming_htlc.channel_id),
        req.incoming_htlc.index,
        endorsement_from_records(&req.incoming_custom_records),
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

impl<
        C: InstantClock + Clock,
        R: Interceptor + ReputationMonitor,
        A: JammingAttack<R> + Sync + Send,
    > AttackInterceptor<C, R, A>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<C>,
        attacker_pubkey: PublicKey,
        target_pubkey: PublicKey,
        target_honest_channels: HashSet<u64>,
        reputation_interceptor: R,
        attack: A,
        shutdown: Trigger,
    ) -> Self {
        Self {
            clock,
            attacker_pubkey,
            target_pubkey,
            target_honest_channels,
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
        target_honest_channels: HashSet<u64>,
        reputation_interceptor: R,
        attack: A,
        shutdown: Trigger,
    ) -> Self {
        Self::new(
            clock,
            attacker_pubkey,
            target_pubkey,
            target_honest_channels,
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
            EndorsementSignal::Endorsed => self.reputation_interceptor.intercept_htlc(req).await,
            EndorsementSignal::Unendorsed => {
                let allocation_check = match self
                    .reputation_interceptor
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

                self.reputation_interceptor.intercept_htlc(req).await;
            }
        };

        Ok(())
    }
}

#[async_trait]
impl<
        C: InstantClock + Clock,
        R: Interceptor + ReputationMonitor,
        A: JammingAttack<R> + Sync + Send,
    > Interceptor for AttackInterceptor<C, R, A>
{
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        // Intercept payments on the attacking node. If they're incoming from the target, jam them. If they're outgoing
        // to the target, just drop them to prevent them from earning revenue. Other payments are ok, they help the
        // attacker be a link that other nodes want to forward through them.
        if req.forwarding_node == self.attacker_pubkey {
            if let Err(e) = self.attack.intercept_attacker_htlc(req).await {
                log::error!("Could not intercept attacker htlc: {e}");
                self.shutdown.trigger();
            }
            return;
        }

        // Intercept payments from peers -> target. If there's no outgoing_channel_id, the intercepting node is
        // the recipient so we take no action.
        if let Some(outgoing_channel_id) = req.outgoing_channel_id {
            if self
                .target_honest_channels
                .contains(&outgoing_channel_id.into())
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
        self.reputation_interceptor.intercept_htlc(req_clone).await
    }

    /// Notifies the underlying jamming interceptor of htlc resolution, as our attacking interceptor doesn't need
    /// to handle notifications.
    async fn notify_resolution(
        &self,
        res: InterceptResolution,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        // Attacker forwards are not reported to the underlying reputation interceptor, so take no action here.
        if res.forwarding_node == self.attacker_pubkey {
            return Ok(()); // TODO: notify attack?
        }

        self.reputation_interceptor.notify_resolution(res).await
    }

    fn name(&self) -> String {
        "sink attack".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::From;
    use std::error::Error;
    use std::sync::Arc;
    use std::time::Instant;

    use crate::attacks::JammingAttack;
    use crate::reputation_interceptor::{HtlcAdd, ReputationMonitor};
    use crate::test_utils::{get_random_keypair, setup_test_request, test_allocation_check};
    use crate::{endorsement_from_records, records_from_endorsement, BoxError};
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use ln_resource_mgr::{AllocationCheck, ChannelSnapshot, EndorsementSignal, ReputationError};
    use mockall::mock;
    use mockall::predicate::function;
    use simln_lib::clock::SimulationClock;
    use simln_lib::sim_node::{InterceptRequest, InterceptResolution, Interceptor};
    use simln_lib::ShortChannelID;

    use super::{AttackInterceptor, TargetChannelType};

    mock! {
        ReputationInterceptor{}

        #[async_trait]
        impl Interceptor for ReputationInterceptor{
            async fn intercept_htlc(&self, req: InterceptRequest);
            async fn notify_resolution(&self,_res: InterceptResolution,) -> Result<(), Box<dyn Error + Send + Sync + 'static>>;
            fn name(&self) -> String;
        }

        #[async_trait]
        impl ReputationMonitor for ReputationInterceptor{
            async fn list_channels(&self, node: PublicKey, access_ins: Instant) -> Result<HashMap<u64, ChannelSnapshot>, BoxError>;
           async fn check_htlc_outcome(&self,htlc_add: HtlcAdd) -> Result<AllocationCheck, ReputationError>;
        }
    }

    mock! {
        Attack{}

        #[async_trait]
        impl <R: ReputationMonitor> JammingAttack<R> for Attack {
            fn setup_for_network(&self) -> Result<crate::attacks::NetworkSetup, BoxError>;
            async fn intercept_attacker_htlc(&self, req: InterceptRequest) -> Result<(), BoxError>;
            async fn simulation_completed(&self, _reputation_monitor: &R) -> Result<bool, BoxError>;
        }
    }

    fn setup_interceptor_test(
    ) -> AttackInterceptor<SimulationClock, MockReputationInterceptor, MockAttack> {
        let target_pubkey = get_random_keypair().1;
        let attacker_pubkey = get_random_keypair().1;

        let target_channels = HashMap::from([
            (ShortChannelID::from(0), TargetChannelType::Attacker),
            (ShortChannelID::from(1), TargetChannelType::Peer),
            (ShortChannelID::from(2), TargetChannelType::Peer),
            (ShortChannelID::from(3), TargetChannelType::Peer),
        ]);

        let (shutdown, listener) = triggered::trigger();
        let mock = MockReputationInterceptor::new();
        AttackInterceptor::new(
            Arc::new(SimulationClock::new(1).unwrap()),
            target_pubkey,
            attacker_pubkey,
            target_channels,
            mock,
            MockAttack::new(),
            shutdown,
        )
    }

    /// Primes the mock to expect intercept_htlc called with the request provided.
    fn mock_intercept_htlc(interceptor: &mut MockReputationInterceptor, req: &InterceptRequest) {
        let expected_incoming = req.incoming_htlc.channel_id;
        let expected_outgoing = req.outgoing_channel_id.unwrap();

        interceptor
            .expect_intercept_htlc()
            .with(function(move |args: &InterceptRequest| {
                args.incoming_htlc.channel_id == expected_incoming
                    && args.outgoing_channel_id.unwrap() == expected_outgoing
            }))
            .return_once(|_| {});
    }

    /// Tests attacker interception of htlcs from the target.
    #[tokio::test]
    async fn test_attacker_from_target() {
        let interceptor = setup_interceptor_test();

        // Intercepted on attacker unendorsed: target -(0)-> attacker -(5)-> should just be forwarded unendorsed.
        let (target_to_attacker, mut receiver) = setup_test_request(
            interceptor.attacker_pubkey,
            0,
            5,
            EndorsementSignal::Unendorsed,
        );
        interceptor.intercept_htlc(target_to_attacker).await;

        let interceptor_resp = receiver.recv().await.unwrap().unwrap().unwrap();
        assert!(interceptor_resp.is_empty());

        // Intercepted on attacker unendorsed: target -(0)-> attacker -(5)-> should just be forwarded unendorsed. We
        // expect the htlc to be held for the full cltv delta, so we set this value to 0 so the test doesn't block.
        let (mut target_to_attacker, mut receiver) = setup_test_request(
            interceptor.attacker_pubkey,
            0,
            5,
            EndorsementSignal::Endorsed,
        );

        target_to_attacker.incoming_expiry_height = 0;
        target_to_attacker.outgoing_expiry_height = 0;
        interceptor.intercept_htlc(target_to_attacker).await;

        let interceptor_resp = receiver.recv().await.unwrap().unwrap().unwrap();
        assert_eq!(
            endorsement_from_records(&interceptor_resp),
            EndorsementSignal::Endorsed
        );
    }

    /// Tests attacker interception of htlcs that need no interception action - either from a random node or those
    /// that are being sent to the target (rather than received from it).
    #[tokio::test]
    async fn test_attacker_no_action() {
        let mut interceptor = setup_interceptor_test();
        let attacker_pk = get_random_keypair().1;

        // Intercepted on the attacker: node -(5)-> attacker -(0)-> target, should just be forwarded.
        let (attacker_to_target, _) =
            setup_test_request(attacker_pk, 5, 0, EndorsementSignal::Unendorsed);
        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &attacker_to_target);
        interceptor.intercept_htlc(attacker_to_target).await;

        // Intercepted on the attacker: node -(5)-> attacker -(6)-> node, should just be forwarded.
        let (attacker_to_target, _) =
            setup_test_request(attacker_pk, 5, 6, EndorsementSignal::Unendorsed);

        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &attacker_to_target);
        interceptor.intercept_htlc(attacker_to_target).await;
    }

    #[tokio::test]
    async fn test_peer_to_target_endorsed() {
        let mut interceptor = setup_interceptor_test();

        // Intercepted on target's peer: node -(5) -> peer -(1)-> target, endorsed payments just passed through.
        let peer_pubkey = get_random_keypair().1;
        let (peer_to_target, _) =
            setup_test_request(peer_pubkey, 5, 1, EndorsementSignal::Endorsed);

        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &peer_to_target);
        interceptor.intercept_htlc(peer_to_target).await;
    }

    /// Tests that payments forwarded from peer -> target are optimistically upgraded to endorsed if they have
    /// sufficient reputation.
    #[tokio::test]
    async fn test_peer_to_target_upgraded() {
        let mut interceptor = setup_interceptor_test();

        let peer_pubkey = get_random_keypair().1;
        let (peer_to_target, _) =
            setup_test_request(peer_pubkey, 5, 1, EndorsementSignal::Unendorsed);

        // Expect a reputation check that passes, then pass the htlc on to the reputation interceptor endorsed.
        interceptor
            .reputation_interceptor
            .expect_check_htlc_outcome()
            .with(function(move |req: &HtlcAdd| {
                req.htlc.incoming_ref.channel_id == peer_to_target.incoming_htlc.channel_id.into()
                    && req.htlc.outgoing_channel_id
                        == peer_to_target.outgoing_channel_id.unwrap().into()
                    && req.htlc.incoming_endorsed == EndorsementSignal::Endorsed
            }))
            .return_once(|_| Ok(test_allocation_check(true)));
        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &peer_to_target);

        interceptor.intercept_htlc(peer_to_target).await;
    }

    /// Tests that payments forwarded from peer -> target are dropped if they don't have sufficient reputation to
    /// be upgraded to endorsed.
    #[tokio::test]
    async fn test_peer_to_target_general_jammed() {
        let mut interceptor = setup_interceptor_test();

        let peer_pubkey = get_random_keypair().1;
        let (peer_to_target, _) =
            setup_test_request(peer_pubkey, 5, 1, EndorsementSignal::Unendorsed);

        // Expect a reputation check that fails, then an interceptor response.
        interceptor
            .reputation_interceptor
            .expect_check_htlc_outcome()
            .with(function(move |req: &HtlcAdd| {
                req.htlc.incoming_ref.channel_id == peer_to_target.incoming_htlc.channel_id.into()
                    && req.htlc.outgoing_channel_id
                        == peer_to_target.outgoing_channel_id.unwrap().into()
                    && req.htlc.incoming_endorsed == EndorsementSignal::Endorsed
            }))
            .return_once(|_| Ok(test_allocation_check(false)));

        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &peer_to_target);
        interceptor.intercept_htlc(peer_to_target).await;
    }

    /// Tests that forwards through the target node to its peers will be upgraded to endorsed.
    #[tokio::test]
    async fn test_target_to_peer() {
        let mut interceptor = setup_interceptor_test();

        let (target_forward, _) = setup_test_request(
            interceptor.target_pubkey,
            1, // Honest channel
            2, // Honest channel
            EndorsementSignal::Unendorsed,
        );

        let mut expected_req = target_forward.clone();
        expected_req.incoming_custom_records =
            records_from_endorsement(EndorsementSignal::Endorsed);
        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &expected_req);
        interceptor.intercept_htlc(target_forward).await;
    }

    /// Tests that forwards through the target node to the attacker will be upgraded to endorsed.
    #[tokio::test]
    async fn test_target_to_attacker() {
        let mut interceptor = setup_interceptor_test();

        let (target_forward, _) = setup_test_request(
            interceptor.target_pubkey,
            1, // Honest channel
            0, // Attacker
            EndorsementSignal::Unendorsed,
        );

        let mut expected_req = target_forward.clone();
        expected_req.incoming_custom_records =
            records_from_endorsement(EndorsementSignal::Endorsed);
        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &expected_req);
        interceptor.intercept_htlc(target_forward).await;
    }

    /// Tests that forwards by the target sent from attacker -> target are handled like any other target payment.
    #[tokio::test]
    async fn test_target_from_attacker() {
        let mut interceptor = setup_interceptor_test();

        let (not_actually_attacker, _) =
            setup_test_request(interceptor.target_pubkey, 0, 3, EndorsementSignal::Endorsed);

        // This tests hangs; the target is actually jamming the attacker lol because we don't check the direction
        mock_intercept_htlc(
            &mut interceptor.reputation_interceptor,
            &not_actually_attacker,
        );
        interceptor.intercept_htlc(not_actually_attacker).await;
    }
}
