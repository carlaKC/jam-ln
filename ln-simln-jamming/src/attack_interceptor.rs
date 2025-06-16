use crate::attacks::JammingAttack;
use crate::reputation_interceptor::ReputationMonitor;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use simln_lib::sim_node::{
    CriticalError, CustomRecords, ForwardingError, InterceptRequest, InterceptResolution,
    Interceptor,
};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Wraps an innner reputation interceptor (which is responsible for implementing a mitigation to
/// channel jamming) in an outer interceptor which can be used to take custom actions for attacks.
#[derive(Clone)]
pub struct AttackInterceptor<R, A>
where
    R: Interceptor + ReputationMonitor,
    A: JammingAttack,
{
    attacker_pubkey: PublicKey,
    /// Inner reputation monitor that implements jamming mitigation.
    reputation_interceptor: Arc<Mutex<R>>,
    /// The attack that will be launched.
    attack: Arc<A>,
}

impl<R, A> AttackInterceptor<R, A>
where
    R: Interceptor + ReputationMonitor,
    A: JammingAttack + Sync + Send,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attacker_pubkey: PublicKey,
        reputation_interceptor: Arc<Mutex<R>>,
        attack: Arc<A>,
    ) -> Self {
        Self {
            attacker_pubkey,
            reputation_interceptor,
            attack,
        }
    }
}

#[async_trait]
impl<R, A> Interceptor for AttackInterceptor<R, A>
where
    R: Interceptor + ReputationMonitor,
    A: JammingAttack + Send + Sync,
{
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, CriticalError> {
        // Intercept payments on the attacking node. If they're incoming from the target, jam them. Otherwise just
        // fail other htlcs, they're not that interesting to us.
        if req.forwarding_node == self.attacker_pubkey {
            return self
                .attack
                .intercept_attacker_htlc(req)
                .await
                .map_err(|e| CriticalError::InterceptorError(e.to_string()));
        }

        // If attacker is not involved, use jamming interceptor to implement reputation and
        // bucketing.
        self.reputation_interceptor
            .lock()
            .await
            .intercept_htlc(req)
            .await
    }

    /// Notifies the underlying jamming interceptor of htlc resolution, as our attacking interceptor doesn't need
    /// to handle notifications.
    async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), CriticalError> {
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
    use std::sync::Arc;

    use crate::attacks::JammingAttack;
    use crate::test_utils::{get_random_keypair, setup_test_request, MockReputationInterceptor};
    use crate::{records_from_signal, BoxError, NetworkReputation};
    use async_trait::async_trait;
    use ln_resource_mgr::AccountableSignal;
    use mockall::mock;
    use mockall::predicate::function;
    use simln_lib::sim_node::{CustomRecords, ForwardingError, InterceptRequest, Interceptor};
    use tokio::sync::Mutex;

    use super::AttackInterceptor;

    mock! {
        Attack{}

        #[async_trait]
        impl JammingAttack for Attack {
            fn setup_for_network(&self) -> Result<crate::attacks::NetworkSetup, BoxError>;
            async fn intercept_attacker_htlc(&self, req: InterceptRequest) -> Result<Result<CustomRecords, ForwardingError>, BoxError>;
            async fn simulation_completed(&self, _start_reputation: NetworkReputation) -> Result<bool, BoxError>;
        }
    }

    fn setup_interceptor_test() -> AttackInterceptor<MockReputationInterceptor, MockAttack> {
        let attacker_pubkey = get_random_keypair().1;

        let mock = MockReputationInterceptor::new();
        AttackInterceptor::new(
            attacker_pubkey,
            Arc::new(Mutex::new(mock)),
            Arc::new(MockAttack::new()),
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
            .return_once(|_| Ok(Ok(CustomRecords::new())));
    }

    /// Tests that any attacker htlc are forwarded through to the attacker.
    #[tokio::test]
    async fn test_attacker_intercept() {
        let attacker_pubkey = get_random_keypair().1;
        let mut mock_attack = MockAttack::new();
        mock_attack
            .expect_intercept_attacker_htlc()
            .returning(|_| Ok(Ok(CustomRecords::new())))
            .times(2);

        let interceptor = AttackInterceptor::new(
            attacker_pubkey,
            Arc::new(Mutex::new(MockReputationInterceptor::new())),
            Arc::new(mock_attack),
        );

        // Intercepted on attacker: target -(0)-> attacker -(5)-> node.
        let target_to_attacker = setup_test_request(
            interceptor.attacker_pubkey,
            0,
            5,
            AccountableSignal::Unaccountable,
        );
        interceptor
            .intercept_htlc(target_to_attacker)
            .await
            .unwrap()
            .unwrap();

        // Intercepted on attacker: node -(5)-> attacker -(0)-> target.
        let attacker_to_target = setup_test_request(
            interceptor.attacker_pubkey,
            5,
            0,
            AccountableSignal::Unaccountable,
        );
        interceptor
            .intercept_htlc(attacker_to_target)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_peer_to_target_accountable() {
        let interceptor = setup_interceptor_test();

        // Intercepted on target's peer: node -(5) -> peer -(1)-> target, accountable payments just passed through.
        let peer_pubkey = get_random_keypair().1;
        let peer_to_target = setup_test_request(peer_pubkey, 5, 1, AccountableSignal::Accountable);

        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &peer_to_target).await;
        interceptor
            .intercept_htlc(peer_to_target)
            .await
            .unwrap()
            .unwrap();
    }

    /// Tests that payments forwarded from peer -> target are optimistically upgraded to accountable if they have
    /// sufficient reputation.
    #[tokio::test]
    async fn test_peer_to_target_upgraded() {
        let interceptor = setup_interceptor_test();

        let peer_pubkey = get_random_keypair().1;
        let peer_to_target =
            setup_test_request(peer_pubkey, 5, 1, AccountableSignal::Unaccountable);

        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &peer_to_target).await;
        interceptor
            .intercept_htlc(peer_to_target)
            .await
            .unwrap()
            .unwrap();
    }

    /// Tests that payments forwarded from peer -> target are dropped if they don't have sufficient reputation to
    /// be upgraded to accountable.
    #[tokio::test]
    async fn test_peer_to_target_general_jammed() {
        let interceptor = setup_interceptor_test();

        let peer_pubkey = get_random_keypair().1;
        let peer_to_target =
            setup_test_request(peer_pubkey, 5, 1, AccountableSignal::Unaccountable);

        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &peer_to_target).await;
        interceptor
            .intercept_htlc(peer_to_target)
            .await
            .unwrap()
            .unwrap();
    }

    /// Tests that forwards through the target node to its peers will be upgraded to accountable.
    #[tokio::test]
    async fn test_target_to_peer() {
        let interceptor = setup_interceptor_test();

        let target_pubkey = get_random_keypair().1;
        let target_forward = setup_test_request(
            target_pubkey,
            1, // Honest channel
            2, // Honest channel
            AccountableSignal::Unaccountable,
        );

        let mut expected_req = target_forward.clone();
        expected_req.incoming_custom_records = records_from_signal(AccountableSignal::Accountable);
        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &expected_req).await;
        interceptor
            .intercept_htlc(target_forward)
            .await
            .unwrap()
            .unwrap();
    }

    /// Tests that forwards through the target node to the attacker will be upgraded to accountable.
    #[tokio::test]
    async fn test_target_to_attacker() {
        let interceptor = setup_interceptor_test();

        let target_pubkey = get_random_keypair().1;
        let target_forward = setup_test_request(
            target_pubkey,
            1, // Honest channel
            0, // Attacker
            AccountableSignal::Unaccountable,
        );

        let mut expected_req = target_forward.clone();
        expected_req.incoming_custom_records = records_from_signal(AccountableSignal::Accountable);
        mock_intercept_htlc(interceptor.reputation_interceptor.clone(), &expected_req).await;
        interceptor
            .intercept_htlc(target_forward)
            .await
            .unwrap()
            .unwrap();
    }

    /// Tests that forwards by the target sent from attacker -> target are handled like any other target payment.
    #[tokio::test]
    async fn test_target_from_attacker() {
        let interceptor = setup_interceptor_test();

        let target_pubkey = get_random_keypair().1;
        let not_actually_attacker =
            setup_test_request(target_pubkey, 0, 3, AccountableSignal::Accountable);

        // This tests hangs; the target is actually jamming the attacker lol because we don't check the direction
        mock_intercept_htlc(
            interceptor.reputation_interceptor.clone(),
            &not_actually_attacker,
        )
        .await;
        interceptor
            .intercept_htlc(not_actually_attacker)
            .await
            .unwrap()
            .unwrap();
    }
}
