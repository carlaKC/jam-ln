use crate::clock::InstantClock;
use crate::reputation_interceptor::{HtlcAdd, ReputationMonitor, ReputationPair};
use crate::{endorsement_from_records, records_from_endorsement, BoxError};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use futures::future::join_all;
use ln_resource_mgr::outgoing_reputation::ForwardManagerParams;
use ln_resource_mgr::{EndorsementSignal, ForwardingOutcome, HtlcRef, ProposedForward};
use simln_lib::clock::Clock;
use simln_lib::sim_node::{ForwardingError, InterceptRequest, InterceptResolution, Interceptor};
use simln_lib::ShortChannelID;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::select;
use triggered::{Listener, Trigger};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetChannelType {
    Attacker,
    Peer,
}

/// Provides the reputation pairs for Peers -> Target and Target -> Attacker to gauge the reputation state of attack
/// relevant nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkReputation {
    /// The attacker's pairwise outgoing reputation with the target.
    pub attacker_reputation: Vec<ReputationPair>,

    /// The target's pairwise outgoing reputation with its peers.
    pub target_reputation: Vec<ReputationPair>,
}

impl NetworkReputation {
    /// Gets the number of pairs that the target or attacker has outgoing reputation for.
    pub fn reputation_count(
        &self,
        target: bool,
        params: &ForwardManagerParams,
        htlc_fee: u64,
        expiry: u32,
    ) -> usize {
        if target {
            &self.target_reputation
        } else {
            &self.attacker_reputation
        }
        .iter()
        .filter(|pair| pair.outgoing_reputation(params.htlc_opportunity_cost(htlc_fee, expiry)))
        .count()
    }
}

// Implements a "sink" attack where an attacking node:
// - General jams its peers so that htlcs will be endorsed
// - Holds the endorsed htlcs to trash the target node's reputation with its peers
//
// This interceptor wraps an inner reputation interceptor so that we can still operate with regular reputation
// on the non-attacking nodes. Doing so also allows us access to reputation values for monitoring.
#[derive(Clone)]
pub struct SinkInterceptor<C, R>
where
    C: InstantClock + Clock,
    R: Interceptor + ReputationMonitor,
{
    clock: Arc<C>,
    attacker_pubkey: PublicKey,
    target_pubkey: PublicKey,
    /// Keeps track of the target's channels for custom behavior.
    target_channels: HashMap<ShortChannelID, TargetChannelType>,
    /// List of public keys of the target's honest (non-attacker) peers.
    honest_peers: Vec<PublicKey>,
    /// Inner reputation monitor that implements jamming mitigation.
    reputation_interceptor: R,
    /// Used to control shutdown.
    listener: Listener,
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

impl<C: InstantClock + Clock, R: Interceptor + ReputationMonitor> SinkInterceptor<C, R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<C>,
        attacker_pubkey: PublicKey,
        target_pubkey: PublicKey,
        target_channels: HashMap<ShortChannelID, TargetChannelType>,
        honest_peers: Vec<PublicKey>,
        reputation_interceptor: R,
        listener: Listener,
        shutdown: Trigger,
    ) -> Self {
        Self {
            clock,
            attacker_pubkey,
            target_pubkey,
            target_channels,
            honest_peers,
            reputation_interceptor,
            listener,
            shutdown,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_network(
        clock: Arc<C>,
        attacker_pubkey: PublicKey,
        target_pubkey: PublicKey,
        target_channels: HashMap<ShortChannelID, TargetChannelType>,
        honest_peers: Vec<PublicKey>,
        reputation_interceptor: R,
        listener: Listener,
        shutdown: Trigger,
    ) -> Self {
        Self::new(
            clock,
            attacker_pubkey,
            target_pubkey,
            target_channels,
            honest_peers,
            reputation_interceptor,
            listener,
            shutdown,
        )
    }

    /// Reports on the current reputation state of the target node with its peers, and the attacker's standing with
    /// the target.
    pub async fn get_reputation_status(
        &self,
        access_ins: Instant,
    ) -> Result<NetworkReputation, BoxError> {
        // Can use regular mapping closures because get_target_pairs is async.
        let target_reputation_results: Vec<Result<Vec<ReputationPair>, BoxError>> =
            join_all(self.honest_peers.iter().map(|pubkey| async {
                self.get_target_pairs(*pubkey, TargetChannelType::Peer, access_ins)
                    .await
            }))
            .await;

        Ok(NetworkReputation {
            attacker_reputation: self
                .get_target_pairs(self.target_pubkey, TargetChannelType::Attacker, access_ins)
                .await?,
            target_reputation: target_reputation_results
                .into_iter()
                .collect::<Result<Vec<Vec<ReputationPair>>, BoxError>>()?
                .into_iter()
                .flatten()
                .collect(),
        })
    }

    /// Gets reputation pairs for the node provided, filtering them for channels that the target node is a part of.
    /// - TargetChannelType::Peer / Node=Peer: reports the target's reputation in the eyes of its peers.
    /// - TargetChannelType::Attacker / Node=Target: reports the attacker's reputation in the eyes of the target.
    ///
    /// Note that if the node provided is not the target or one of its peers, nothing will be returned.
    pub async fn get_target_pairs(
        &self,
        node: PublicKey,
        filter_chan_type: TargetChannelType,
        access_ins: Instant,
    ) -> Result<Vec<ReputationPair>, BoxError> {
        let channels: HashSet<u64> = self
            .target_channels
            .iter()
            .filter(|(_, chan_type)| **chan_type == filter_chan_type)
            .map(|(scid, _)| *scid)
            .map(|scid| scid.into()) // TODO: don't double map
            .collect();

        let reputations: Vec<ReputationPair> = self
            .reputation_interceptor
            .list_reputation_pairs(node, access_ins)
            .await?
            .iter()
            .filter(|scid| channels.contains(&scid.outgoing_scid))
            .copied()
            .collect();

        Ok(reputations)
    }

    /// Intercepts payments flowing from target -> attacker, holding the htlc for the maximum allowable time to
    /// trash its reputation if the htlc is endorsed. We do not use our underlying jamming mitigation interceptor
    /// at all because the attacker is not required to run the mitigation.
    async fn intercept_attacker_incoming(&self, req: InterceptRequest) {
        // Exit early if not endorsed, no point in holding.
        if endorsement_from_records(&req.incoming_custom_records) == EndorsementSignal::Unendorsed {
            log::info!(
                "HTLC from target -> attacker not endorsed, releasing: {}",
                print_request(&req)
            );
            send_intercept_result!(
                req,
                Ok(Ok(records_from_endorsement(EndorsementSignal::Unendorsed))),
                self.shutdown
            );
            return;
        }

        // Get maximum hold time assuming 10 minute blocks.
        // TODO: this is actually the current height less the expiry, but we don't have the concept of height here.
        let max_hold_secs = Duration::from_secs(
            ((req.incoming_expiry_height - req.outgoing_expiry_height) * 10 * 60).into(),
        );

        log::info!(
            "HTLC from target -> attacker endorsed, holding for {:?}: {}",
            max_hold_secs,
            print_request(&req),
        );

        // If the htlc is endorsed, then we go ahead and hold the htlc for as long as we can only exiting if we
        // get a shutdown signal elsewhere.
        let resp = select! {
            _ = self.listener.clone() => Err(ForwardingError::InterceptorError("shutdown signal received".to_string().into())),
            _ = self.clock.sleep(max_hold_secs) => Ok(records_from_endorsement(EndorsementSignal::Endorsed))
        };

        send_intercept_result!(req, Ok(resp), self.shutdown);
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
impl<C: InstantClock + Clock, R: Interceptor + ReputationMonitor> Interceptor
    for SinkInterceptor<C, R>
{
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        // Intercept payments from target -> attacker.
        if let Some(target_chan) = self.target_channels.get(&req.incoming_htlc.channel_id) {
            if *target_chan == TargetChannelType::Attacker
                && req.forwarding_node == self.attacker_pubkey
            {
                self.intercept_attacker_incoming(req).await;
                return;
            }
        }

        // Intercept payments from peers -> target. If there's no outgoing_channel_id, the intercepting node is
        // the recipient so we take no action.
        if let Some(outgoing_channel_id) = req.outgoing_channel_id {
            if let Some(target_chan) = self.target_channels.get(&outgoing_channel_id) {
                if *target_chan == TargetChannelType::Peer
                    && req.forwarding_node != self.target_pubkey
                {
                    if let Err(e) = self.intercept_peer_outgoing(req.clone()).await {
                        log::error!("Could not intercept peer outgoing: {e}");
                        self.shutdown.trigger();
                    }

                    return;
                }
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
        // If this was a payment forwarded through the attacker from the target (target -> attacker -> *), we don't
        // want to report it to the reputation interceptor (because we didn't use it for the original intercepted htlc).
        if let Some(target_chan) = self.target_channels.get(&res.incoming_htlc.channel_id) {
            if *target_chan == TargetChannelType::Attacker {
                return Ok(());
            }
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

    use crate::reputation_interceptor::{HtlcAdd, ReputationMonitor, ReputationPair};
    use crate::test_utils::{get_random_keypair, setup_test_request, test_allocation_check};
    use crate::{endorsement_from_records, records_from_endorsement, test_utils, BoxError};
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use ln_resource_mgr::{AllocationCheck, EndorsementSignal, ReputationError};
    use mockall::mock;
    use mockall::predicate::function;
    use simln_lib::clock::SimulationClock;
    use simln_lib::sim_node::{InterceptRequest, InterceptResolution, Interceptor};
    use simln_lib::ShortChannelID;

    use super::{SinkInterceptor, TargetChannelType};

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
            async fn list_reputation_pairs(&self,node: PublicKey,access_ins: std::time::Instant) -> Result<Vec<ReputationPair>, BoxError>;
            async fn check_htlc_outcome(&self,htlc_add: HtlcAdd) -> Result<AllocationCheck, ReputationError>;
        }
    }

    fn setup_interceptor_test() -> SinkInterceptor<SimulationClock, MockReputationInterceptor> {
        let target_pubkey = get_random_keypair().1;
        let attacker_pubkey = get_random_keypair().1;
        let honest_peers = vec![
            test_utils::get_random_keypair().1,
            test_utils::get_random_keypair().1,
            test_utils::get_random_keypair().1,
        ];
        let target_channels = HashMap::from([
            (ShortChannelID::from(0), TargetChannelType::Attacker),
            (ShortChannelID::from(1), TargetChannelType::Peer),
            (ShortChannelID::from(2), TargetChannelType::Peer),
            (ShortChannelID::from(3), TargetChannelType::Peer),
        ]);

        let (shutdown, listener) = triggered::trigger();
        let mock = MockReputationInterceptor::new();
        let interceptor = SinkInterceptor::new(
            Arc::new(SimulationClock::new(1).unwrap()),
            target_pubkey,
            attacker_pubkey,
            target_channels,
            honest_peers,
            mock,
            listener,
            shutdown,
        );

        interceptor
    }

    /// Primes the mock to expect intercept_htlc called with the request provided.
    fn mock_intercept_htlc(interceptor: &mut MockReputationInterceptor, req: &InterceptRequest) {
        let expected_incoming = req.incoming_htlc.channel_id.clone();
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
        let (peer_to_target, _) = setup_test_request(
            interceptor.honest_peers[0],
            5,
            1,
            EndorsementSignal::Endorsed,
        );

        mock_intercept_htlc(&mut interceptor.reputation_interceptor, &peer_to_target);
        interceptor.intercept_htlc(peer_to_target).await;
    }

    /// Tests that payments forwarded from peer -> target are optimistically upgraded to endorsed if they have
    /// sufficient reputation.
    #[tokio::test]
    async fn test_peer_to_target_upgraded() {
        let mut interceptor = setup_interceptor_test();

        let (peer_to_target, _) = setup_test_request(
            interceptor.honest_peers[0],
            5,
            1,
            EndorsementSignal::Unendorsed,
        );

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

        let (peer_to_target, _) = setup_test_request(
            interceptor.honest_peers[0],
            5,
            1,
            EndorsementSignal::Unendorsed,
        );

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
