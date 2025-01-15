use crate::reputation_interceptor::{ReputationInterceptor, ReputationPair};
use crate::{endorsement_from_records, BoxError};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use futures::future::join_all;
use ln_resource_mgr::outgoing_reputation::ForwardManagerParams;
use ln_resource_mgr::EndorsementSignal;
use simln_lib::clock::Clock;
use simln_lib::sim_node::{
    CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
};
use simln_lib::{NetworkParser, ShortChannelID};
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
pub struct SinkInterceptor {
    clock: Arc<dyn Clock>,
    target_pubkey: PublicKey,
    /// Keeps track of the target's channels for custom behavior.
    target_channels: HashMap<ShortChannelID, TargetChannelType>,
    /// List of public keys of the target's honest (non-attacker) peers.
    honest_peers: Vec<PublicKey>,
    /// Inner reputation monitor that implements jamming mitigation.
    reputation_interceptor: ReputationInterceptor,
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

impl SinkInterceptor {
    pub fn new_for_network(
        clock: Arc<dyn Clock>,
        attacking_pubkey: PublicKey,
        target_pubkey: PublicKey,
        edges: &[NetworkParser],
        jamming_interceptor: ReputationInterceptor,
        listener: Listener,
        shutdown: Trigger,
    ) -> Self {
        let mut target_channels = HashMap::new();
        let mut honest_peers = Vec::new();

        for channel in edges.iter() {
            let node_1_target = channel.node_1.pubkey == target_pubkey;
            let node_2_target = channel.node_2.pubkey == target_pubkey;

            if !(node_1_target || node_2_target) {
                continue;
            }

            let channel_type = if node_1_target && channel.node_2.pubkey == attacking_pubkey {
                TargetChannelType::Attacker
            } else if node_1_target {
                TargetChannelType::Peer
            } else if node_2_target && channel.node_1.pubkey == attacking_pubkey {
                TargetChannelType::Attacker
            } else {
                TargetChannelType::Peer
            };

            if channel_type == TargetChannelType::Peer {
                honest_peers.push(if node_1_target {
                    channel.node_2.pubkey
                } else {
                    channel.node_1.pubkey
                });
            }
            target_channels.insert(channel.scid, channel_type);
        }

        Self {
            clock,
            target_pubkey,
            honest_peers,
            reputation_interceptor: jamming_interceptor,
            target_channels,
            listener,
            shutdown,
        }
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
            .filter(|scid| channels.get(&scid.outgoing_scid).is_some())
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
            send_intercept_result!(req, Ok(Ok(CustomRecords::default())), self.shutdown);
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
            _ = self.clock.sleep(max_hold_secs) => Ok(CustomRecords::default())
        };

        send_intercept_result!(req, Ok(resp), self.shutdown);
    }

    /// Intercepts payments flowing from peer -> target, simulating a general jamming attack by failing any
    /// unendorsed payments.
    async fn intercept_peer_outgoing(&self, req: InterceptRequest) {
        log::info!(
            "HTLC from peer -> target, general jamming if endorsed: {}",
            print_request(&req),
        );

        // If the htlc is endorsed, apply usual reputation checks, otherwise just reject unendorsed htlcs to mimic
        // a general jam on the channel.
        match endorsement_from_records(&req.incoming_custom_records) {
            EndorsementSignal::Endorsed => self.reputation_interceptor.intercept_htlc(req).await,
            EndorsementSignal::Unendorsed => {
                let resp = Ok(Err(ForwardingError::InterceptorError(
                    "general jamming unendorsed".to_string().into(),
                )));

                send_intercept_result!(req, resp, self.shutdown)
            }
        };
    }
}

#[async_trait]
impl Interceptor for SinkInterceptor {
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        // Intercept payments from target -> attacker.
        if let Some(target_chan) = self.target_channels.get(&req.incoming_htlc.channel_id) {
            if *target_chan == TargetChannelType::Attacker {
                self.intercept_attacker_incoming(req).await;
                return;
            }
        }

        // Intercept payments from peers -> target. If there's no outgoing_channel_id, the intercepting node is
        // the recipient so we take no action.
        if let Some(outgoing_channel_id) = req.outgoing_channel_id {
            if let Some(target_chan) = self.target_channels.get(&outgoing_channel_id) {
                if *target_chan == TargetChannelType::Peer {
                    self.intercept_peer_outgoing(req).await;
                    return;
                }
            }
        }

        // The target is not involved in the forward at all, just use jamming interceptor to implement reputation
        // and bucketing.
        self.reputation_interceptor.intercept_htlc(req).await
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
