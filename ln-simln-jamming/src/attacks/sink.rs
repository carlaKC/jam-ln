use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::EndorsementSignal;
use simln_lib::clock::Clock;
use simln_lib::sim_node::{ForwardingError, InterceptRequest};
use simln_lib::NetworkParser;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::Mutex;
use triggered::{Listener, Trigger};

use crate::clock::InstantClock;
use crate::{
    endorsement_from_records, get_network_reputation, records_from_endorsement, BoxError,
    NetworkReputation,
};

use super::{AttackMonitor, JammingAttack, NetworkSetup};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetChannelType {
    Attacker,
    Peer,
}

macro_rules! send_intercept_result {
    ($req:expr, $result:expr, $shutdown:expr) => {
        if let Err(e) = $req.response.send($result).await {
            log::error!("Could not send to interceptor: {e}");
            $shutdown.trigger();
        }
    };
}

#[derive(Clone)]
pub struct SinkAttack<C>
where
    C: Clock + InstantClock,
{
    clock: Arc<C>,
    target_pubkey: PublicKey,
    target_alias: String,
    attacker_pubkey: PublicKey,
    target_channels: HashMap<u64, (PublicKey, String)>,
    risk_margin: u64,
    listener: Listener,
    shutdown: Trigger,
}

impl<C: Clock + InstantClock> SinkAttack<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock: Arc<C>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        target_alias: String,
        attacker_pubkey: PublicKey,
        risk_margin: u64,
        listener: Listener,
        shutdown: Trigger,
    ) -> Self {
        Self {
            clock,
            target_pubkey,
            target_alias,
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
            listener,
            shutdown,
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
    /// trash its reputation if the htlc is endorsed. We do not use our underlying jamming mitigation interceptor
    /// at all because the attacker is not required to run the mitigation.
    async fn intercept_attacker_incoming(&self, req: InterceptRequest) {
        assert_eq!(
            self.attacker_pubkey, req.forwarding_node,
            "misuse of intercept_attacker_incoming"
        );

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

        // Get maximum hold time assuming 10 minute blocks, assuming a zero block height (simulator doesn't track
        // height).
        let max_hold_secs = Duration::from_secs((req.incoming_expiry_height * 10 * 60).into());

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
}

#[async_trait]
impl<C> JammingAttack for SinkAttack<C>
where
    C: Clock + InstantClock,
{
    fn setup_for_network(&self) -> Result<NetworkSetup, BoxError> {
        self.validate()?;

        // Monitor all of the target node's peer and the target itself.
        let mut monitored_nodes: Vec<(PublicKey, String)> = self
            .target_channels
            .iter()
            .filter_map(|(_, (pk, alias))| {
                if *pk != self.attacker_pubkey {
                    Some((*pk, alias.clone()))
                } else {
                    None
                }
            })
            .collect();
        monitored_nodes.push((self.target_pubkey, self.target_alias.clone()));

        Ok(NetworkSetup {
            monitored_nodes,
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

    async fn intercept_attacker_htlc(&self, req: InterceptRequest) -> Result<(), BoxError> {
        if let Some((pk, _)) = self
            .target_channels
            .get(&req.incoming_htlc.channel_id.into())
        {
            assert_eq!(*pk, self.attacker_pubkey, "intercept_attacker_htlc misused");

            self.intercept_attacker_incoming(req).await;
            return Ok(());
        }

        send_intercept_result!(
            req,
            Ok(Err(ForwardingError::InterceptorError(
                "attacker failing".into()
            ))),
            self.shutdown
        );

        Ok(())
    }

    async fn simulation_completed(
        &self,
        reputation_monitor: Arc<Mutex<impl AttackMonitor>>,
        start_reputation: NetworkReputation,
    ) -> Result<bool, BoxError> {
        let status = get_network_reputation(
            reputation_monitor,
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
        .await;

        match status {
            Ok(rep) => {
                if rep.attacker_reputation == 0 {
                    log::error!("Attacker has no more reputation with the target");

                    if rep.target_reputation >= start_reputation.target_reputation {
                        log::error!("Attacker has no more reputation with target and the target's reputation is similar to simulation start");
                        return Ok(true);
                    }

                    log::info!("Attacker has no more reputation with target but target's reputation is worse than start count ({} < {}), continuing simulation to monitor recovery", rep.target_reputation, start_reputation.target_reputation);
                }

                Ok(false)
            }
            Err(e) => return Err(format!("Error checking attacker reputation: {}", e).into()),
        }
    }
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
