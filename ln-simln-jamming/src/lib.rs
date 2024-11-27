pub mod reputation_interceptor {
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use simln_lib::sim_node::{
        CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
    };
    use simln_lib::NetworkParser;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use ln_resource_mgr::outgoing_reputation::{
        ForwardManager, ForwardManagerParams, ReputationParams,
    };
    use ln_resource_mgr::reputation::{
        AllocatoinCheck, EndorsementSignal, ForwardResolution, ForwardingOutcome, HtlcRef,
        ProposedForward, ReputationError, ReputationManager,
    };

    pub const ENDORSEMENT_TYPE: u64 = 106823;

    pub fn endorsement_from_records(records: &CustomRecords) -> EndorsementSignal {
        match records.get(&ENDORSEMENT_TYPE) {
            Some(endorsed) => {
                if endorsed.len() == 1 && endorsed[0] == 1 {
                    EndorsementSignal::Endorsed
                } else {
                    // Consider any value that isn't [1] to be unendorsed.
                    // TODO: we really shouldn't run into this?
                    EndorsementSignal::Unendorsed
                }
            }
            None => EndorsementSignal::Unendorsed,
        }
    }

    /// Implements a network-wide interceptor that implements resource management for every forwarding node in the
    /// network.
    pub struct JammingInterceptor {
        network_nodes: Arc<Mutex<HashMap<PublicKey, (ForwardManager, String)>>>,
    }

    impl JammingInterceptor {
        pub fn new_for_network(edges: &Vec<NetworkParser>) -> Result<Self, ()> {
            let mut network_nodes: HashMap<PublicKey, (ForwardManager, String)> = HashMap::new();

            macro_rules! add_node_to_network {
                ($network_nodes:expr, $node_pubkey:expr, $node_alias:expr, $channel:expr) => {
                    match $network_nodes.entry($node_pubkey) {
                        Entry::Vacant(e) => {
                            let forward_manager = ForwardManager::new(ForwardManagerParams {
                                reputation_params: ReputationParams {
                                    revenue_window: Duration::from_secs(14 * 24 * 60 * 60),
                                    reputation_multiplier: 12,
                                    resolution_period: Duration::from_secs(90),
                                    expected_block_speed: Some(Duration::from_secs(10 * 60 * 60)),
                                },
                                general_slot_portion: 50,
                                general_liquidity_portion: 50,
                            });

                            let _ = forward_manager
                                .add_channel($channel.scid.into(), $channel.capacity_msat)
                                .map_err(|_| ())?;

                            e.insert((forward_manager, $node_alias));
                        }
                        Entry::Occupied(mut e) => {
                            let _ = e
                                .get_mut()
                                .0
                                .add_channel($channel.scid.into(), $channel.capacity_msat)
                                .map_err(|_| ())?;
                        }
                    }
                };
            }

            for channel in edges {
                add_node_to_network!(
                    network_nodes,
                    channel.node_1.pubkey,
                    channel.node_1.alias.clone(),
                    channel
                );
                add_node_to_network!(
                    network_nodes,
                    channel.node_2.pubkey,
                    channel.node_2.alias.clone(),
                    channel
                );
            }

            Ok(Self {
                network_nodes: Arc::new(Mutex::new(network_nodes)),
            })
        }

        // TODO: flatten this with a macro
        pub fn get_forwarding_outcome(
            &self,
            forwading_node: PublicKey,
            htlc: &ProposedForward,
        ) -> Result<(AllocatoinCheck, String), ReputationError> {
            match self.network_nodes.lock().unwrap().entry(forwading_node) {
                Entry::Occupied(mut e) => {
                    let (node, alias) = e.get_mut();
                    Ok((node.get_forwarding_outcome(htlc)?, alias.to_string()))
                }
                Entry::Vacant(_) => Err(ReputationError::ErrUnknown(format!(
                    "node not found: {}",
                    forwading_node,
                ))),
            }
        }

        fn get_interceptor_resp(
            &self,
            forwading_node: PublicKey,
            htlc: &ProposedForward,
        ) -> Result<(AllocatoinCheck, String), ReputationError> {
            match self.network_nodes.lock().unwrap().entry(forwading_node) {
                Entry::Occupied(mut e) => {
                    let (node, alias) = e.get_mut();
                    Ok((node.add_outgoing_hltc(htlc)?, alias.to_string()))
                }
                Entry::Vacant(_) => Err(ReputationError::ErrUnknown(format!(
                    "node not found: {}",
                    forwading_node,
                ))),
            }
        }
    }

    #[async_trait]
    impl Interceptor for JammingInterceptor {
        /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
        async fn intercept_htlc(&self, req: InterceptRequest) {
            // If the intercept has no outgoing channel, we can just exit early because there's no action to be taken.
            let outgoing_channel_id = match req.outgoing_channel_id {
                Some(c) => c.into(),
                None => {
                    if let Err(e) = req.response.send(Ok(Ok(CustomRecords::default()))).await {
                        // TODO: select?
                        println!("Failed to send response: {:?}", e);
                    }
                    return;
                }
            };

            let htlc = &ProposedForward {
                incoming_ref: HtlcRef {
                    channel_id: req.incoming_htlc.channel_id.into(),
                    htlc_index: req.incoming_htlc.index,
                },
                outgoing_channel_id,
                amount_in_msat: req.incoming_amount_msat,
                amount_out_msat: req.outgoing_amount_msat,
                expiry_in_height: req.incoming_expiry_height,
                expiry_out_height: req.outgoing_expiry_height,
                added_at: Instant::now(),
                incoming_endorsed: endorsement_from_records(&req.incoming_custom_records),
            };

            // If we can't successfully perform a reputation check, error out the interceptor so that the simulation
            // will fail - we do not expect failure here.
            let (allocation_check, alias) =
                match self.get_interceptor_resp(req.forwarding_node, htlc) {
                    Ok(a) => a,
                    Err(e) => {
                        if let Err(e) = req.response.send(Err(Some(e.to_string()))).await {
                            println!("Failed to send response: {:?}", e); // TODO: error handling
                        }
                        return;
                    }
                };

            // Once we have a forwarding decision, return successfully to the interceptor with the call.
            let fwd_decision =
                allocation_check.forwarding_outcome(htlc.amount_out_msat, htlc.incoming_endorsed);

            log::info!(
                "Node {} forwarding: {} with outcome {}",
                alias,
                htlc,
                fwd_decision,
            );

            let resp = match fwd_decision {
                ForwardingOutcome::Forward(endorsement) => {
                    let mut outgoing_records = HashMap::new();

                    match endorsement {
                        EndorsementSignal::Endorsed => {
                            outgoing_records.insert(ENDORSEMENT_TYPE, vec![1]);
                        }
                        EndorsementSignal::Unendorsed => {
                            outgoing_records.insert(ENDORSEMENT_TYPE, vec![0]);
                        }
                    }

                    Ok(outgoing_records)
                }
                ForwardingOutcome::Fail(reason) => {
                    Err(ForwardingError::InterceptorError(format!("{:?}", reason)))
                }
            };

            if let Err(e) = req.response.send(Ok(resp)).await {
                // TODO: select
                println!("Failed to send response: {:?}", e); // TODO: error handling
            }
        }

        async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), Option<String>> {
            // If there's not outgoing channel, we're notifying on the receiving node which doesn't need any action.
            let outgoing_channel_id = match res.outgoing_channel_id {
                Some(c) => c.into(),
                None => return Ok(()),
            };

            match self
                .network_nodes
                .lock()
                .unwrap()
                .entry(res.forwarding_node)
            {
                Entry::Occupied(mut e) => e
                    .get_mut()
                    .0
                    .resolve_htlc(
                        outgoing_channel_id,
                        HtlcRef {
                            channel_id: res.incoming_htlc.channel_id.into(),
                            htlc_index: res.incoming_htlc.index,
                        },
                        ForwardResolution::from(res.success),
                        Instant::now(),
                    )
                    .map_err(|e| Some(format!("{e}"))),
                Entry::Vacant(_) => Err(Some(format!("Node: {} not found", res.forwarding_node))),
            }
        }

        /// Returns an identifying name for the interceptor for logging, does not need to be unique.
        fn name(&self) -> String {
            "channel jammer".to_string()
        }
    }
}

pub mod sink_attack_interceptor {
    use crate::reputation_interceptor::{endorsement_from_records, JammingInterceptor};
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use ln_resource_mgr::reputation::{EndorsementSignal, HtlcRef, ProposedForward};
    use simln_lib::sim_node::{
        CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
    };
    use simln_lib::{NetworkParser, ShortChannelID};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tokio::{select, time};
    use triggered::{Listener, Trigger};

    #[derive(Eq, PartialEq)]
    enum TargetChannelType {
        Attacker,
        Peer,
    }

    // Implements a "sink" attack where an attacking node:
    // - Builds up reputation so that it can slow jam a target node
    // - General jams its peers so that htlcs will be endorsed
    // - Holds the endorsed htlcs to trash the target node's reputation with its peers
    //
    // This interceptor wraps an inner reputation interceptor so that we can still operate with regular reputation
    // on the non-attacking nodes. Doing so also allows us access to reputation values for monitoring.
    pub struct SinkInterceptor {
        start_ins: Instant,
        bootstrap: Duration,
        /// Keeps track of the target's channels for custom behavior.
        target_channels: HashMap<ShortChannelID, TargetChannelType>,
        /// Inner reputation monitor that implements jamming mitigation.
        jamming_interceptor: JammingInterceptor,
        attacking_node: PublicKey,
        target_node: PublicKey,
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
            start_ins: Instant,
            bootstrap: Duration,
            attacking_alias: String,
            target_alias: String,
            edges: Vec<NetworkParser>,
            listener: Listener,
            shutdown: Trigger,
        ) -> Self {
            let mut target_channels = HashMap::new();
            // TODO: clean this up it's gross
            let mut attacker_pubkey = None;
            let mut target_pubkey = None;

            for channel in edges.iter() {
                let node_1_target = channel.node_1.alias == target_alias;
                let node_2_target = channel.node_2.alias == target_alias;

                if !(node_1_target || node_2_target) {
                    continue;
                }

                let channel_type = if node_1_target && channel.node_2.alias == attacking_alias {
                    attacker_pubkey = Some(channel.node_1.pubkey);
                    target_pubkey = Some(channel.node_2.pubkey);

                    TargetChannelType::Attacker
                } else if node_1_target {
                    TargetChannelType::Peer
                } else if node_2_target && channel.node_1.alias == attacking_alias {
                    attacker_pubkey = Some(channel.node_2.pubkey);
                    target_pubkey = Some(channel.node_1.pubkey);

                    TargetChannelType::Attacker
                } else {
                    TargetChannelType::Peer
                };

                target_channels.insert(channel.scid, channel_type);
            }

            Self {
                start_ins,
                bootstrap,
                jamming_interceptor: JammingInterceptor::new_for_network(&edges).unwrap(),
                target_channels,
                attacking_node: attacker_pubkey.unwrap(),
                target_node: target_pubkey.unwrap(),
                listener,
                shutdown,
            }
        }

        fn filter_chanels_by_type(&self, channel_type: TargetChannelType) -> Vec<ShortChannelID> {
            self.target_channels
                .iter()
                .filter(|v| *v.1 == channel_type)
                .map(|v| *v.0)
                .collect()
        }

        // Can be used to query all of the attacker's reputation stats.
        fn get_reputation_stats(&self) -> Result<(), ()> {
            let attacking_channels = self.filter_chanels_by_type(TargetChannelType::Attacker);
            let peer_channels = self.filter_chanels_by_type(TargetChannelType::Peer);

            for attacker_chan in attacking_channels.iter() {
                for peer_chan in peer_channels.iter() {
                    // Create a htlc that is forwarded from Peer -> Target -> Attacker to gauge whether the attacker
                    // has sufficient reputation.
                    let htlc = ProposedForward {
                        incoming_ref: HtlcRef {
                            channel_id: u64::from(*peer_chan),
                            htlc_index: 0,
                        },
                        outgoing_channel_id: u64::from(*attacker_chan),
                        // Set fee = 5000 msat.
                        amount_in_msat: 10_000,
                        amount_out_msat: 5_000,
                        // Set cltv_expiry_delta = 100.
                        expiry_in_height: 200,
                        expiry_out_height: 100,
                        added_at: Instant::now(),
                        incoming_endorsed: EndorsementSignal::Unendorsed,
                    };

                    let fwd_outcome = self
                        .jamming_interceptor
                        .get_forwarding_outcome(self.target_node, &htlc);

                    log::info!(
                        "Reputation check for attacker; {:?}",
                        fwd_outcome.map_err(|_| ())?.0
                    );
                }
            }

            Ok(())
        }

        pub async fn poll_reputation_stats(&self, interval: Duration) -> Result<(), ()> {
            loop {
                select! {
                    _ = self.listener.clone() => return Ok(()),
                    _ = time::sleep(interval) => {
                        self.get_reputation_stats()?;
                    }
                }
            }
        }

        /// Intercepts payments flowing from target -> attacker, holding the htlc for the maximum allowable time to
        /// trash its reputation if the htlc is endorsed. We do not use our underlying jamming mitigation interceptor
        /// at all because the attacker is not required to run the mitigation.
        async fn intercept_attacker_incoming(&self, req: InterceptRequest) {
            // The attacker only starts to act on htlcs once the bootstrap period is over.
            if Instant::now().duration_since(self.start_ins) < self.bootstrap {
                log::info!(
                    "HTLC from target -> attacker received during bootstrap period, forwarding: {}",
                    print_request(&req)
                );
                send_intercept_result!(req, Ok(Ok(CustomRecords::default())), self.shutdown);
            }

            // Exit early if not endorsed, no point in holding.
            if endorsement_from_records(&req.incoming_custom_records)
                == EndorsementSignal::Unendorsed
            {
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
                _ = self.listener.clone() => Err(ForwardingError::InterceptorError("shutdown signal received".to_string())),

                _ = time::sleep(max_hold_secs) => Ok(CustomRecords::default())
            };

            send_intercept_result!(req, Ok(resp), self.shutdown);
        }

        /// Intercepts payments flowing from peer -> target, simulating a general jamming attack by failing any
        /// unendorsed payments.
        async fn intercept_peer_outgoing(&self, req: InterceptRequest) {
            // If we're still in the bootstrapping period, just handle the htlc as usual.
            if Instant::now().duration_since(self.start_ins) < self.bootstrap {
                log::info!(
                    "HTLC from peer -> target received during bootstrap period, forwarding: {}",
                    print_request(&req)
                );

                self.jamming_interceptor.intercept_htlc(req).await;
                return;
            }

            log::info!(
                "HTLC from peer -> target, general jamming if endorsed: {}",
                print_request(&req),
            );

            // If the htlc is endorsed, apply usual reputation checks, otherwise just reject unendorsed htlcs to mimic
            // a general jam on the channel.
            match endorsement_from_records(&req.incoming_custom_records) {
                EndorsementSignal::Endorsed => self.jamming_interceptor.intercept_htlc(req).await,
                EndorsementSignal::Unendorsed => {
                    let resp = Ok(Err(ForwardingError::InterceptorError(
                        "general jamming unendorsed".to_string(),
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
            self.jamming_interceptor.intercept_htlc(req).await
        }

        /// Notifies the underlying jamming interceptor of htlc resolution, as our attacking interceptor doesn't need
        /// to handle notifications.
        async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), Option<String>> {
            self.jamming_interceptor.notify_resolution(res).await
        }

        fn name(&self) -> String {
            "sink attack".to_string()
        }
    }
}
