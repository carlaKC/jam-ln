use bitcoin::secp256k1::PublicKey;

use super::JammingAttack;

pub struct SinkAttack {
    target_pubkey: PublicKey,
    attacker_pubkeys: PublicKey,
}

impl JammingAttack for SinkAttack {}
