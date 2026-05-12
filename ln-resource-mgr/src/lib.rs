use serde::Serialize;
use std::fmt::Display;

/// The different possible accountable signals on a htlc's update_add message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AccountableSignal {
    Unaccountable,
    Accountable,
}

impl Display for AccountableSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountableSignal::Accountable => write!(f, "accountable"),
            AccountableSignal::Unaccountable => write!(f, "unaccountable"),
        }
    }
}

/// Provides a snapshot of the reputation and revenue values tracked for a channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelSnapshot {
    pub capacity_msat: u64,
    pub outgoing_reputation: i64,
    pub incoming_revenue: i64,
}
