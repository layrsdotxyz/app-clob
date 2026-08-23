use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccessCapability {
    PublicData,
    AccountRead,
    Authentication,
    Deposits,
    NewOrders,
    OrderCancellation,
    PositionReduction,
    Redemptions,
    Withdrawals,
    PrivateApiMutations,
    X402Mutations,
    McpMutations,
}

impl AccessCapability {
    pub fn aad_label(self) -> &'static [u8] {
        match self {
            Self::PublicData => b"publicData",
            Self::AccountRead => b"accountRead",
            Self::Authentication => b"authentication",
            Self::Deposits => b"deposits",
            Self::NewOrders => b"newOrders",
            Self::OrderCancellation => b"orderCancellation",
            Self::PositionReduction => b"positionReduction",
            Self::Redemptions => b"redemptions",
            Self::Withdrawals => b"withdrawals",
            Self::PrivateApiMutations => b"privateApiMutations",
            Self::X402Mutations => b"x402Mutations",
            Self::McpMutations => b"mcpMutations",
        }
    }
}
