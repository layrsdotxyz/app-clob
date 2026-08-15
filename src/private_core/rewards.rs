use ethers_core::types::Address;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeMap, str::FromStr};
use tiny_keccak::{Hasher, Keccak};

use super::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RewardKey {
    owner: String,
    chain: String,
    reward_token: String,
}

impl RewardKey {
    fn encoded(&self) -> String {
        format!("{}:{}:{}", self.owner, self.chain, self.reward_token)
    }

    fn decode(value: &str) -> Option<Self> {
        let mut parts = value.split(':');
        let owner = parts.next()?;
        let chain = parts.next()?;
        let reward_token = parts.next()?;
        if parts.next().is_some() || !valid_owner_id(owner) || !matches!(chain, "base" | "horizen")
        {
            return None;
        }
        Some(Self {
            owner: owner.into(),
            chain: chain.into(),
            reward_token: canonical_address(reward_token, "reward token").ok()?,
        })
    }
}

impl Serialize for RewardKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encoded())
    }
}

impl<'de> Deserialize<'de> for RewardKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::decode(&value).ok_or_else(|| serde::de::Error::custom("invalid reward key"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RewardEntry {
    #[serde(with = "super::decimal_u128")]
    cumulative_accrued: u128,
    claim_account: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "is_zero_u128",
        with = "super::decimal_u128"
    )]
    cumulative_maker_rebate: u128,
    #[serde(
        default,
        skip_serializing_if = "is_zero_u128",
        with = "super::decimal_u128"
    )]
    cumulative_taker_fees: u128,
    #[serde(
        default,
        skip_serializing_if = "is_zero_u128",
        with = "super::decimal_u128"
    )]
    cumulative_maker_volume_micros: u128,
    #[serde(
        default,
        skip_serializing_if = "is_zero_u128",
        with = "super::decimal_u128"
    )]
    cumulative_taker_volume_micros: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PrivateRewardBook {
    entries: BTreeMap<String, RewardEntry>,
    /// Daily, owner-private fee attribution makes later retrospective reward
    /// programs possible without changing historical fills or exposing the
    /// user-to-order relationship outside the enclave.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    daily_attributions: BTreeMap<String, DailyFeeAttribution>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct DailyFeeAttribution {
    #[serde(with = "super::decimal_u128")]
    maker_volume_micros: u128,
    #[serde(with = "super::decimal_u128")]
    taker_volume_micros: u128,
    #[serde(with = "super::decimal_u128")]
    taker_fees_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    maker_rebate_atomic: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRewardEntitlement {
    pub chain: String,
    pub reward_token: String,
    pub cumulative_amount_atomic: String,
    pub claim_account: Option<String>,
    pub cumulative_maker_rebate_atomic: String,
    pub cumulative_taker_fees_atomic: String,
    pub cumulative_maker_volume_micros: String,
    pub cumulative_taker_volume_micros: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardClaimIntent {
    pub protocol_version: String,
    pub chain: String,
    pub account: String,
    pub recipient: String,
    pub reward_token: String,
    pub cumulative_amount_atomic: String,
    pub deadline_seconds: u64,
    pub context_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardClaimAuthorization {
    pub intent: RewardClaimIntent,
    pub chain_id: u64,
    pub distributor: String,
    pub signer: String,
    pub signature: Vec<u8>,
}

impl PrivateRewardBook {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_fill(
        &mut self,
        taker_owner: &str,
        maker_owner: Option<&str>,
        chain: &str,
        reward_token: &str,
        quantity_micros: u128,
        taker_fee_atomic: u128,
        maker_rebate_atomic: u128,
        occurred_at_millis: i64,
    ) -> CoreResult<()> {
        if quantity_micros == 0 || occurred_at_millis < 0 {
            return Err(CoreError::InvalidOrder(
                "invalid private fee attribution".into(),
            ));
        }
        if maker_owner.is_none() && maker_rebate_atomic != 0 {
            return Err(CoreError::InvalidOrder(
                "maker rebate requires a maker".into(),
            ));
        }
        if maker_rebate_atomic > taker_fee_atomic {
            return Err(CoreError::InvalidOrder(
                "maker rebate exceeds taker fee".into(),
            ));
        }
        let day = occurred_at_millis / 86_400_000;
        let taker_key = reward_key(taker_owner, chain, reward_token)?;
        let taker_entry = self.entries.entry(taker_key.encoded()).or_default();
        taker_entry.cumulative_taker_fees = checked_add(
            taker_entry.cumulative_taker_fees,
            taker_fee_atomic,
            "taker fee attribution overflow",
        )?;
        taker_entry.cumulative_taker_volume_micros = checked_add(
            taker_entry.cumulative_taker_volume_micros,
            quantity_micros,
            "taker volume attribution overflow",
        )?;
        let taker_daily = self
            .daily_attributions
            .entry(format!("{}:{day}", taker_key.encoded()))
            .or_default();
        taker_daily.taker_fees_atomic = checked_add(
            taker_daily.taker_fees_atomic,
            taker_fee_atomic,
            "daily taker fee attribution overflow",
        )?;
        taker_daily.taker_volume_micros = checked_add(
            taker_daily.taker_volume_micros,
            quantity_micros,
            "daily taker volume attribution overflow",
        )?;

        if let Some(maker_owner) = maker_owner {
            let maker_key = reward_key(maker_owner, chain, reward_token)?;
            let maker_entry = self.entries.entry(maker_key.encoded()).or_default();
            maker_entry.cumulative_maker_rebate = checked_add(
                maker_entry.cumulative_maker_rebate,
                maker_rebate_atomic,
                "maker rebate attribution overflow",
            )?;
            maker_entry.cumulative_accrued = checked_add(
                maker_entry.cumulative_accrued,
                maker_rebate_atomic,
                "maker reward accrual overflow",
            )?;
            maker_entry.cumulative_maker_volume_micros = checked_add(
                maker_entry.cumulative_maker_volume_micros,
                quantity_micros,
                "maker volume attribution overflow",
            )?;
            let maker_daily = self
                .daily_attributions
                .entry(format!("{}:{day}", maker_key.encoded()))
                .or_default();
            maker_daily.maker_rebate_atomic = checked_add(
                maker_daily.maker_rebate_atomic,
                maker_rebate_atomic,
                "daily maker rebate attribution overflow",
            )?;
            maker_daily.maker_volume_micros = checked_add(
                maker_daily.maker_volume_micros,
                quantity_micros,
                "daily maker volume attribution overflow",
            )?;
        }
        Ok(())
    }

    pub(crate) fn accrue(
        &mut self,
        owner: &str,
        chain: &str,
        reward_token: &str,
        amount_atomic: u128,
    ) -> CoreResult<()> {
        if amount_atomic == 0 {
            return Err(CoreError::ZeroAmount);
        }
        let key = reward_key(owner, chain, reward_token)?;
        let entry = self.entries.entry(key.encoded()).or_default();
        entry.cumulative_accrued = entry
            .cumulative_accrued
            .checked_add(amount_atomic)
            .ok_or_else(|| CoreError::InvalidOrder("reward accrual overflow".into()))?;
        Ok(())
    }

    pub(crate) fn entitlements(&self, owner: &str) -> Vec<PrivateRewardEntitlement> {
        self.entries
            .iter()
            .filter_map(|(key, entry)| {
                let parsed = RewardKey::decode(key)?;
                if parsed.owner != owner
                    || (entry.cumulative_accrued == 0
                        && entry.cumulative_taker_fees == 0
                        && entry.cumulative_maker_volume_micros == 0
                        && entry.cumulative_taker_volume_micros == 0)
                {
                    return None;
                }
                Some((parsed, entry))
            })
            .map(|(key, entry)| PrivateRewardEntitlement {
                chain: key.chain,
                reward_token: key.reward_token,
                cumulative_amount_atomic: entry.cumulative_accrued.to_string(),
                claim_account: entry.claim_account.clone(),
                cumulative_maker_rebate_atomic: entry.cumulative_maker_rebate.to_string(),
                cumulative_taker_fees_atomic: entry.cumulative_taker_fees.to_string(),
                cumulative_maker_volume_micros: entry.cumulative_maker_volume_micros.to_string(),
                cumulative_taker_volume_micros: entry.cumulative_taker_volume_micros.to_string(),
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize(
        &mut self,
        owner: &str,
        chain: &str,
        account: &str,
        recipient: &str,
        reward_token: &str,
        deadline_seconds: u64,
        idempotency_key: &str,
    ) -> CoreResult<RewardClaimIntent> {
        let key = reward_key(owner, chain, reward_token)?;
        let account = canonical_address(account, "claim account")?;
        let recipient = canonical_address(recipient, "claim recipient")?;
        let entry = self
            .entries
            .get_mut(&key.encoded())
            .ok_or_else(|| CoreError::InvalidOrder("reward entitlement not found".into()))?;
        if entry.cumulative_accrued == 0 {
            return Err(CoreError::ZeroAmount);
        }
        if entry
            .claim_account
            .as_ref()
            .is_some_and(|bound| bound != &account)
        {
            return Err(CoreError::InvalidOrder(
                "reward claim account is already bound".into(),
            ));
        }
        entry.claim_account = Some(account.clone());
        let context_hash = claim_context_hash(
            owner,
            chain,
            &account,
            &recipient,
            &key.reward_token,
            entry.cumulative_accrued,
            deadline_seconds,
            idempotency_key,
        );
        Ok(RewardClaimIntent {
            protocol_version: "layrs.reward-claim.v1".into(),
            chain: chain.into(),
            account,
            recipient,
            reward_token: key.reward_token,
            cumulative_amount_atomic: entry.cumulative_accrued.to_string(),
            deadline_seconds,
            context_hash,
        })
    }
}

fn checked_add(left: u128, right: u128, message: &str) -> CoreResult<u128> {
    left.checked_add(right)
        .ok_or_else(|| CoreError::InvalidOrder(message.into()))
}

fn is_zero_u128(value: &u128) -> bool {
    *value == 0
}

fn reward_key(owner: &str, chain: &str, reward_token: &str) -> CoreResult<RewardKey> {
    if !valid_owner_id(owner) || !matches!(chain, "base" | "horizen") {
        return Err(CoreError::InvalidOrder("invalid reward rail".into()));
    }
    Ok(RewardKey {
        owner: owner.into(),
        chain: chain.into(),
        reward_token: canonical_address(reward_token, "reward token")?,
    })
}

fn valid_owner_id(value: &str) -> bool {
    value
        .strip_prefix("usr_")
        .is_some_and(|rest| rest.len() == 64 && rest.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn canonical_address(value: &str, label: &str) -> CoreResult<String> {
    let address = Address::from_str(value)
        .map_err(|_| CoreError::InvalidOrder(format!("invalid {label}")))?;
    if address == Address::zero() {
        return Err(CoreError::InvalidOrder(format!("invalid {label}")));
    }
    Ok(format!("{address:#x}"))
}

#[allow(clippy::too_many_arguments)]
fn claim_context_hash(
    owner: &str,
    chain: &str,
    account: &str,
    recipient: &str,
    reward_token: &str,
    cumulative_amount: u128,
    deadline_seconds: u64,
    idempotency_key: &str,
) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(b"layrs.reward-claim-context.v1\0");
    for value in [
        owner.as_bytes(),
        chain.as_bytes(),
        account.as_bytes(),
        recipient.as_bytes(),
        reward_token.as_bytes(),
        idempotency_key.as_bytes(),
    ] {
        hash.update(&(value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(&cumulative_amount.to_be_bytes());
    hash.update(&deadline_seconds.to_be_bytes());
    let mut output = [0u8; 32];
    hash.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0x0000000000000000000000000000000000000011";
    const ACCOUNT: &str = "0x0000000000000000000000000000000000000022";
    const RECIPIENT: &str = "0x0000000000000000000000000000000000000033";
    const USER_ONE: &str = "usr_1111111111111111111111111111111111111111111111111111111111111111";
    const USER_TWO: &str = "usr_2222222222222222222222222222222222222222222222222222222222222222";
    const USER_MISSING: &str =
        "usr_3333333333333333333333333333333333333333333333333333333333333333";

    #[test]
    fn cumulative_entitlement_binds_one_claim_account() {
        let mut book = PrivateRewardBook::default();
        book.accrue(USER_ONE, "base", TOKEN, 100).unwrap();
        book.accrue(USER_ONE, "base", TOKEN, 25).unwrap();
        let intent = book
            .authorize(
                USER_ONE,
                "base",
                ACCOUNT,
                RECIPIENT,
                TOKEN,
                1_800_000_000,
                "claim-0001",
            )
            .unwrap();
        assert_eq!(intent.cumulative_amount_atomic, "125");
        assert_eq!(
            book.entitlements(USER_ONE)[0].claim_account.as_deref(),
            Some(ACCOUNT)
        );

        let other = "0x0000000000000000000000000000000000000044";
        assert!(matches!(
            book.authorize(
                USER_ONE,
                "base",
                other,
                RECIPIENT,
                TOKEN,
                1_800_000_001,
                "claim-0002",
            ),
            Err(CoreError::InvalidOrder(_))
        ));
    }

    #[test]
    fn users_and_reward_tokens_remain_isolated() {
        let mut book = PrivateRewardBook::default();
        book.accrue(USER_ONE, "base", TOKEN, 10).unwrap();
        book.accrue(
            USER_TWO,
            "horizen",
            "0x0000000000000000000000000000000000000055",
            20,
        )
        .unwrap();
        assert_eq!(book.entitlements(USER_ONE).len(), 1);
        assert_eq!(book.entitlements(USER_TWO).len(), 1);
        assert_eq!(book.entitlements(USER_MISSING).len(), 0);
    }

    #[test]
    fn fill_economics_credit_only_the_maker_and_preserve_private_fee_history() {
        let mut book = PrivateRewardBook::default();
        book.record_fill(
            USER_ONE,
            Some(USER_TWO),
            "base",
            TOKEN,
            2_000_000,
            35_000,
            7_000,
            1_786_700_700_000,
        )
        .unwrap();
        let taker = &book.entitlements(USER_ONE)[0];
        assert_eq!(taker.cumulative_amount_atomic, "0");
        assert_eq!(taker.cumulative_taker_fees_atomic, "35000");
        assert_eq!(taker.cumulative_taker_volume_micros, "2000000");
        let maker = &book.entitlements(USER_TWO)[0];
        assert_eq!(maker.cumulative_amount_atomic, "7000");
        assert_eq!(maker.cumulative_maker_rebate_atomic, "7000");
        assert_eq!(maker.cumulative_maker_volume_micros, "2000000");
        assert_eq!(book.daily_attributions.len(), 2);
    }

    #[test]
    fn empty_daily_attribution_preserves_the_historical_serialized_shape() {
        let book = PrivateRewardBook::default();
        assert_eq!(serde_json::to_string(&book).unwrap(), r#"{"entries":{}}"#);
    }

    #[test]
    fn fill_economics_reject_invalid_or_unfunded_rebates() {
        let mut book = PrivateRewardBook::default();
        assert!(matches!(
            book.record_fill(USER_ONE, None, "base", TOKEN, 1, 10, 1, 1),
            Err(CoreError::InvalidOrder(_))
        ));
        assert!(matches!(
            book.record_fill(USER_ONE, Some(USER_TWO), "base", TOKEN, 1, 10, 11, 1),
            Err(CoreError::InvalidOrder(_))
        ));
    }
}
