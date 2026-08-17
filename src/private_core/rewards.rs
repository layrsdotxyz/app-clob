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
    /// Enclave-private, immutable fee-policy evidence for every fill. The map
    /// key is the deterministic fill UUID, so a retry under a different
    /// operator idempotency key cannot accrue a fee or rebate twice.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fill_attributions: BTreeMap<String, FillFeeAttribution>,
    /// Enclave-private reward-program accrual evidence. The evidence hash is
    /// derived from program, beneficiary, source and amount by the scheduler;
    /// it is the replay boundary independent of transport idempotency.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    program_accruals: BTreeMap<String, ProgramRewardAccrual>,
    /// Balanced reward expense/payable totals by custody rail and program
    /// class. These never leave the encrypted state or public entitlement API.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    reward_postings: BTreeMap<String, BalancedRewardPosting>,
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
struct FillFeeAttribution {
    taker_owner: String,
    maker_owner: Option<String>,
    chain: String,
    reward_token: String,
    fee_policy_version: String,
    fee_profile_id: String,
    match_type: String,
    #[serde(with = "super::decimal_u128")]
    quantity_micros: u128,
    #[serde(with = "super::decimal_u128")]
    taker_fee_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    maker_rebate_atomic: u128,
    occurred_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProgramRewardAccrual {
    owner: String,
    chain: String,
    reward_token: String,
    program_id: String,
    program_type: String,
    policy_id: String,
    policy_version: u32,
    fee_policy_version: String,
    source_id_hash: String,
    #[serde(with = "super::decimal_u128")]
    amount_atomic: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct BalancedRewardPosting {
    #[serde(with = "super::decimal_u128")]
    expense_debit_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    payable_credit_atomic: u128,
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
        fill_id: &str,
        taker_owner: &str,
        maker_owner: Option<&str>,
        chain: &str,
        reward_token: &str,
        fee_policy_version: &str,
        fee_profile_id: &str,
        match_type: &str,
        quantity_micros: u128,
        taker_fee_atomic: u128,
        maker_rebate_atomic: u128,
        occurred_at_millis: i64,
    ) -> CoreResult<()> {
        if !valid_uuid(fill_id)
            || !valid_policy_name(fee_policy_version)
            || !valid_policy_name(fee_profile_id)
            || !matches!(match_type, "NORMAL" | "MINT" | "MERGE")
            || quantity_micros == 0
            || occurred_at_millis < 0
        {
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
        let reward_token = canonical_address(reward_token, "reward token")?;
        let attribution = FillFeeAttribution {
            taker_owner: taker_owner.into(),
            maker_owner: maker_owner.map(str::to_owned),
            chain: chain.into(),
            reward_token: reward_token.clone(),
            fee_policy_version: fee_policy_version.into(),
            fee_profile_id: fee_profile_id.into(),
            match_type: match_type.into(),
            quantity_micros,
            taker_fee_atomic,
            maker_rebate_atomic,
            occurred_at_millis,
        };
        if let Some(existing) = self.fill_attributions.get(fill_id) {
            return if existing == &attribution {
                Ok(())
            } else {
                Err(CoreError::InvalidOrder(
                    "fill fee attribution conflicts with immutable evidence".into(),
                ))
            };
        }
        // Validate every owner/rail before mutating any aggregate.
        let taker_key = reward_key(taker_owner, chain, &reward_token)?;
        let maker_key = maker_owner
            .map(|owner| reward_key(owner, chain, &reward_token))
            .transpose()?;
        let mut next = self.clone();
        let day = occurred_at_millis / 86_400_000;
        let taker_entry = next.entries.entry(taker_key.encoded()).or_default();
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
        let taker_daily = next
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

        if let Some(maker_key) = maker_key {
            let maker_entry = next.entries.entry(maker_key.encoded()).or_default();
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
            let maker_daily = next
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
            next.post_reward("MAKER_REBATE", chain, &reward_token, maker_rebate_atomic)?;
        }
        next.fill_attributions.insert(fill_id.into(), attribution);
        *self = next;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accrue(
        &mut self,
        owner: &str,
        chain: &str,
        reward_token: &str,
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        source_id_hash: [u8; 32],
        program_id: &str,
        program_type: &str,
        policy_id: &str,
        policy_version: u32,
        fee_policy_version: &str,
    ) -> CoreResult<()> {
        if amount_atomic == 0 {
            return Err(CoreError::ZeroAmount);
        }
        if evidence_hash == [0u8; 32]
            || source_id_hash == [0u8; 32]
            || !valid_program_id(program_id)
            || !matches!(
                program_type,
                "MAKER_REBATE" | "TRADER_REWARD" | "REFERRAL" | "RETROSPECTIVE"
            )
            || !valid_program_id(policy_id)
            || policy_version == 0
            || !valid_policy_name(fee_policy_version)
        {
            return Err(CoreError::InvalidOrder(
                "invalid private reward evidence".into(),
            ));
        }
        let key = reward_key(owner, chain, reward_token)?;
        let evidence_key = hex::encode(evidence_hash);
        let accrual = ProgramRewardAccrual {
            owner: owner.into(),
            chain: chain.into(),
            reward_token: key.reward_token.clone(),
            program_id: program_id.into(),
            program_type: program_type.into(),
            policy_id: policy_id.into(),
            policy_version,
            fee_policy_version: fee_policy_version.into(),
            source_id_hash: hex::encode(source_id_hash),
            amount_atomic,
        };
        if let Some(existing) = self.program_accruals.get(&evidence_key) {
            return if existing == &accrual {
                Ok(())
            } else {
                Err(CoreError::InvalidOrder(
                    "reward evidence conflicts with immutable accrual".into(),
                ))
            };
        }
        let mut next = self.clone();
        let entry = next.entries.entry(key.encoded()).or_default();
        entry.cumulative_accrued = entry
            .cumulative_accrued
            .checked_add(amount_atomic)
            .ok_or_else(|| CoreError::InvalidOrder("reward accrual overflow".into()))?;
        next.post_reward(program_type, chain, &key.reward_token, amount_atomic)?;
        next.program_accruals.insert(evidence_key, accrual);
        *self = next;
        Ok(())
    }

    fn post_reward(
        &mut self,
        program_type: &str,
        chain: &str,
        reward_token: &str,
        amount_atomic: u128,
    ) -> CoreResult<()> {
        if amount_atomic == 0 {
            return Ok(());
        }
        let posting_key = format!("{program_type}:{chain}:{reward_token}");
        let posting = self.reward_postings.entry(posting_key).or_default();
        posting.expense_debit_atomic = checked_add(
            posting.expense_debit_atomic,
            amount_atomic,
            "reward expense overflow",
        )?;
        posting.payable_credit_atomic = checked_add(
            posting.payable_credit_atomic,
            amount_atomic,
            "reward payable overflow",
        )?;
        if posting.expense_debit_atomic != posting.payable_credit_atomic {
            return Err(CoreError::UnbalancedTransaction);
        }
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

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|parsed| parsed.to_string() == value.to_ascii_lowercase())
}

fn valid_program_id(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn valid_policy_name(value: &str) -> bool {
    (2..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
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

    fn accrue(book: &mut PrivateRewardBook, owner: &str, amount: u128, evidence: u8) {
        book.accrue(
            owner,
            "base",
            TOKEN,
            amount,
            [evidence; 32],
            [evidence.wrapping_add(1); 32],
            "trader-reward-v1",
            "TRADER_REWARD",
            "layrs-fee-v2",
            1,
            "LAYRS_FEE_V2",
        )
        .unwrap();
    }

    #[test]
    fn cumulative_entitlement_binds_one_claim_account() {
        let mut book = PrivateRewardBook::default();
        accrue(&mut book, USER_ONE, 100, 1);
        accrue(&mut book, USER_ONE, 25, 2);
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
        accrue(&mut book, USER_ONE, 10, 3);
        book.accrue(
            USER_TWO,
            "horizen",
            "0x0000000000000000000000000000000000000055",
            20,
            [4; 32],
            [5; 32],
            "referral-v1",
            "REFERRAL",
            "layrs-fee-v2",
            1,
            "LAYRS_FEE_V2",
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
            "00000000-0000-4000-8000-000000000001",
            USER_ONE,
            Some(USER_TWO),
            "base",
            TOKEN,
            "LAYRS_FEE_V2",
            "LAYRS_CRYPTO_V2",
            "MINT",
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
        let posting = book.reward_postings.values().next().unwrap();
        assert_eq!(posting.expense_debit_atomic, 7_000);
        assert_eq!(posting.payable_credit_atomic, 7_000);
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
            book.record_fill(
                "00000000-0000-4000-8000-000000000001",
                USER_ONE,
                None,
                "base",
                TOKEN,
                "LAYRS_FEE_V2",
                "LAYRS_CRYPTO_V2",
                "NORMAL",
                1,
                10,
                1,
                1,
            ),
            Err(CoreError::InvalidOrder(_))
        ));
        assert!(matches!(
            book.record_fill(
                "00000000-0000-4000-8000-000000000001",
                USER_ONE,
                Some(USER_TWO),
                "base",
                TOKEN,
                "LAYRS_FEE_V2",
                "LAYRS_CRYPTO_V2",
                "NORMAL",
                1,
                10,
                11,
                1,
            ),
            Err(CoreError::InvalidOrder(_))
        ));
    }

    #[test]
    fn fill_replay_is_exactly_once_and_policy_conflicts_fail_closed() {
        let mut book = PrivateRewardBook::default();
        let fill = "00000000-0000-4000-8000-000000000001";
        let record = |book: &mut PrivateRewardBook, profile: &str| {
            book.record_fill(
                fill,
                USER_ONE,
                Some(USER_TWO),
                "base",
                TOKEN,
                "LAYRS_FEE_V2",
                profile,
                "MERGE",
                2_000_000,
                35_000,
                7_000,
                1_786_700_700_000,
            )
        };
        record(&mut book, "LAYRS_CRYPTO_V2").unwrap();
        let snapshot = book.clone();
        record(&mut book, "LAYRS_CRYPTO_V2").unwrap();
        assert_eq!(book, snapshot);
        assert!(matches!(
            record(&mut book, "LAYRS_SPORTS_V2"),
            Err(CoreError::InvalidOrder(message))
                if message.contains("immutable evidence")
        ));
        assert_eq!(book, snapshot);
    }

    #[test]
    fn layrs_fee_v2_postings_cover_normal_mint_and_merge_without_cross_asset_drift() {
        let mut book = PrivateRewardBook::default();
        for (suffix, match_type) in [(1, "NORMAL"), (2, "MINT"), (3, "MERGE")] {
            book.record_fill(
                &format!("00000000-0000-4000-8000-{suffix:012}"),
                USER_ONE,
                Some(USER_TWO),
                "base",
                TOKEN,
                "LAYRS_FEE_V2",
                "LAYRS_CRYPTO_V2",
                match_type,
                1_000_000,
                10,
                2,
                1_786_700_700_000 + suffix,
            )
            .unwrap();
        }
        assert_eq!(book.fill_attributions.len(), 3);
        assert!(book
            .fill_attributions
            .values()
            .all(|fill| fill.fee_policy_version == "LAYRS_FEE_V2"));
        let posting = book.reward_postings.values().next().unwrap();
        assert_eq!(posting.expense_debit_atomic, 6);
        assert_eq!(posting.payable_credit_atomic, 6);
        assert_eq!(book.reward_postings.len(), 1);
    }

    #[test]
    fn reward_evidence_replay_is_exactly_once_across_operator_keys() {
        let mut book = PrivateRewardBook::default();
        accrue(&mut book, USER_ONE, 100, 9);
        let snapshot = book.clone();
        accrue(&mut book, USER_ONE, 100, 9);
        assert_eq!(book, snapshot);
        assert!(matches!(
            book.accrue(
                USER_ONE, "base", TOKEN, 101, [9; 32], [10; 32], "trader-reward-v1",
                "TRADER_REWARD", "layrs-fee-v2", 1, "LAYRS_FEE_V2",
            ),
            Err(CoreError::InvalidOrder(message)) if message.contains("immutable accrual")
        ));
        assert_eq!(book, snapshot);
    }
}
