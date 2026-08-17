use std::collections::BTreeMap;

use clob_service::private_core::{
    command_request_hash, signing_payload, AccountBucket, AccountKey, BookOrder, CommandResult,
    ExternalFlowDirection, FeeProfileId, JournalKey, MarketConfig, MarketExecution, MatchType,
    OrderAction, Outcome, PrivateTradingCore, ReceiptSigner, SessionRequest, SignedSessionRequest,
    TimeInForce, UserCommand, UserCommandAction,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const INPUT: &str = include_str!("vectors/e10_replay_input_v1.json");
const EXPECTED: &str = include_str!("vectors/e10_replay_expected_v1.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplayInput {
    version: String,
    journal_key_byte: u8,
    receipt_seed_byte: u8,
    oracle_key_byte: u8,
    market: VectorMarket,
    users: Vec<VectorUser>,
    commands: Vec<VectorCommand>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorMarket {
    market_id: String,
    fee_profile: String,
    settlement_asset: String,
    settlement_decimals: u8,
    opens_at_millis: i64,
    closes_at_millis: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorUser {
    label: String,
    signing_key_byte: u8,
    identity_commitment_byte: u8,
    session_id: String,
    deposit_atomic: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorCommand {
    command_id: String,
    user: String,
    sequence: u64,
    now_millis: i64,
    order_id: Uuid,
    outcome: String,
    action: String,
    price_micros: u64,
    quantity_micros: String,
    time_in_force: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplayOutput {
    version: String,
    setup_state_root: String,
    commands: Vec<CommandOutput>,
    final_state_root: String,
    final_balances: FinalBalances,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandOutput {
    command_id: String,
    state_root: String,
    fee_revenue_atomic: String,
    fills: Vec<FillOutput>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FillOutput {
    fill_id: Uuid,
    maker_order_id: Uuid,
    taker_order_id: Uuid,
    outcome: String,
    match_type: String,
    price_micros: u64,
    taker_price_micros: u64,
    quantity_micros: String,
    sequence: u64,
    fee_atomic: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FinalBalances {
    up_available_atomic: String,
    down_available_atomic: String,
    fee_revenue_atomic: String,
    market_collateral_atomic: String,
    up_claim_micros: String,
    down_claim_micros: String,
}

struct UserRuntime {
    signing_key: SigningKey,
    private_user_id: String,
    session_id: String,
}

#[test]
fn published_replay_vector_is_byte_identical_for_fills_ids_fees_and_states() {
    let input: ReplayInput = serde_json::from_str(INPUT).expect("valid replay input fixture");
    let first = run_vector(&input);
    let second = run_vector(&input);

    let first_bytes = serde_json::to_vec(&first).expect("serialize first replay output");
    let second_bytes = serde_json::to_vec(&second).expect("serialize second replay output");
    assert_eq!(first_bytes, second_bytes, "semantic replay output drifted");

    if std::env::var_os("LAYRS_PRINT_REPLAY_VECTOR").is_some() {
        println!(
            "{}",
            serde_json::to_string_pretty(&first).expect("print replay output")
        );
    }

    let expected: ReplayOutput =
        serde_json::from_str(EXPECTED).expect("valid expected replay fixture");
    let expected_bytes = serde_json::to_vec(&expected).expect("serialize expected replay output");
    assert_eq!(
        first_bytes, expected_bytes,
        "published replay vector drifted"
    );
}

fn run_vector(input: &ReplayInput) -> ReplayOutput {
    assert_eq!(input.version, "layrs.deterministic-replay.v1");
    assert_eq!(input.market.fee_profile, "LAYRS_CRYPTO_V2");

    let journal_key = [input.journal_key_byte; 32];
    let oracle = SigningKey::from_bytes(&[input.oracle_key_byte; 32]);
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([input.receipt_seed_byte; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .expect("construct deterministic core");
    core.register_market(
        "sys:vector:market".into(),
        MarketConfig {
            market_id: input.market.market_id.clone(),
            settlement_asset: input.market.settlement_asset.clone(),
            settlement_decimals: input.market.settlement_decimals,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: input.market.opens_at_millis,
            closes_at_millis: input.market.closes_at_millis,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 100,
            oracle_feed_id: 245,
            fee_profile_id: FeeProfileId::LayrsCryptoV2,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .expect("register vector market");

    let mut users = BTreeMap::new();
    for (index, user) in input.users.iter().enumerate() {
        let signing_key = SigningKey::from_bytes(&[user.signing_key_byte; 32]);
        let commitment = [user.identity_commitment_byte; 32];
        core.register_session(
            format!("sys:vector:session:{}", user.label),
            user.session_id.clone(),
            commitment,
            signing_key.verifying_key().to_bytes(),
            3_000,
            850,
        )
        .expect("register vector session");
        core.apply_user_external_flow(
            format!("sys:vector:deposit:{}", user.label),
            commitment,
            input.market.settlement_asset.clone(),
            AccountBucket::UserAvailable,
            parse_u128(&user.deposit_atomic),
            ExternalFlowDirection::Inflow,
            [(37 + index) as u8; 32],
            875,
        )
        .expect("apply vector deposit");
        users.insert(
            user.label.clone(),
            UserRuntime {
                signing_key,
                private_user_id: derived_private_user(journal_key, commitment),
                session_id: user.session_id.clone(),
            },
        );
    }

    let setup_state_root = hex::encode(core.state_root());
    let fee_account = AccountKey::new(
        "layrs",
        AccountBucket::FeeRevenue,
        &input.market.settlement_asset,
    );
    let mut command_outputs = Vec::new();
    for command in &input.commands {
        let user = users.get(&command.user).expect("known vector user");
        let action = UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                command.order_id,
                "ignored",
                &input.market.market_id,
                parse_outcome(&command.outcome),
                parse_action(&command.action),
                command.price_micros,
                parse_u128(&command.quantity_micros),
                parse_time_in_force(&command.time_in_force),
                None,
            ),
        };
        let idempotency_key = format!("idem:{}", command.command_id);
        let request_hash = command_request_hash(&command.command_id, &idempotency_key, &action)
            .expect("hash vector command");
        let request = SessionRequest {
            session_id: user.session_id.clone(),
            sequence: command.sequence,
            issued_at_millis: command.now_millis,
            expires_at_millis: 2_900,
            request_hash,
        };
        let signature = user
            .signing_key
            .sign(&signing_payload(&request))
            .to_bytes()
            .to_vec();
        let response = core
            .execute(
                UserCommand {
                    command_id: command.command_id.clone(),
                    idempotency_key,
                    session: SignedSessionRequest { request, signature },
                    action,
                },
                command.now_millis,
            )
            .expect("execute vector command");
        let state_root = hex::encode(core.state_root());
        assert_eq!(state_root, hex::encode(response.receipt.state_root));
        let fills = match &response.result {
            CommandResult::Order { result } => result
                .fills
                .iter()
                .enumerate()
                .map(|(index, fill)| FillOutput {
                    fill_id: fill.fill_id,
                    maker_order_id: fill.maker_order_id,
                    taker_order_id: fill.taker_order_id,
                    outcome: format!("{:?}", fill.outcome).to_uppercase(),
                    match_type: match fill.match_type {
                        MatchType::Normal => "NORMAL",
                        MatchType::Mint => "MINT",
                        MatchType::Merge => "MERGE",
                    }
                    .into(),
                    price_micros: fill.price_micros,
                    taker_price_micros: fill.taker_price_micros(),
                    quantity_micros: fill.quantity_micros.to_string(),
                    sequence: fill.sequence,
                    fee_atomic: response.audit_fills[index].statement.fee_atomic.clone(),
                })
                .collect(),
            _ => panic!("vector command must return an order result"),
        };
        command_outputs.push(CommandOutput {
            command_id: command.command_id.clone(),
            state_root,
            fee_revenue_atomic: core.balance(&fee_account).to_string(),
            fills,
        });
    }

    let up = users.get("up").expect("up vector user");
    let down = users.get("down").expect("down vector user");
    let up_available = AccountKey::new(
        &up.private_user_id,
        AccountBucket::UserAvailable,
        &input.market.settlement_asset,
    );
    let down_available = AccountKey::new(
        &down.private_user_id,
        AccountBucket::UserAvailable,
        &input.market.settlement_asset,
    );
    ReplayOutput {
        version: input.version.clone(),
        setup_state_root,
        commands: command_outputs,
        final_state_root: hex::encode(core.state_root()),
        final_balances: FinalBalances {
            up_available_atomic: core.balance(&up_available).to_string(),
            down_available_atomic: core.balance(&down_available).to_string(),
            fee_revenue_atomic: core.balance(&fee_account).to_string(),
            market_collateral_atomic: core.balance(&market_collateral(input)).to_string(),
            up_claim_micros: core
                .balance(&claim(input, &up.private_user_id, Outcome::Up))
                .to_string(),
            down_claim_micros: core
                .balance(&claim(input, &down.private_user_id, Outcome::Down))
                .to_string(),
        },
    }
}

fn market_collateral(input: &ReplayInput) -> AccountKey {
    let mut account = AccountKey::new(
        "layrs",
        AccountBucket::MarketCollateral,
        &input.market.settlement_asset,
    );
    account.market_id = Some(input.market.market_id.clone());
    account
}

fn claim(input: &ReplayInput, owner: &str, outcome: Outcome) -> AccountKey {
    let name = match outcome {
        Outcome::Up => "UP",
        Outcome::Down => "DOWN",
    };
    AccountKey::position(
        owner,
        format!("CLAIM:{}:{name}", input.market.market_id),
        &input.market.market_id,
        name,
    )
}

fn parse_u128(value: &str) -> u128 {
    value.parse().expect("valid vector u128")
}

fn parse_outcome(value: &str) -> Outcome {
    match value {
        "UP" => Outcome::Up,
        "DOWN" => Outcome::Down,
        _ => panic!("unsupported vector outcome: {value}"),
    }
}

fn parse_action(value: &str) -> OrderAction {
    match value {
        "BUY" => OrderAction::Buy,
        "SELL" => OrderAction::Sell,
        _ => panic!("unsupported vector action: {value}"),
    }
}

fn parse_time_in_force(value: &str) -> TimeInForce {
    match value {
        "GTC" => TimeInForce::Gtc,
        "FOK" => TimeInForce::Fok,
        _ => panic!("unsupported vector time in force: {value}"),
    }
}

fn derived_private_user(journal_key: [u8; 32], commitment: [u8; 32]) -> String {
    use sha2::{Digest, Sha256};

    let mut key_hash = Sha256::new();
    key_hash.update(b"layrs.enclave-key-derivation.v1\0");
    key_hash.update(journal_key);
    key_hash.update((15u32).to_be_bytes());
    key_hash.update(b"private-user-id");
    let identity_key = key_hash.finalize();
    let mut user_hash = Sha256::new();
    user_hash.update(b"layrs.private-user-id.v1\0");
    user_hash.update(identity_key);
    user_hash.update(commitment);
    format!("usr_{}", hex::encode(user_hash.finalize()))
}
