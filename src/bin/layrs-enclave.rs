use std::{collections::BTreeSet, io, sync::Arc};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use clob_service::private_core::{
    AccountKey, CoreResponse, EncryptedSnapshot, ExternalFlowDirection, JournalKey, MarketConfig,
    PrivateTradingCore, ReceiptSigner, SignedResolution, SystemResponse, UserCommand,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const PORT: u32 = 5_003;
const MAX_FRAME_BYTES: usize = 1_048_576;
const MAX_REPLAY_ENTRIES: usize = 100_000;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum WireRequest {
    Attestation {
        nonce: Vec<u8>,
    },
    Encrypted {
        client_public_key: [u8; 32],
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum WireResponse {
    Attestation {
        document: Vec<u8>,
        transport_public_key: [u8; 32],
        receipt_public_key: [u8; 32],
    },
    Encrypted {
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
    Error {
        code: &'static str,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperatorEnvelope {
    nonce: [u8; 32],
    command: OperatorCommand,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum OperatorCommand {
    Provision {
        journal_key: [u8; 32],
        oracle_public_key: [u8; 32],
        snapshot: Option<EncryptedSnapshot>,
        minimum_anchored_sequence: u64,
    },
    ExportSnapshot,
    RegisterMarket {
        idempotency_key: String,
        market: MarketConfig,
        now_millis: i64,
    },
    RegisterSession {
        idempotency_key: String,
        session_id: String,
        identity_commitment: [u8; 32],
        public_key: [u8; 32],
        expires_at_millis: i64,
        now_millis: i64,
    },
    ExternalFlow {
        idempotency_key: String,
        account: AccountKey,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount: u128,
        direction: ExternalFlowDirection,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    CreditDeposit {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    FinalizeWithdrawal {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    ReleaseWithdrawal {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    ResolveMarket {
        idempotency_key: String,
        signed: SignedResolution,
        now_millis: i64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum PlainRequest {
    Operator {
        envelope: OperatorEnvelope,
    },
    User {
        command: UserCommand,
        now_millis: i64,
    },
    AggregateDepth {
        market_id: String,
        outcome: clob_service::private_core::Outcome,
        now_millis: i64,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        minimum_level_quantity_micros: u128,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum PlainResponse {
    Provisioned,
    System {
        response: SystemResponse,
    },
    User {
        response: CoreResponse,
    },
    Depth {
        bids: Vec<(u64, u128)>,
        asks: Vec<(u64, u128)>,
    },
    Snapshot {
        snapshot: EncryptedSnapshot,
    },
    Error {
        code: String,
    },
}

struct EnclaveState {
    nsm_fd: i32,
    transport_secret: StaticSecret,
    transport_public_key: [u8; 32],
    receipt_signer: Option<ReceiptSigner>,
    receipt_public_key: [u8; 32],
    operator_public_key: VerifyingKey,
    operator_nonces: BTreeSet<[u8; 32]>,
    transport_nonces: BTreeSet<[u8; 44]>,
    core: Option<PrivateTradingCore>,
}

impl Drop for EnclaveState {
    fn drop(&mut self) {
        nsm_exit(self.nsm_fd);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operator_public_key = compile_time_operator_key()?;
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        return Err("Nitro Secure Module is unavailable".into());
    }
    let measurement_sha384 = read_pcr0(nsm_fd)?;
    let transport_secret = StaticSecret::random();
    let transport_public_key = PublicKey::from(&transport_secret).to_bytes();
    let receipt_signer = ReceiptSigner::generate(measurement_sha384);
    let receipt_public_key = receipt_signer.verifying_key();
    let state = Arc::new(Mutex::new(EnclaveState {
        nsm_fd,
        transport_secret,
        transport_public_key,
        receipt_signer: Some(receipt_signer),
        receipt_public_key,
        operator_public_key,
        operator_nonces: BTreeSet::new(),
        transport_nonces: BTreeSet::new(),
        core: None,
    }));

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, PORT))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve_connection(stream, state).await;
        });
    }
}

async fn serve_connection(
    mut stream: VsockStream,
    state: Arc<Mutex<EnclaveState>>,
) -> io::Result<()> {
    let frame = read_frame(&mut stream).await?;
    let request: WireRequest = serde_json::from_slice(&frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let response = match request {
        WireRequest::Attestation { nonce } => create_attestation(&state, nonce).await,
        WireRequest::Encrypted {
            client_public_key,
            nonce,
            ciphertext,
        } => handle_encrypted(&state, client_public_key, nonce, ciphertext).await,
    };
    let encoded = serde_json::to_vec(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_frame(&mut stream, &encoded).await
}

async fn create_attestation(state: &Arc<Mutex<EnclaveState>>, nonce: Vec<u8>) -> WireResponse {
    if nonce.len() < 16 || nonce.len() > 512 {
        return WireResponse::Error {
            code: "INVALID_NONCE",
        };
    }
    let state = state.lock().await;
    let mut binding = Vec::with_capacity(88);
    binding.extend_from_slice(b"layrs.enclave-key-binding.v1\0");
    binding.extend_from_slice(&state.transport_public_key);
    binding.extend_from_slice(&state.receipt_public_key);
    match nsm_process_request(
        state.nsm_fd,
        NsmRequest::Attestation {
            user_data: Some(binding.into()),
            nonce: Some(nonce.into()),
            public_key: Some(state.transport_public_key.to_vec().into()),
        },
    ) {
        NsmResponse::Attestation { document } => WireResponse::Attestation {
            document,
            transport_public_key: state.transport_public_key,
            receipt_public_key: state.receipt_public_key,
        },
        _ => WireResponse::Error {
            code: "ATTESTATION_FAILED",
        },
    }
}

async fn handle_encrypted(
    state: &Arc<Mutex<EnclaveState>>,
    client_public_key: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
) -> WireResponse {
    let mut state = state.lock().await;
    let mut replay_key = [0u8; 44];
    replay_key[..32].copy_from_slice(&client_public_key);
    replay_key[32..].copy_from_slice(&nonce);
    if state.transport_nonces.len() >= MAX_REPLAY_ENTRIES
        || state.transport_nonces.contains(&replay_key)
    {
        return WireResponse::Error {
            code: "REPLAY_REJECTED",
        };
    }
    let key = transport_key(&state.transport_secret, client_public_key);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key size is fixed");
    let mut plaintext = match cipher.decrypt(
        Nonce::from_slice(&nonce),
        aes_gcm::aead::Payload {
            msg: &ciphertext,
            aad: request_aad(&client_public_key, &state.transport_public_key).as_slice(),
        },
    ) {
        Ok(value) => value,
        Err(_) => {
            return WireResponse::Error {
                code: "DECRYPTION_FAILED",
            }
        }
    };
    let request: PlainRequest = match serde_json::from_slice(&plaintext) {
        Ok(value) => value,
        Err(_) => {
            return WireResponse::Error {
                code: "INVALID_REQUEST",
            }
        }
    };
    plaintext.zeroize();
    state.transport_nonces.insert(replay_key);
    let response = dispatch(&mut state, request);
    let encoded = match serde_json::to_vec(&response) {
        Ok(value) => value,
        Err(_) => {
            return WireResponse::Error {
                code: "ENCODING_FAILED",
            }
        }
    };
    let mut response_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut response_nonce);
    match cipher.encrypt(
        Nonce::from_slice(&response_nonce),
        aes_gcm::aead::Payload {
            msg: &encoded,
            aad: response_aad(&client_public_key, &state.transport_public_key).as_slice(),
        },
    ) {
        Ok(ciphertext) => WireResponse::Encrypted {
            nonce: response_nonce,
            ciphertext,
        },
        Err(_) => WireResponse::Error {
            code: "ENCRYPTION_FAILED",
        },
    }
}

fn dispatch(state: &mut EnclaveState, request: PlainRequest) -> PlainResponse {
    let result: Result<PlainResponse, String> = match request {
        PlainRequest::Operator { envelope } => dispatch_operator(state, envelope),
        PlainRequest::User {
            command,
            now_millis,
        } => state
            .core
            .as_mut()
            .ok_or_else(|| "NOT_PROVISIONED".into())
            .and_then(|core| {
                core.execute(command, now_millis)
                    .map(|response| PlainResponse::User { response })
                    .map_err(|error| error.to_string())
            }),
        PlainRequest::AggregateDepth {
            market_id,
            outcome,
            now_millis,
            minimum_level_quantity_micros,
        } => state
            .core
            .as_ref()
            .ok_or_else(|| "NOT_PROVISIONED".into())
            .map(|core| {
                let (bids, asks) = core.aggregate_depth(
                    &market_id,
                    outcome,
                    now_millis,
                    minimum_level_quantity_micros,
                );
                PlainResponse::Depth { bids, asks }
            }),
    };
    result.unwrap_or_else(|code| PlainResponse::Error { code })
}

fn dispatch_operator(
    state: &mut EnclaveState,
    envelope: OperatorEnvelope,
) -> Result<PlainResponse, String> {
    if state.operator_nonces.contains(&envelope.nonce)
        || state.operator_nonces.len() >= MAX_REPLAY_ENTRIES
    {
        return Err("OPERATOR_REPLAY_REJECTED".into());
    }
    let signature_bytes: [u8; 64] = envelope
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "INVALID_OPERATOR_SIGNATURE".to_string())?;
    state
        .operator_public_key
        .verify(
            &operator_payload(envelope.nonce, &envelope.command)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| "INVALID_OPERATOR_SIGNATURE".to_string())?;
    state.operator_nonces.insert(envelope.nonce);

    match envelope.command {
        OperatorCommand::Provision {
            journal_key,
            oracle_public_key,
            snapshot,
            minimum_anchored_sequence,
        } => {
            if state.core.is_some() {
                return Err("ALREADY_PROVISIONED".into());
            }
            let signer = state
                .receipt_signer
                .take()
                .ok_or_else(|| "ALREADY_PROVISIONED".to_string())?;
            let key = JournalKey::from_bytes(journal_key);
            state.core = Some(match snapshot {
                Some(snapshot) => PrivateTradingCore::restore_encrypted_snapshot(
                    key,
                    signer,
                    &snapshot,
                    minimum_anchored_sequence,
                )
                .map_err(|error| error.to_string())?,
                None => PrivateTradingCore::new_with_oracle(key, signer, oracle_public_key)
                    .map_err(|error| error.to_string())?,
            });
            Ok(PlainResponse::Provisioned)
        }
        command => {
            let core = state
                .core
                .as_mut()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            let response = match command {
                OperatorCommand::RegisterMarket {
                    idempotency_key,
                    market,
                    now_millis,
                } => core.register_market(idempotency_key, market, now_millis),
                OperatorCommand::RegisterSession {
                    idempotency_key,
                    session_id,
                    identity_commitment,
                    public_key,
                    expires_at_millis,
                    now_millis,
                } => core.register_session(
                    idempotency_key,
                    session_id,
                    identity_commitment,
                    public_key,
                    expires_at_millis,
                    now_millis,
                ),
                OperatorCommand::ExternalFlow {
                    idempotency_key,
                    account,
                    amount,
                    direction,
                    evidence_hash,
                    now_millis,
                } => core.apply_external_flow(
                    idempotency_key,
                    account,
                    amount,
                    direction,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::CreditDeposit {
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                } => core.apply_user_external_flow(
                    idempotency_key,
                    identity_commitment,
                    asset,
                    clob_service::private_core::AccountBucket::UserAvailable,
                    amount_atomic,
                    ExternalFlowDirection::Inflow,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::FinalizeWithdrawal {
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                } => core.apply_user_external_flow(
                    idempotency_key,
                    identity_commitment,
                    asset,
                    clob_service::private_core::AccountBucket::UserWithdrawalHold,
                    amount_atomic,
                    ExternalFlowDirection::Outflow,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::ReleaseWithdrawal {
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                } => core.release_user_withdrawal(
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::ResolveMarket {
                    idempotency_key,
                    signed,
                    now_millis,
                } => core.resolve_market(idempotency_key, signed, now_millis),
                OperatorCommand::ExportSnapshot => {
                    return core
                        .export_encrypted_snapshot()
                        .map(|snapshot| PlainResponse::Snapshot { snapshot })
                        .map_err(|error| error.to_string());
                }
                OperatorCommand::Provision { .. } => unreachable!(),
            }
            .map_err(|error| error.to_string())?;
            Ok(PlainResponse::System { response })
        }
    }
}

fn operator_payload(nonce: [u8; 32], command: &OperatorCommand) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(command).map_err(|_| "INVALID_OPERATOR_COMMAND".to_string())?;
    let mut payload = Vec::with_capacity(encoded.len() + 64);
    payload.extend_from_slice(b"layrs.enclave-operator.v1\0");
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn transport_key(secret: &StaticSecret, client_public_key: [u8; 32]) -> [u8; 32] {
    let shared = secret.diffie_hellman(&PublicKey::from(client_public_key));
    let mut hash = Sha256::new();
    hash.update(b"layrs.enclave-transport.v1\0");
    hash.update(shared.as_bytes());
    hash.finalize().into()
}

fn request_aad(client: &[u8; 32], enclave: &[u8; 32]) -> Vec<u8> {
    let mut aad = b"layrs.enclave-request.v1\0".to_vec();
    aad.extend_from_slice(client);
    aad.extend_from_slice(enclave);
    aad
}

fn response_aad(client: &[u8; 32], enclave: &[u8; 32]) -> Vec<u8> {
    let mut aad = b"layrs.enclave-response.v1\0".to_vec();
    aad.extend_from_slice(client);
    aad.extend_from_slice(enclave);
    aad
}

fn compile_time_operator_key() -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let encoded = option_env!("LAYRS_OPERATOR_PUBLIC_KEY_HEX")
        .ok_or("LAYRS_OPERATOR_PUBLIC_KEY_HEX must be set while building the EIF")?;
    let bytes = hex::decode(encoded)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "operator public key must be 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&key)?)
}

fn read_pcr0(nsm_fd: i32) -> Result<[u8; 48], Box<dyn std::error::Error>> {
    match nsm_process_request(nsm_fd, NsmRequest::DescribePCR { index: 0 }) {
        NsmResponse::DescribePCR { data, .. } => data
            .try_into()
            .map_err(|_| "PCR0 must be a SHA-384 measurement".into()),
        _ => Err("unable to read PCR0".into()),
    }
}

async fn read_frame(stream: &mut VsockStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut frame = vec![0u8; length];
    stream.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_frame(stream: &mut VsockStream, value: &[u8]) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    stream.write_u32(value.len() as u32).await?;
    stream.write_all(value).await?;
    stream.shutdown().await
}
