use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROOF_PROGRAM_VERSION: &str = "layrs.zk.settlement.v1";
pub const HORIZEN_CHAIN_ID: u64 = 26_514;
pub const ZEN_USD_PYTH_FEED_ID: u64 = 245;
pub const BOUNDARY_SAMPLE_COUNT: usize = 25;
pub const BOUNDARY_WINDOW_MICROS: i64 = 5_000_000;
pub const PUBLIC_JOURNAL_WORDS: usize = 15;
pub const PUBLIC_JOURNAL_BYTES: usize = PUBLIC_JOURNAL_WORDS * 32;

const OBSERVATION_DOMAIN: &[u8] = b"layrs.zk.boundary-observations.v1\0";
const SETTLEMENT_DOMAIN: &[u8] = b"layrs.zk.settlement-commitment.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionOutcome {
    Up,
    Down,
    Push,
}

impl ResolutionOutcome {
    fn discriminant(&self) -> u8 {
        match self {
            Self::Up => 1,
            Self::Down => 2,
            Self::Push => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct BoundaryWitness {
    pub window_start_micros: i64,
    pub window_end_micros: i64,
    pub minimum_publisher_count: u16,
    pub evidence_commitment: [u8; 32],
    pub observations_e8: [i64; BOUNDARY_SAMPLE_COUNT],
    pub observations_commitment: [u8; 32],
    pub expected_median_e8: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct SettlementProofInput {
    pub proof_program_version: String,
    pub market_id: String,
    pub destination_chain_id: u64,
    pub oracle_feed_id: u64,
    pub opening: BoundaryWitness,
    pub closing: BoundaryWitness,
    pub payout_root: [u8; 32],
    pub fee_root: [u8; 32],
    pub payout_coverage: bool,
    pub fee_coverage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementProofOutput {
    pub proof_program_version: String,
    pub proof_program_version_hash: [u8; 32],
    pub market_id: String,
    pub market_id_hash: [u8; 32],
    pub destination_chain_id: u64,
    pub oracle_feed_id: u64,
    pub opening_median_e8: i64,
    pub closing_median_e8: i64,
    pub outcome: ResolutionOutcome,
    pub opening_evidence_commitment: [u8; 32],
    pub closing_evidence_commitment: [u8; 32],
    pub opening_observations_commitment: [u8; 32],
    pub closing_observations_commitment: [u8; 32],
    pub payout_root: [u8; 32],
    pub fee_root: [u8; 32],
    pub payout_coverage: bool,
    pub fee_coverage: bool,
    pub settlement_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofInputError {
    WrongProgramVersion,
    InvalidMarketId,
    WrongDestinationChain,
    WrongOracleFeed,
    InvalidBoundaryWindow,
    InvalidPublisherPolicy,
    InvalidEvidenceCommitment,
    InvalidObservation,
    InvalidObservationCommitment,
    InvalidMedian,
    InvalidBoundaryOrder,
    UnsupportedPayoutCoverage,
    UnsupportedFeeCoverage,
}

pub fn observation_commitment(boundary: &BoundaryWitness) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OBSERVATION_DOMAIN);
    hasher.update(boundary.window_start_micros.to_be_bytes());
    hasher.update(boundary.window_end_micros.to_be_bytes());
    hasher.update(boundary.minimum_publisher_count.to_be_bytes());
    for price in boundary.observations_e8 {
        hasher.update(price.to_be_bytes());
    }
    hasher.finalize().into()
}

pub fn prove_resolution(
    input: SettlementProofInput,
) -> Result<SettlementProofOutput, ProofInputError> {
    if input.proof_program_version != PROOF_PROGRAM_VERSION {
        return Err(ProofInputError::WrongProgramVersion);
    }
    if input.market_id.is_empty()
        || input.market_id.len() > 160
        || !input
            .market_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._-/".contains(&byte))
    {
        return Err(ProofInputError::InvalidMarketId);
    }
    if input.destination_chain_id != HORIZEN_CHAIN_ID {
        return Err(ProofInputError::WrongDestinationChain);
    }
    if input.oracle_feed_id != ZEN_USD_PYTH_FEED_ID {
        return Err(ProofInputError::WrongOracleFeed);
    }
    if input.opening.window_end_micros >= input.closing.window_end_micros {
        return Err(ProofInputError::InvalidBoundaryOrder);
    }
    if input.payout_coverage || input.payout_root != [0u8; 32] {
        return Err(ProofInputError::UnsupportedPayoutCoverage);
    }
    if input.fee_coverage || input.fee_root != [0u8; 32] {
        return Err(ProofInputError::UnsupportedFeeCoverage);
    }

    let opening_median = validate_boundary(&input.opening)?;
    let closing_median = validate_boundary(&input.closing)?;
    let outcome = derive_resolution_outcome(opening_median, closing_median);

    let settlement_commitment =
        settlement_commitment(&input, opening_median, closing_median, &outcome);
    Ok(SettlementProofOutput {
        proof_program_version: input.proof_program_version,
        proof_program_version_hash: sha256(PROOF_PROGRAM_VERSION.as_bytes()),
        market_id_hash: sha256(input.market_id.as_bytes()),
        market_id: input.market_id,
        destination_chain_id: input.destination_chain_id,
        oracle_feed_id: input.oracle_feed_id,
        opening_median_e8: opening_median,
        closing_median_e8: closing_median,
        outcome,
        opening_evidence_commitment: input.opening.evidence_commitment,
        closing_evidence_commitment: input.closing.evidence_commitment,
        opening_observations_commitment: input.opening.observations_commitment,
        closing_observations_commitment: input.closing.observations_commitment,
        payout_root: input.payout_root,
        fee_root: input.fee_root,
        payout_coverage: input.payout_coverage,
        fee_coverage: input.fee_coverage,
        settlement_commitment,
    })
}

/// Canonical UP/DOWN/PUSH derivation shared by the production enclave and the
/// RISC Zero guest. Keeping this small pure function in the proof core makes
/// outcome equivalence a compile-time dependency instead of a documentation
/// claim.
pub fn derive_resolution_outcome(
    opening_median_e8: i64,
    closing_median_e8: i64,
) -> ResolutionOutcome {
    match closing_median_e8.cmp(&opening_median_e8) {
        core::cmp::Ordering::Greater => ResolutionOutcome::Up,
        core::cmp::Ordering::Less => ResolutionOutcome::Down,
        core::cmp::Ordering::Equal => ResolutionOutcome::Push,
    }
}

/// Encode the public journal as fifteen fixed 32-byte big-endian words.
///
/// This deliberately avoids a Rust/serde ABI on the public boundary so the
/// Horizen attestation contract can bind the verified zkVerify leaf to the
/// exact market and settlement commitment.
pub fn encode_public_journal(output: &SettlementProofOutput) -> [u8; PUBLIC_JOURNAL_BYTES] {
    let mut journal = [0u8; PUBLIC_JOURNAL_BYTES];
    put_word(&mut journal, 0, output.proof_program_version_hash);
    put_word(&mut journal, 1, output.market_id_hash);
    put_u64_word(&mut journal, 2, output.destination_chain_id);
    put_u64_word(&mut journal, 3, output.oracle_feed_id);
    put_i64_word(&mut journal, 4, output.opening_median_e8);
    put_i64_word(&mut journal, 5, output.closing_median_e8);
    journal[6 * 32 + 31] = output.outcome.discriminant();
    put_word(&mut journal, 7, output.opening_evidence_commitment);
    put_word(&mut journal, 8, output.closing_evidence_commitment);
    put_word(&mut journal, 9, output.opening_observations_commitment);
    put_word(&mut journal, 10, output.closing_observations_commitment);
    put_word(&mut journal, 11, output.payout_root);
    put_word(&mut journal, 12, output.fee_root);
    journal[13 * 32 + 30] = output.payout_coverage as u8;
    journal[13 * 32 + 31] = output.fee_coverage as u8;
    put_word(&mut journal, 14, output.settlement_commitment);
    journal
}

fn validate_boundary(boundary: &BoundaryWitness) -> Result<i64, ProofInputError> {
    if boundary
        .window_end_micros
        .checked_sub(boundary.window_start_micros)
        != Some(BOUNDARY_WINDOW_MICROS)
    {
        return Err(ProofInputError::InvalidBoundaryWindow);
    }
    if boundary.minimum_publisher_count < 3 {
        return Err(ProofInputError::InvalidPublisherPolicy);
    }
    if boundary.evidence_commitment == [0u8; 32] {
        return Err(ProofInputError::InvalidEvidenceCommitment);
    }
    if boundary.observations_e8.iter().any(|price| *price <= 0) {
        return Err(ProofInputError::InvalidObservation);
    }
    if observation_commitment(boundary) != boundary.observations_commitment {
        return Err(ProofInputError::InvalidObservationCommitment);
    }

    let mut sorted = boundary.observations_e8;
    sorted.sort_unstable();
    let median = sorted[BOUNDARY_SAMPLE_COUNT / 2];
    if median != boundary.expected_median_e8 {
        return Err(ProofInputError::InvalidMedian);
    }
    Ok(median)
}

fn settlement_commitment(
    input: &SettlementProofInput,
    opening_median_e8: i64,
    closing_median_e8: i64,
    outcome: &ResolutionOutcome,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_DOMAIN);
    put_bytes(&mut hasher, input.proof_program_version.as_bytes());
    put_bytes(&mut hasher, input.market_id.as_bytes());
    hasher.update(input.destination_chain_id.to_be_bytes());
    hasher.update(input.oracle_feed_id.to_be_bytes());
    hasher.update(input.opening.evidence_commitment);
    hasher.update(input.closing.evidence_commitment);
    hasher.update(input.opening.observations_commitment);
    hasher.update(input.closing.observations_commitment);
    hasher.update(opening_median_e8.to_be_bytes());
    hasher.update(closing_median_e8.to_be_bytes());
    hasher.update([outcome.discriminant()]);
    hasher.update(input.payout_root);
    hasher.update(input.fee_root);
    hasher.update([input.payout_coverage as u8, input.fee_coverage as u8]);
    hasher.finalize().into()
}

fn put_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn put_word(journal: &mut [u8; PUBLIC_JOURNAL_BYTES], index: usize, value: [u8; 32]) {
    journal[index * 32..(index + 1) * 32].copy_from_slice(&value);
}

fn put_u64_word(journal: &mut [u8; PUBLIC_JOURNAL_BYTES], index: usize, value: u64) {
    journal[(index + 1) * 32 - 8..(index + 1) * 32].copy_from_slice(&value.to_be_bytes());
}

fn put_i64_word(journal: &mut [u8; PUBLIC_JOURNAL_BYTES], index: usize, value: i64) {
    let fill = if value.is_negative() { 0xff } else { 0x00 };
    journal[index * 32..(index + 1) * 32].fill(fill);
    journal[(index + 1) * 32 - 8..(index + 1) * 32].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boundary(end: i64, prices: [i64; BOUNDARY_SAMPLE_COUNT]) -> BoundaryWitness {
        let mut sorted = prices;
        sorted.sort_unstable();
        let mut boundary = BoundaryWitness {
            window_start_micros: end - BOUNDARY_WINDOW_MICROS,
            window_end_micros: end,
            minimum_publisher_count: 3,
            evidence_commitment: [7u8; 32],
            observations_e8: prices,
            observations_commitment: [0u8; 32],
            expected_median_e8: sorted[12],
        };
        boundary.observations_commitment = observation_commitment(&boundary);
        boundary
    }

    fn input(
        opening: [i64; BOUNDARY_SAMPLE_COUNT],
        closing: [i64; BOUNDARY_SAMPLE_COUNT],
    ) -> SettlementProofInput {
        SettlementProofInput {
            proof_program_version: PROOF_PROGRAM_VERSION.into(),
            market_id: "layrs:v3:ZEN:15m:1785196800".into(),
            destination_chain_id: HORIZEN_CHAIN_ID,
            oracle_feed_id: ZEN_USD_PYTH_FEED_ID,
            opening: boundary(1_785_196_800_000_000, opening),
            closing: boundary(1_785_197_700_000_000, closing),
            payout_root: [0u8; 32],
            fee_root: [0u8; 32],
            payout_coverage: false,
            fee_coverage: false,
        }
    }

    #[test]
    fn proves_up_down_and_push() {
        let base = [
            100, 120, 80, 110, 90, 101, 102, 103, 104, 105, 106, 107, 108, 109, 111, 112, 113, 114,
            115, 116, 117, 118, 119, 121, 122,
        ];
        let higher = base.map(|price| price + 20);
        let lower = base.map(|price| price - 20);
        assert_eq!(
            prove_resolution(input(base, higher)).unwrap().outcome,
            ResolutionOutcome::Up
        );
        assert_eq!(
            prove_resolution(input(base, lower)).unwrap().outcome,
            ResolutionOutcome::Down
        );
        assert_eq!(
            prove_resolution(input(base, base)).unwrap().outcome,
            ResolutionOutcome::Push
        );
    }

    #[test]
    fn rejects_tampered_observations_and_median() {
        let base = [100; BOUNDARY_SAMPLE_COUNT];
        let mut tampered = input(base, base);
        tampered.closing.observations_e8[0] = 999;
        assert_eq!(
            prove_resolution(tampered),
            Err(ProofInputError::InvalidObservationCommitment)
        );

        let mut wrong_median = input(base, base);
        wrong_median.closing.expected_median_e8 = 101;
        assert_eq!(
            prove_resolution(wrong_median),
            Err(ProofInputError::InvalidMedian)
        );
    }

    #[test]
    fn rejects_wrong_chain_feed_and_unsupported_root_claims() {
        let base = [100; BOUNDARY_SAMPLE_COUNT];
        let mut wrong_chain = input(base, base);
        wrong_chain.destination_chain_id = 8453;
        assert_eq!(
            prove_resolution(wrong_chain),
            Err(ProofInputError::WrongDestinationChain)
        );

        let mut wrong_feed = input(base, base);
        wrong_feed.oracle_feed_id = 1;
        assert_eq!(
            prove_resolution(wrong_feed),
            Err(ProofInputError::WrongOracleFeed)
        );

        let mut false_coverage = input(base, base);
        false_coverage.payout_coverage = true;
        false_coverage.payout_root = [9u8; 32];
        assert_eq!(
            prove_resolution(false_coverage),
            Err(ProofInputError::UnsupportedPayoutCoverage)
        );
    }

    #[test]
    fn commitment_is_deterministic_and_market_bound() {
        let base = [100; BOUNDARY_SAMPLE_COUNT];
        let first = prove_resolution(input(base, base)).unwrap();
        let second = prove_resolution(input(base, base)).unwrap();
        assert_eq!(first.settlement_commitment, second.settlement_commitment);

        let mut changed = input(base, base);
        changed.market_id.push_str("-different");
        let changed = prove_resolution(changed).unwrap();
        assert_ne!(first.settlement_commitment, changed.settlement_commitment);
    }

    #[test]
    fn public_journal_is_fixed_and_binds_market_and_settlement() {
        let output = prove_resolution(input(
            [100; BOUNDARY_SAMPLE_COUNT],
            [120; BOUNDARY_SAMPLE_COUNT],
        ))
        .unwrap();
        let journal = encode_public_journal(&output);
        assert_eq!(journal.len(), PUBLIC_JOURNAL_BYTES);
        assert_eq!(&journal[32..64], &output.market_id_hash);
        assert_eq!(&journal[14 * 32..15 * 32], &output.settlement_commitment);
        assert_eq!(journal[6 * 32 + 31], ResolutionOutcome::Up.discriminant());
        assert_eq!(journal[13 * 32 + 30], 0);
        assert_eq!(journal[13 * 32 + 31], 0);
    }

    #[test]
    fn canonical_outcome_derivation_covers_signed_boundaries() {
        assert_eq!(derive_resolution_outcome(1, 2), ResolutionOutcome::Up);
        assert_eq!(derive_resolution_outcome(2, 1), ResolutionOutcome::Down);
        assert_eq!(derive_resolution_outcome(1, 1), ResolutionOutcome::Push);
        assert_eq!(
            derive_resolution_outcome(i64::MAX - 1, i64::MAX),
            ResolutionOutcome::Up
        );
        assert_eq!(
            derive_resolution_outcome(i64::MAX, i64::MAX - 1),
            ResolutionOutcome::Down
        );
    }

    #[test]
    fn rejects_unknown_fields_and_non_canonical_shapes() {
        let canonical = serde_json::to_value(input(
            [100; BOUNDARY_SAMPLE_COUNT],
            [100; BOUNDARY_SAMPLE_COUNT],
        ))
        .unwrap();
        let mut unknown_top_level = canonical.clone();
        unknown_top_level
            .as_object_mut()
            .unwrap()
            .insert("uncommittedField".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<SettlementProofInput>(unknown_top_level).is_err());

        let mut unknown_boundary = canonical;
        unknown_boundary["opening"]
            .as_object_mut()
            .unwrap()
            .insert("uncommittedField".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<SettlementProofInput>(unknown_boundary).is_err());
    }
}
