use layrs_direct_execution_v1::DirectStateArtifact;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("artifact path required")?;
    let artifact: DirectStateArtifact = serde_cbor::from_slice(&std::fs::read(path)?)?;
    println!("{}", serde_json::json!({"epochId": artifact.epoch_id, "sequence": artifact.sequence, "priorStateHash": artifact.prior_state_hash, "stateHash": artifact.state_hash, "receipt": artifact.receipt}));
    Ok(())
}
