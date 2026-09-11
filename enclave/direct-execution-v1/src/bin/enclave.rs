use std::env;

use layrs_direct_execution_v1::{SealedEpoch, EPOCH_STATE_SHA256, TRANSACTION_MODEL};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::var("LAYRS_OPENING_EPOCH_PATH")?;
    let epoch = SealedEpoch::load(path)?;
    println!("{{\"runtime\":\"enclave\",\"transactionModel\":\"{TRANSACTION_MODEL}\",\"epochStateSha256\":\"{EPOCH_STATE_SHA256}\",\"identityCount\":{}}}", epoch.identity_count());
    Ok(())
}
