use std::{env, fs};

use anyhow::{anyhow, Context, Result};
use risc0_zkvm::InnerReceipt;
use serde::Serialize;

#[derive(Serialize)]
struct ZkVerifyProof<'a> {
    inner: &'a InnerReceipt,
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let source = args
        .next()
        .ok_or_else(|| anyhow!("usage: wrap_zkverify_proof <inner-receipt.cbor> <proof.cbor>"))?;
    let destination = args
        .next()
        .ok_or_else(|| anyhow!("usage: wrap_zkverify_proof <inner-receipt.cbor> <proof.cbor>"))?;
    if args.next().is_some() {
        return Err(anyhow!("unexpected extra arguments"));
    }

    let inner: InnerReceipt =
        ciborium::from_reader(fs::File::open(&source).with_context(|| format!("open {source}"))?)
            .context("decode inner receipt")?;
    let mut encoded = Vec::new();
    ciborium::into_writer(&ZkVerifyProof { inner: &inner }, &mut encoded)
        .context("encode zkVerify proof wrapper")?;
    fs::write(&destination, encoded).with_context(|| format!("write {destination}"))?;
    Ok(())
}
