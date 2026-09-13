use std::io::{self, Read};

use layrs_direct_execution_v1::GovernedMarketRegistration;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Evidence {
    source: Source,
    signing: Signing,
    registrations: Vec<RegistrationEvidence>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Source {
    captured_at_unix: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Signing {
    expires_at_unix: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationEvidence {
    market_id: String,
    http_body: RegistrationBody,
}

#[derive(Deserialize)]
struct RegistrationBody {
    registration: GovernedMarketRegistration,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let evidence: Evidence = serde_json::from_slice(&input)?;
    if evidence.registrations.is_empty()
        || evidence.signing.expires_at_unix <= evidence.source.captured_at_unix
        || evidence.signing.expires_at_unix
            > evidence
                .source
                .captured_at_unix
                .saturating_add(30 * 60 * 60)
    {
        return Err("unbounded or invalid registration authorization window".into());
    }
    for item in &evidence.registrations {
        if item.market_id != item.http_body.registration.market.market_id
            || item.http_body.registration.expires_at_unix != evidence.signing.expires_at_unix
            || !item
                .http_body
                .registration
                .verify(evidence.source.captured_at_unix)
        {
            return Err(format!("invalid registration evidence for {}", item.market_id).into());
        }
    }
    println!(
        "verified {} governed direct-market registrations",
        evidence.registrations.len()
    );
    Ok(())
}
