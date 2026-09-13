#!/usr/bin/env node

import { createHash, createPublicKey, verify } from 'node:crypto';

const epochId = 'layrs-opening-epoch-20260911-941107537728c98b';
const runtime = 'layrs.direct-execution.v1';
const domain = 'layrs.direct-market-registration.v1\0';
const governanceKeyId = 'alias/layrs/production/recovery-evidence-signing';
const signingAlgorithm = 'ECDSA_SHA_256';
const governancePublicKeyDerBase64 = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj+YWePc+NPoCGDc7OF6yw4rVY2VYN0Ty3K2Y/tndvv9YSEp3scEn24l8KwAlexmygo+jlBofIkiSr12Wk99iuQ==';
const sourceManifestSha256 = 'f156932795e74e5dc37089ace56bc088b8b2a006e66902d42a68fcf8bef7810a';
const sourceCapturedAt = '2026-09-13T19:19:26.578Z';
const sourceCapturedAtUnix = 1_789_327_166;
// One bounded UTC cutover window. Registration is a one-time governed state
// change; an accepted registration remains part of the encrypted ledger after
// this authorization expires.
const expiresAtUnix = 1_789_430_400; // 2026-09-15T00:00:00Z

const limits = Object.freeze({
  minimum_quantity_micros: '1000',
  maximum_quantity_micros: '1000000000',
  minimum_order_notional_micros: '1000000',
  maximum_order_notional_micros: '1000000000',
  maximum_user_position_micros: '2500000000',
  maximum_pending_bootstrap_notional_micros: '1000000000',
  tick_size_micros: 1000,
});

const sourceMarkets = [
  ['BTC', '1f9b3a006f4397cf2fa5bc2f829b7132fc837011ae97721e1be92e3d85ffeaeb', 9002],
  ['ETH', 'a9064871759503838b9b9b6c8cecbc733fa1ba17f34dbe69a3ff84cba95175e7', 9003],
  ['HYPE', '2e217e3c185a62bf4930b83a5160d590637726fe9764768534cc5fe3f1c13990', 9006],
  ['SOL', '9ea85e8f788fc29bc920aaf97e31cf94d99dbfef4679b8829a6a22df6570735e', 9004],
  ['ZEC', 'ad4adb70ef8c7f4449696f7645f372d21775453954b7808391e524308452ca82', 9005],
];

const signatures = Object.freeze({
  BTC: 'MEQCIB+ifDjEqsayRAliI1kMliymft36d9DJPbPkcaecy17tAiAYzWG8YujhVf4UW7LZO3BL0OhB6Z8TS10Z7r5ID6dkRQ==',
  ETH: 'MEUCIC/I3f7hD2PNNCH7NDQQO4xRPyPXIQetY/MM4tNXsWWoAiEA1zXAaiUWTaPC7cm6QiNhlAd0F2HLEWT71dMTj/j7v2o=',
  HYPE: 'MEUCIQCQFg77ptc76qlUjZ1U3UO7uK7ONINWbGz2DyHbSa83xgIgYm7sB7RnqAj9rLC7fg3t/XvkMqP1E5wptEdZrU2sKBw=',
  SOL: 'MEUCIQDseIFWqG9DBA6ooKg1xG1vMgowftYVdk+udBzO8y6D0AIgHIZtch00tFtHjaCUcLwMHT8MTyUeOsaoG+6DwmpjmT8=',
  ZEC: 'MEUCIQDoduIvsTPEB4vraBOe39bga9wrAUpFb8YhyJFOy2lq2QIgRATIMWCxJaAYMuUn+zEIUOQXXD413ZTpjjq+wbHNeRc=',
});

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const registrations = sourceMarkets.map(([asset, contentHash, oracleFeedId]) => {
  const marketId = `layrs:v5:${asset}:USDC:1mo:1788220800`;
  const unsigned = {
    registrationId: `direct-market:${contentHash}`,
    epochId,
    runtime,
    market: {
      market_id: marketId,
      settlement_asset: 'USDC',
      settlement_decimals: 6,
      public_settlement_chain: 'horizen',
      opens_at_millis: 1_788_220_800_000,
      closes_at_millis: 1_790_812_800_000,
      ...limits,
      oracle_feed_id: oracleFeedId,
      fee_profile_id: 'LAYRS_CRYPTO_V2',
      execution: 'NATIVE_CLOB',
    },
    expiresAtUnix,
    governanceKeyId,
    signingAlgorithm,
    signature: '',
  };
  const signingPayload = Buffer.from(JSON.stringify([domain, unsigned]));
  const signature = signatures[asset];
  const signedRegistration = { ...unsigned, signature };
  const publicKey = createPublicKey({
    key: Buffer.from(governancePublicKeyDerBase64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const localSignatureVerification = verify(
    'sha256',
    signingPayload,
    publicKey,
    Buffer.from(signature, 'base64'),
  );
  if (!localSignatureVerification) {
    throw new Error(`governance signature verification failed for ${marketId}`);
  }
  return {
    marketId,
    sourceContentHash: contentHash,
    sourceManifestSha256,
    unsignedRegistration: unsigned,
    signingPayloadBase64: signingPayload.toString('base64'),
    signingPayloadSha256: sha256(signingPayload),
    kmsSignatureVerifiedAtCreation: true,
    localSignatureVerification,
    httpBody: { registration: signedRegistration },
  };
});

process.stdout.write(`${JSON.stringify({
  protocol: 'layrs.direct-market-registration-evidence.v1',
  source: {
    authority: 'production PostgreSQL layrsv2.market_specs joined to immutable layrsv2.market_release_manifests.payload',
    transaction: 'REPEATABLE READ READ ONLY',
    capturedAt: sourceCapturedAt,
    capturedAtUnix: sourceCapturedAtUnix,
    releaseManifestSha256: sourceManifestSha256,
    filters: {
      lifecycle: 'OPEN',
      publicState: 'OPEN',
      visible: true,
      namespace: 'layrs:v5',
      settlementAsset: 'USDC',
      executionMode: 'NATIVE_ONLY',
      resolutionKinds: ['BINANCE_SPOT_KLINE_MEDIAN', 'KRAKEN_SPOT_TRADE_MEDIAN'],
      closesAfterCapture: true,
      selectedWindow: '1mo',
    },
  },
  signing: {
    domain,
    governanceKeyId,
    signingAlgorithm,
    publicKeyDerSha256: 'a001a573309c778b0b1f90ecd93eaf1cb07a37f4bea501c32c43afd754871f22',
    expiresAtUnix,
    expiresAt: '2026-09-15T00:00:00.000Z',
    signatureEncoding: 'standard-base64 DER ECDSA P-256',
  },
  registrations,
}, null, 2)}\n`);
