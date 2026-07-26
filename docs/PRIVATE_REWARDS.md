# Private rewards and claim authorization

The private trading core now owns cumulative reward entitlements. An operator
may submit an encrypted, signed `ACCRUE_REWARD` command containing an identity
commitment, reward rail, amount and non-zero evidence hash. Inside the enclave,
the identity commitment is converted to the existing keyed private-user ID.
Only that private ID and cumulative amount enter the encrypted journal and
snapshot.

Users query `REWARDS` or submit `REQUEST_REWARD_CLAIM` through the existing
attested private relay. The session guard ensures a user can see only the
entitlements belonging to that private-user ID. The first claim permanently
binds the private entitlement/chain/token tuple to one claim account; later
authorizations cannot redirect the cumulative entitlement to a different
account. A recipient may still differ because the recipient is covered by the
claim signature.

The chain-signer bundle accepts optional `reward_claim_domains`. Each configured
domain contains a dedicated ECDSA key and the deployed
`LayrsRewardClaimDistributor` address. The key is held only in the enclave and
signs the distributor's exact EIP-712 `Claim` digest. It must be distinct from
pool-withdrawal and market-resolution keys, and its address must receive only
`CLAIM_SIGNER_ROLE`.

The host receives ciphertext and public enclave artifacts. It does not receive
the claim account, recipient, token amount or entitlement list. An onchain claim
necessarily reveals the account, recipient, reward token and amount, but it does
not reveal the private trading identity or LP history.

Deployment remains fail-closed until:

- the reward distributor and PRE_TGE addresses are governance-approved;
- a dedicated claim key is provisioned through the attested KMS release flow;
- its signer address is granted `CLAIM_SIGNER_ROLE`;
- the operator accrual source and fee-batch evidence policy are approved; and
- a small-denomination controlled-wallet claim E2E is completed.
