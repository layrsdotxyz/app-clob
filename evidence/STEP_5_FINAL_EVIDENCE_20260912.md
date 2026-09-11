# Step 5 evidence — verified, not activated

The isolated Nitro candidate is `ami-00b5f08fce6be9018`.  Its EIF is
`138d35cb576bd07f2dcf37652d436fa4d2acdc5aa3431c6c4934a0ff8cbc1548`.
It attests to the sealed opening epoch and runs `layrs.direct-execution.v1`.

The packaged canary proved one 1 USDC withdrawal effect from an isolated
5 USDC opening balance, one immutable artifact, receipt, accounting event,
custody projection, and session.  A parent restart restored 4 USDC; replay of
the exact request remained 4 USDC and created no duplicate projection or
artifact.  Missing and corrupted latest artifacts stopped the parent before
serving and recovered only after the original isolated artifact was restored.

Privy ES256/JWKS verification, canonical wallet binding, epoch-bound signed
sessions, deterministic custody-finality semantics, and writer-grant rejection
coverage passed in clean worktrees.  PostgreSQL was verified as projection only;
the runtime restored exclusively from the immutable encrypted artifact.

`STEP_5_STATUS = VERIFIED_NOT_ACTIVATED`

Production activation remains blocked on an independently governed old-writer
fence and signed grant, attested live custody credentials/finality, explicit
activation approval, and a separately authorized funded canary.  No production
resource or customer financial state was changed.
