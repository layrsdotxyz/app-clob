# Direct BFF production image — 2026-09-12

The clean BFF bridge source at `8c9d73dc` was packaged through the existing
`layrs-production-backend-image-builder` and pushed to the existing
`layrs-production-backend` registry:

| Field | Value |
|---|---|
| Source archive SHA-256 | `5040e9e27f5445f8138db807bbbb5a2bb4215262ef64e4c81a46b3bd65caa10a` |
| CodeBuild | `layrs-production-backend-image-builder:0faf5911-14df-4622-9443-e0b6e5003ac1` |
| Image tag | `direct-bff-8c9d73dc` |
| Image digest | `sha256:ef783e524608cac7d8ec95080b69584bdb38d9fc152f664e6a95f7563b9f098b` |

The first build attempt was rejected because the image-builder role is
intentionally scoped to `source/app-backend-*.zip`; the same clean source was
then uploaded under that existing permitted prefix.  No IAM broadening was
made.  No ECS service/task definition, public route, production writer,
custody request, customer balance, or legacy writer was changed.

The resulting image is ready for the governed direct-BFF deployment manifest
once the writer/projection/monitoring activation controls are applied.  It
continues to use the existing Privy verifier and the epoch-bound session
bridge; it does not accept raw caller-selected identities or use PostgreSQL as
private financial-state authority.
