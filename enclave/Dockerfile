ARG SOURCE_DATE_EPOCH=1787611129

FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS builder
WORKDIR /build
ARG LAYRS_OPERATOR_PUBLIC_KEY_HEX
ARG LAYRS_RECOVERY_ENVIRONMENT
ARG LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256
ARG SOURCE_DATE_EPOCH
ENV LAYRS_OPERATOR_PUBLIC_KEY_HEX=${LAYRS_OPERATOR_PUBLIC_KEY_HEX}
ENV LAYRS_RECOVERY_ENVIRONMENT=${LAYRS_RECOVERY_ENVIRONMENT}
ENV LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256=${LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256}
COPY enclave/runtime/Cargo.toml enclave/runtime/Cargo.lock ./enclave/runtime/
COPY enclave/runtime/src ./enclave/runtime/src
COPY enclave/recovery-policies ./enclave/recovery-policies
COPY proofs/settlement/core ./proofs/settlement/core
COPY src ./src
RUN test "${#LAYRS_OPERATOR_PUBLIC_KEY_HEX}" -eq 64 \
    && test "${SOURCE_DATE_EPOCH}" = "1787611129" \
    && test "${LAYRS_RECOVERY_ENVIRONMENT}" = "development" -o "${LAYRS_RECOVERY_ENVIRONMENT}" = "staging" -o "${LAYRS_RECOVERY_ENVIRONMENT}" = "production" \
    && { test -z "${LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256}" \
      || echo "${LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256}" | grep -Eq '^[0-9a-f]{64}$'; } \
    && cargo build --locked --release --manifest-path enclave/runtime/Cargo.toml --bin layrs-enclave \
    && touch --date="@${SOURCE_DATE_EPOCH}" --no-dereference \
        /build/enclave/runtime/target/release/layrs-enclave

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e AS runtime-base

# BuildKit v0.12 fixes image configuration timestamps from SOURCE_DATE_EPOCH,
# but does not rewrite file metadata inside image layers. Normalize the whole
# runtime rootfs and squash it through scratch before Nitro packages it.
FROM builder AS normalizer
ARG SOURCE_DATE_EPOCH
COPY --from=runtime-base / /normalized-rootfs
RUN test "${SOURCE_DATE_EPOCH}" = "1787611129" \
    && install -D --owner=65532 --group=65532 --mode=0755 \
        /build/enclave/runtime/target/release/layrs-enclave \
        /normalized-rootfs/usr/local/bin/layrs-enclave \
    && find /normalized-rootfs -xdev -newermt "@${SOURCE_DATE_EPOCH}" \
        -writable -print0 \
        | xargs -0 -r touch --date="@${SOURCE_DATE_EPOCH}" --no-dereference

FROM scratch
COPY --from=normalizer /normalized-rootfs /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /home/nonroot
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/layrs-enclave"]
