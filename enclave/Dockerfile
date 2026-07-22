FROM rust:1.94-bookworm AS builder
WORKDIR /build
ARG LAYRS_OPERATOR_PUBLIC_KEY_HEX
ENV LAYRS_OPERATOR_PUBLIC_KEY_HEX=${LAYRS_OPERATOR_PUBLIC_KEY_HEX}
COPY enclave/runtime/Cargo.toml enclave/runtime/Cargo.lock ./enclave/runtime/
COPY enclave/runtime/src ./enclave/runtime/src
COPY src ./src
RUN test "${#LAYRS_OPERATOR_PUBLIC_KEY_HEX}" -eq 64 \
    && cargo build --locked --release --manifest-path enclave/runtime/Cargo.toml --bin layrs-enclave

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder --chown=nonroot:nonroot /build/enclave/runtime/target/release/layrs-enclave /usr/local/bin/layrs-enclave
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/layrs-enclave"]
