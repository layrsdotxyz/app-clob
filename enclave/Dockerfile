FROM rust:1.94-bookworm AS builder
WORKDIR /build
ARG LAYRS_OPERATOR_PUBLIC_KEY_HEX
ENV LAYRS_OPERATOR_PUBLIC_KEY_HEX=${LAYRS_OPERATOR_PUBLIC_KEY_HEX}
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN test "${#LAYRS_OPERATOR_PUBLIC_KEY_HEX}" -eq 64 \
    && cargo build --locked --release --bin layrs-enclave

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home layrs
COPY --from=builder /build/target/release/layrs-enclave /usr/local/bin/layrs-enclave
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/layrs-enclave"]
