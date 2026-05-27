# ── build stage ───────────────────────────────────────────────────────────────
# Pin the toolchain so every build uses the same compiler (reproducibility).
FROM rust:1.83.0-bookworm AS builder

WORKDIR /app

# Workspace manifests arrive before source so the dependency layer is cached.
COPY Cargo.toml Cargo.lock ./
# Copy each workspace member; the WASM client crate (wasm32-unknown-unknown) is
# excluded — it is not a dependency of the server binary.
COPY crates/adapters crates/adapters/
COPY crates/application crates/application/
COPY crates/domain crates/domain/
COPY crates/infra crates/infra/
COPY crates/ports crates/ports/
COPY bin/ bin/

# SOURCE_DATE_EPOCH strips embedded build timestamps from the binary, making the
# output byte-for-byte reproducible across CI runs on the same source tree.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# --locked: Cargo resolves only from committed Cargo.lock — no silent dep drift.
RUN cargo build --release --locked --bin powehi-server

# ── runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-20250317-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    adduser --disabled-password --gecos '' --uid 1000 powehi

COPY --from=builder /app/target/release/powehi-server /usr/local/bin/powehi-server

# Runtime defaults — operators override these via ConfigMap / Secrets.
ENV POWEHI__HOST="0.0.0.0" \
    POWEHI__PORT="8080" \
    POWEHI__ADMIN_PORT="9090"

EXPOSE 8080 9090

USER powehi

ENTRYPOINT ["/usr/local/bin/powehi-server"]
