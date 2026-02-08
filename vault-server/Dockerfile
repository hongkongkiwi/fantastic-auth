# Build stage
FROM rust:1.79-slim-bookworm AS builder

WORKDIR /usr/src/vault-server

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-chef for efficient layer caching
RUN cargo install cargo-chef

# Generate recipe
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source and build
COPY . .
RUN cargo build --release --bin vault-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

ARG DBMATE_VERSION=2.12.0
RUN curl -fsSL "https://github.com/amacneil/dbmate/releases/download/v${DBMATE_VERSION}/dbmate-linux-amd64" \
    -o /usr/local/bin/dbmate \
    && chmod +x /usr/local/bin/dbmate

# Create app user
RUN groupadd -r vault && useradd -r -g vault vault

WORKDIR /app

# Copy binary and necessary files
COPY --from=builder /usr/src/vault-server/target/release/vault-server /app/vault-server
COPY --from=builder /usr/src/vault-server/.env.example /app/.env.example
COPY --from=builder /usr/src/vault-server/migrations /app/migrations

# Set permissions
RUN chown -R vault:vault /app

USER vault

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:3000/health || exit 1

EXPOSE 3000 9090

CMD ["./vault-server"]
