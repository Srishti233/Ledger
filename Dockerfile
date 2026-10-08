# syntax=docker/dockerfile:1

# Stage 1: compile the contract with Foundry (needs network once, to fetch solc).
FROM ghcr.io/foundry-rs/foundry:latest AS contracts
USER root
WORKDIR /work
COPY contracts/foundry.toml ./foundry.toml
COPY contracts/src ./src
RUN forge build --out /work/out

# Stage 2: the Ledger service.
FROM python:3.12-slim AS app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY ledger ./ledger
RUN pip install ".[postgres]"
COPY --from=contracts /work/out/AuditAnchor.sol/AuditAnchor.json /app/artifacts/AuditAnchor.json
RUN useradd --create-home --uid 10001 ledger && mkdir -p /data && chown ledger:ledger /data
USER ledger
ENV LEDGER_ARTIFACT_PATH=/app/artifacts/AuditAnchor.json \
    LEDGER_DATA_DIR=/data
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --retries=20 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1
# `ledger deploy` is idempotent: it reuses the contract if it still exists on the chain.
CMD ["sh", "-c", "ledger deploy && exec ledger serve --host 0.0.0.0 --port 8000"]
