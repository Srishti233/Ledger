"""Configuration: YAML file + LEDGER_* environment overrides, validated."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

# Anvil/Hardhat well-known development keys. They control accounts on EVERY dev
# chain and hold no real value. They are the defaults on purpose and must never be
# used with a real network.
ANVIL_TEST_KEY_DEPLOYER = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_TEST_KEY_ANCHORER = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
TEST_KEYS = {ANVIL_TEST_KEY_DEPLOYER, ANVIL_TEST_KEY_ANCHORER}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "chain", "anvil", "host.docker.internal"}


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    rpc_url: str = "http://127.0.0.1:8545"
    private_key: str = ANVIL_TEST_KEY_ANCHORER  # signs anchorBatch (allowlisted)
    deployer_private_key: str = ANVIL_TEST_KEY_DEPLOYER  # owner; only used by `ledger deploy`
    contract_address: str = ""  # empty -> read <data_dir>/deployment.json
    artifact_path: str = ""  # forge artifact JSON; empty -> search default locations
    data_dir: str = "./data"
    db_path: str = ""  # empty -> <data_dir>/ledger.db
    batch_size: int = 100
    max_wait_seconds: int = 300
    confirmations: int = 1
    interval_seconds: int = 0  # background auto-anchor loop; 0 disables
    tx_timeout_seconds: int = 60
    explorer_tx_url: str = ""  # e.g. https://sepolia.etherscan.io/tx/{tx_hash}
    aegis_db_url: str = ""
    aegis_url: str = ""
    aegis_admin_key: str = ""
    allow_non_local_chain: bool = False
    api_key: str = ""  # if set, mutating API endpoints require header X-Ledger-Key
    inbox_dir: str = ""  # API may only read Gauntlet results from here (default <data_dir>/inbox)

    @property
    def inbox(self) -> str:
        return self.inbox_dir or str(Path(self.data_dir) / "inbox")

    @property
    def database(self) -> str:
        return self.db_path or str(Path(self.data_dir) / "ledger.db")

    @property
    def deployment_file(self) -> str:
        return str(Path(self.data_dir) / "deployment.json")

    @property
    def source_dir(self) -> str:
        return str(Path(self.data_dir) / "source")

    def is_local_chain(self) -> bool:
        host = (urlparse(self.rpc_url).hostname or "").lower()
        return host in LOCAL_HOSTS or host.startswith("192.168.") or host.startswith("10.")

    def validate(self) -> "Config":
        parsed = urlparse(self.rpc_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ConfigError(f"rpc_url must be an http(s) URL, got {self.rpc_url!r}")
        for name in ("private_key", "deployer_private_key"):
            if not re.fullmatch(r"0x[0-9a-fA-F]{64}", getattr(self, name)):
                raise ConfigError(f"{name} must be 0x followed by 64 hex characters")
        if self.contract_address and not re.fullmatch(r"0x[0-9a-fA-F]{40}", self.contract_address):
            raise ConfigError("contract_address must be a 0x-prefixed 20-byte address")
        if self.batch_size < 1:
            raise ConfigError("batch_size must be >= 1")
        if self.confirmations < 1:
            raise ConfigError("confirmations must be >= 1")
        if self.max_wait_seconds < 0 or self.interval_seconds < 0:
            raise ConfigError("max_wait_seconds and interval_seconds must be >= 0")
        if self.tx_timeout_seconds < 1:
            raise ConfigError("tx_timeout_seconds must be >= 1")
        if not self.is_local_chain():
            if not self.allow_non_local_chain:
                raise ConfigError(
                    "rpc_url is not a local host. Ledger anchors to a LOCAL chain by default; "
                    "set allow_non_local_chain: true to use a public testnet (never mainnet)."
                )
            if self.private_key in TEST_KEYS or self.deployer_private_key in TEST_KEYS:
                raise ConfigError(
                    "refusing to use the well-known Anvil test keys against a non-local chain; "
                    "anyone can spend from those accounts. Provide your own testnet keys."
                )
        return self


def _coerce(name: str, value: Any, default: Any) -> Any:
    if isinstance(default, bool):
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if isinstance(default, int):
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{name} must be an integer, got {value!r}") from exc
    return "" if value is None else str(value)


def load_config(path: str | Path | None = None, env: Optional[dict] = None) -> Config:
    """Load defaults < YAML file < LEDGER_<FIELD> environment variables."""
    env = os.environ if env is None else env
    path = path or env.get("LEDGER_CONFIG")
    values: dict[str, Any] = {}
    if path:
        p = Path(path)
        if not p.exists():
            raise ConfigError(f"config file not found: {p}")
        import yaml

        loaded = yaml.safe_load(p.read_text()) or {}
        if not isinstance(loaded, dict):
            raise ConfigError("config file must contain a YAML mapping")
        values.update(loaded)
    for f in fields(Config):
        key = "LEDGER_" + f.name.upper()
        if key in env:
            values[f.name] = env[key]
    defaults = Config()
    known = {f.name for f in fields(Config)}
    unknown = set(values) - known
    if unknown:
        raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")
    coerced = {k: _coerce(k, v, getattr(defaults, k)) for k, v in values.items()}
    return Config(**coerced).validate()
