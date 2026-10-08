"""Blockchain access.

``ChainClient`` is the small interface the rest of Ledger depends on. The only real
implementation is ``Web3ChainClient`` (web3.py, imported lazily so everything else
works without it). Tests use an in-memory fake; integration tests and the Docker demo
use a real Anvil node.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol

from .config import Config, ConfigError
from .models import AnchorReceipt, OnChainBatch

DEFAULT_ARTIFACT_LOCATIONS = (
    "/app/artifacts/AuditAnchor.json",
    "contracts/out/AuditAnchor.sol/AuditAnchor.json",
)


class ChainError(RuntimeError):
    pass


class ChainClient(Protocol):
    contract_address: str

    def is_connected(self) -> bool: ...
    def chain_id(self) -> int: ...
    def anchor_batch(self, root: bytes, label: str, count: int, timeout: float) -> AnchorReceipt: ...
    def get_batch(self, batch_id: int) -> Optional[OnChainBatch]: ...
    def wait_confirmations(self, receipt: AnchorReceipt, needed: int, timeout: float) -> None: ...


def load_artifact(path: str = "") -> dict:
    """Load the forge build artifact (ABI + bytecode) for AuditAnchor."""
    candidates = [path] if path else list(DEFAULT_ARTIFACT_LOCATIONS)
    for c in candidates:
        if c and Path(c).is_file():
            data = json.loads(Path(c).read_text())
            bytecode = data.get("bytecode", {})
            bytecode = bytecode.get("object", "") if isinstance(bytecode, dict) else bytecode
            if not data.get("abi") or not bytecode:
                raise ChainError(f"artifact {c} has no abi/bytecode; rebuild with `forge build`")
            return {"abi": data["abi"], "bytecode": bytecode}
    raise ChainError(
        "contract artifact not found (looked in: "
        + ", ".join(candidates)
        + "). Run `forge build` in contracts/ or set LEDGER_ARTIFACT_PATH."
    )


class Web3ChainClient:
    def __init__(self, rpc_url: str, contract_address: str, abi: list, private_key: str):
        from web3 import Web3

        self._Web3 = Web3
        self._w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
        self._account = self._w3.eth.account.from_key(private_key)
        self.contract_address = Web3.to_checksum_address(contract_address)
        self._contract = self._w3.eth.contract(address=self.contract_address, abi=abi)

    def is_connected(self) -> bool:
        try:
            return bool(self._w3.is_connected())
        except Exception:
            return False

    def chain_id(self) -> int:
        return int(self._w3.eth.chain_id)

    def anchor_batch(self, root: bytes, label: str, count: int, timeout: float) -> AnchorReceipt:
        if len(root) != 32:
            raise ChainError("merkle root must be 32 bytes")
        try:
            sender = self._account.address
            fn = self._contract.functions.anchorBatch(root, label, count)
            tx = fn.build_transaction(
                {"from": sender, "nonce": self._w3.eth.get_transaction_count(sender, "pending")}
            )
            signed = self._account.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
            tx_hash = self._w3.eth.send_raw_transaction(raw)
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
        except Exception as exc:
            raise ChainError(f"anchorBatch transaction failed: {exc}") from exc
        if receipt["status"] != 1:
            raise ChainError(f"anchorBatch reverted (tx {tx_hash.hex()})")
        events = self._contract.events.BatchAnchored().process_receipt(receipt)
        if not events:
            raise ChainError("transaction mined but no BatchAnchored event was found")
        block = self._w3.eth.get_block(receipt["blockNumber"])
        return AnchorReceipt(
            batch_id=int(events[0]["args"]["batchId"]),
            tx_hash=self._tx_hex(tx_hash),
            block_number=int(receipt["blockNumber"]),
            block_timestamp=int(block["timestamp"]),
            gas_used=int(receipt["gasUsed"]),
            contract_address=self.contract_address,
        )

    @staticmethod
    def _tx_hex(tx_hash) -> str:
        h = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
        return h if h.startswith("0x") else "0x" + h

    def get_batch(self, batch_id: int) -> Optional[OnChainBatch]:
        try:
            count = int(self._contract.functions.batchCount().call())
            if not 1 <= batch_id <= count:
                return None
            root, label_hash, by, rec_count, ts, block = self._contract.functions.getBatch(
                batch_id
            ).call()
        except Exception as exc:
            raise ChainError(f"on-chain lookup failed: {exc}") from exc
        return OnChainBatch(
            batch_id=batch_id,
            merkle_root=bytes(root).hex(),
            label_hash=bytes(label_hash).hex(),
            anchored_by=str(by),
            record_count=int(rec_count),
            timestamp=int(ts),
            block_number=int(block),
            contract_address=self.contract_address,
        )

    def wait_confirmations(self, receipt: AnchorReceipt, needed: int, timeout: float) -> None:
        """Block until ``needed`` confirmations, and fail if the tx left its block (reorg)."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                latest = int(self._w3.eth.block_number)
                current = self._w3.eth.get_transaction_receipt(receipt.tx_hash)
            except Exception as exc:
                raise ChainError(f"lost track of tx {receipt.tx_hash} (possible reorg): {exc}") from exc
            if int(current["blockNumber"]) != receipt.block_number:
                raise ChainError("transaction moved blocks: chain reorganised, re-run anchoring")
            if latest - receipt.block_number + 1 >= needed:
                return
            if time.monotonic() > deadline:
                raise ChainError(
                    f"timed out waiting for {needed} confirmations. A dev chain with "
                    "automine only produces blocks when transactions arrive; use confirmations: 1."
                )
            time.sleep(0.5)

    # ---- deployment helpers (used by `ledger deploy` and integration tests) --------
    @property
    def w3(self):
        return self._w3


def _send(w3, account, tx: dict, timeout: float):
    signed = account.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
    if receipt["status"] != 1:
        raise ChainError(f"transaction reverted: {tx_hash.hex()}")
    return receipt


def deploy_contract(cfg: Config, artifact: dict) -> dict:
    """Deploy AuditAnchor with the deployer key and allowlist the anchoring key."""
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        raise ChainError(f"cannot reach chain at {cfg.rpc_url}")
    deployer = w3.eth.account.from_key(cfg.deployer_private_key)
    anchorer = w3.eth.account.from_key(cfg.private_key)
    factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    try:
        tx = factory.constructor().build_transaction(
            {"from": deployer.address, "nonce": w3.eth.get_transaction_count(deployer.address, "pending")}
        )
        receipt = _send(w3, deployer, tx, cfg.tx_timeout_seconds)
        address = receipt["contractAddress"]
        contract = w3.eth.contract(address=address, abi=artifact["abi"])
        tx2 = contract.functions.setAnchorer(anchorer.address, True).build_transaction(
            {"from": deployer.address, "nonce": w3.eth.get_transaction_count(deployer.address, "pending")}
        )
        _send(w3, deployer, tx2, cfg.tx_timeout_seconds)
    except ChainError:
        raise
    except Exception as exc:
        raise ChainError(f"deployment failed: {exc}") from exc
    return {
        "contract_address": address,
        "chain_id": int(w3.eth.chain_id),
        "deployer": deployer.address,
        "anchorer": anchorer.address,
        "deploy_tx": Web3.to_hex(receipt["transactionHash"]),
        "deployed_block": int(receipt["blockNumber"]),
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }


def read_deployment(cfg: Config) -> Optional[dict]:
    p = Path(cfg.deployment_file)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


def ensure_deployment(cfg: Config) -> tuple[dict, bool]:
    """Return (deployment, deployed_now). Reuse an existing contract if it still has
    code on the connected chain and our anchoring key is allowlisted; else deploy."""
    from web3 import Web3

    artifact = load_artifact(cfg.artifact_path)
    w3 = Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        raise ChainError(f"cannot reach chain at {cfg.rpc_url}")
    existing = read_deployment(cfg)
    if cfg.contract_address:
        existing = {"contract_address": cfg.contract_address}
    if existing:
        addr = Web3.to_checksum_address(existing["contract_address"])
        if w3.eth.get_code(addr):
            anchorer = w3.eth.account.from_key(cfg.private_key).address
            c = w3.eth.contract(address=addr, abi=artifact["abi"])
            if c.functions.isAnchorer(anchorer).call():
                return existing, False
        if cfg.contract_address:
            raise ChainError(
                f"configured contract {cfg.contract_address} has no code or does not "
                "allowlist the anchoring key on this chain"
            )
    dep = deploy_contract(cfg, artifact)
    Path(cfg.data_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.deployment_file).write_text(json.dumps(dep, indent=2))
    return dep, True


def make_chain(cfg: Config) -> Web3ChainClient:
    artifact = load_artifact(cfg.artifact_path)
    address = cfg.contract_address
    if not address:
        dep = read_deployment(cfg)
        if not dep:
            raise ConfigError("no contract address: run `ledger deploy` first (or set contract_address)")
        address = dep["contract_address"]
    return Web3ChainClient(cfg.rpc_url, address, artifact["abi"], cfg.private_key)
