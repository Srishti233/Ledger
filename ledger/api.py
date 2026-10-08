"""FastAPI service: thin HTTP layer over LedgerService."""

from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import __version__
from .anchorer import AnchorError
from .chain import ChainError, make_chain
from .config import Config
from .dashboard import render_dashboard
from .service import LedgerService
from .sources import SourceUnavailable
from .store import Index

log = logging.getLogger("ledger")


class GauntletBody(BaseModel):
    results_path: str = Field(..., description="Path to results.json inside the inbox directory")


class SyntheticBody(BaseModel):
    count: int = Field(25, ge=1, le=10000)
    kind: Literal["aegis", "gauntlet"] = "aegis"


def build_service(cfg: Config) -> LedgerService:
    return LedgerService(cfg, Index(cfg.database), make_chain(cfg))


async def _auto_anchor(svc: LedgerService, interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(svc.anchor_if_due)
        except Exception as exc:  # keep the loop alive; the next tick retries
            log.warning("auto-anchor failed: %s", exc)


def create_app(cfg: Config, service: Optional[LedgerService] = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if getattr(app.state, "svc", None) is None:
            app.state.svc = build_service(cfg)
        task = None
        if cfg.interval_seconds > 0:
            task = asyncio.create_task(_auto_anchor(app.state.svc, cfg.interval_seconds))
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Ledger", version=__version__, lifespan=lifespan)
    app.state.svc = service

    def svc_dep(request: Request) -> LedgerService:
        return request.app.state.svc

    def require_key(x_ledger_key: Optional[str] = Header(default=None)) -> None:
        if cfg.api_key and not (x_ledger_key and hmac.compare_digest(x_ledger_key, cfg.api_key)):
            raise HTTPException(401, "missing or invalid X-Ledger-Key header")

    def guard(fn):
        try:
            return fn()
        except LookupError as exc:
            raise HTTPException(404, str(exc))
        except SourceUnavailable as exc:
            raise HTTPException(503, str(exc))
        except (AnchorError, ChainError) as exc:
            raise HTTPException(502, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/status")
    def status(svc: LedgerService = Depends(svc_dep)) -> dict:
        return svc.status()

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(svc: LedgerService = Depends(svc_dep)) -> PlainTextResponse:
        return PlainTextResponse(svc.metrics_text(), media_type="text/plain; version=0.0.4")

    @app.post("/collect/aegis", dependencies=[Depends(require_key)])
    def collect_aegis(svc: LedgerService = Depends(svc_dep)) -> dict:
        """Uses the server-side aegis_db_url; the API never accepts a database URL from callers."""
        return guard(lambda: svc.collect_aegis())

    @app.post("/collect/gauntlet", dependencies=[Depends(require_key)])
    def collect_gauntlet(body: GauntletBody, svc: LedgerService = Depends(svc_dep)) -> dict:
        inbox = Path(cfg.inbox).resolve()
        target = (inbox / body.results_path).resolve()
        if inbox not in target.parents:
            raise HTTPException(400, f"results_path must be inside the inbox directory ({inbox})")
        return guard(lambda: svc.collect_gauntlet(str(target)))

    @app.post("/collect/synthetic", dependencies=[Depends(require_key)])
    def collect_synthetic(body: SyntheticBody = SyntheticBody(),
                          svc: LedgerService = Depends(svc_dep)) -> dict:
        return guard(lambda: svc.collect_synthetic(body.count, body.kind))

    @app.post("/anchor-now", dependencies=[Depends(require_key)])
    def anchor_now(svc: LedgerService = Depends(svc_dep)) -> dict:
        results = guard(svc.anchor_now)
        return {"anchored": [r.to_dict() for r in results]}

    @app.get("/records/{record_id}")
    def get_record(record_id: int, svc: LedgerService = Depends(svc_dep)) -> dict:
        return guard(lambda: svc.record(record_id))

    @app.get("/records/{record_id}/proof")
    def get_proof(record_id: int, svc: LedgerService = Depends(svc_dep)) -> dict:
        return guard(lambda: svc.proof(record_id))

    @app.get("/verify/batch/{batch_id}")
    def verify_batch(batch_id: int, full: bool = Query(False),
                     svc: LedgerService = Depends(svc_dep)) -> dict:
        return guard(lambda: svc.verify_batch(batch_id, use_source=full).to_dict())

    @app.get("/verify/{record_id}")
    def verify_record(record_id: int, use_source: bool = Query(True),
                      svc: LedgerService = Depends(svc_dep)) -> dict:
        return guard(lambda: svc.verify_record(record_id, use_source=use_source).to_dict())

    @app.get("/batches")
    def list_batches(limit: int = Query(20, ge=1, le=200),
                     svc: LedgerService = Depends(svc_dep)) -> list:
        return svc.batches(limit)

    @app.get("/batches/{batch_id}")
    def get_batch(batch_id: int, svc: LedgerService = Depends(svc_dep)) -> dict:
        return guard(lambda: svc.batch_dict(batch_id))

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        return HTMLResponse(render_dashboard())

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/dashboard")

    return app
