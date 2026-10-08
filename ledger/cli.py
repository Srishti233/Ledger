"""Command-line interface (click). Mirrors the HTTP API, plus deploy/demo/eval/serve."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .anchorer import AnchorError
from .chain import ChainError, ensure_deployment, make_chain, read_deployment
from .collector import collect_aegis as _collect_aegis
from .collector import collect_gauntlet as _collect_gauntlet
from .collector import collect_synthetic as _collect_synthetic
from .config import Config, ConfigError, load_config
from .demo import run_demo
from .evaluation import run_eval
from .service import LedgerService
from .sources import BYPASS_KEYS, SourceUnavailable, source_from_path
from .store import Index, archive_stale_index


def _emit(obj) -> None:
    click.echo(json.dumps(obj, indent=2, default=str))


def _service(cfg: Config) -> LedgerService:
    return LedgerService(cfg, Index(cfg.database), make_chain(cfg))


@click.group(name="ledger", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "config_path", type=click.Path(), default=None,
              help="YAML config file (or set LEDGER_CONFIG). LEDGER_* env vars override it.")
@click.version_option(__version__, prog_name="ledger")
@click.pass_context
def main(ctx: click.Context, config_path: Optional[str]) -> None:
    """Ledger: anchor Aegis audit logs and Gauntlet reports on a (local) blockchain."""
    try:
        ctx.obj = load_config(config_path)
    except ConfigError as exc:
        raise click.ClickException(f"configuration error: {exc}")


@main.command()
@click.pass_obj
def deploy(cfg: Config) -> None:
    """Deploy AuditAnchor (or reuse an existing deployment) and allowlist the anchoring key."""
    had_prior = read_deployment(cfg) is not None
    try:
        dep, fresh = ensure_deployment(cfg)
    except (ChainError, ConfigError) as exc:
        raise click.ClickException(str(exc))
    click.echo(("Deployed" if fresh else "Reusing existing deployment of") +
               f" AuditAnchor at {dep['contract_address']}")
    if fresh and had_prior and cfg.is_local_chain() and not cfg.contract_address:
        moved = archive_stale_index(cfg.database)
        if moved:
            click.echo("The local chain was reset since the last run, so the old index no longer "
                       f"matches it. Archived (not deleted) to {moved}", err=True)


@main.command("collect-aegis")
@click.option("--db-url", default=None, help="Aegis Postgres URL (read-only); sqlite:///file also works.")
@click.option("--limit", type=int, default=None)
@click.pass_obj
def collect_aegis_cmd(cfg: Config, db_url: Optional[str], limit: Optional[int]) -> None:
    """Read new rows from Aegis's audit_events table (read-only) into the pending queue."""
    url = db_url or cfg.aegis_db_url
    if not url:
        raise click.ClickException("no Aegis database URL: pass --db-url or set aegis_db_url")
    try:
        _emit(_collect_aegis(Index(cfg.database), url, limit))
    except SourceUnavailable as exc:
        click.echo(f"Aegis is not reachable, nothing collected: {exc}", err=True)
        sys.exit(3)


@main.command("collect-gauntlet")
@click.option("--results", "results", required=True, type=click.Path(), help="Gauntlet results.json")
@click.option("--bypass-key", "bypass_keys", multiple=True,
              help=f"JSON key holding bypass findings (repeatable). Default: {', '.join(BYPASS_KEYS)}")
@click.pass_obj
def collect_gauntlet_cmd(cfg: Config, results: str, bypass_keys: tuple[str, ...]) -> None:
    """Hash a Gauntlet results file and each bypass finding into the pending queue."""
    try:
        _emit(_collect_gauntlet(Index(cfg.database), results, cfg.source_dir,
                                bypass_keys=list(bypass_keys) or BYPASS_KEYS))
    except SourceUnavailable as exc:
        click.echo(f"Gauntlet results not available, nothing collected: {exc}", err=True)
        sys.exit(3)
    except ValueError as exc:
        raise click.ClickException(str(exc))


@main.command("collect-synthetic")
@click.option("--count", type=click.IntRange(min=1), default=25, show_default=True)
@click.option("--kind", type=click.Choice(["aegis", "gauntlet"]), default="aegis", show_default=True)
@click.option("--seed", type=int, default=1, show_default=True)
@click.pass_obj
def collect_synthetic_cmd(cfg: Config, count: int, kind: str, seed: int) -> None:
    """Generate synthetic fixture records (tagged source=synthetic) into the pending queue."""
    _emit(_collect_synthetic(Index(cfg.database), count, cfg.source_dir, kind, seed))


@main.command("anchor-now")
@click.pass_obj
def anchor_now(cfg: Config) -> None:
    """Anchor every pending record now (one batch per source, chunked by batch_size)."""
    svc = _service(cfg)
    try:
        results = svc.anchor_now()
    except (AnchorError, ChainError) as exc:
        raise click.ClickException(str(exc))
    if not results:
        click.echo("Nothing pending.")
    _emit([r.to_dict() for r in results])


@main.command()
@click.option("--record", "record_id", type=int, help="Verify one record.")
@click.option("--batch", "batch_id", type=int, help="Verify a whole batch.")
@click.option("--records", "records_path", type=click.Path(), default=None,
              help="Supply the source data (audit-table export or results.json) to re-hash.")
@click.option("--full", is_flag=True, help="Batch mode: re-fetch every record from its stored source.")
@click.option("--no-source", is_flag=True, help="Record mode: skip re-checking source data.")
@click.option("--json", "as_json", is_flag=True, help="Print only the JSON verdict.")
@click.option("--json-out", type=click.Path(), default=None, help="Also write the JSON verdict here.")
@click.pass_obj
def verify(cfg: Config, record_id, batch_id, records_path, full, no_source, as_json, json_out) -> None:
    """Verify a record or batch against the live chain. Exit: 0 verified, 1 tamper, 2 inconclusive."""
    if (record_id is None) == (batch_id is None):
        raise click.UsageError("give exactly one of --record or --batch")
    svc = _service(cfg)
    try:
        source = source_from_path(records_path) if records_path else None
        if record_id is not None:
            verdict = svc.verify_record(record_id, source, use_source=not no_source)
        else:
            verdict = svc.verify_batch(batch_id, source, use_source=full)
    except LookupError as exc:
        raise click.ClickException(str(exc))
    except SourceUnavailable as exc:
        raise click.ClickException(f"cannot read supplied source data: {exc}")
    if json_out:
        Path(json_out).write_text(json.dumps(verdict.to_dict(), indent=2))
    click.echo(json.dumps(verdict.to_dict(), indent=2) if as_json else verdict.render_text())
    sys.exit(verdict.exit_code)


@main.command()
@click.pass_obj
def status(cfg: Config) -> None:
    """Pending count, last anchor time, chain connectivity."""
    _emit(_service(cfg).status())


@main.command("record")
@click.argument("record_id", type=int)
@click.pass_obj
def record_cmd(cfg: Config, record_id: int) -> None:
    """Show one record and where it was anchored."""
    try:
        _emit(_service(cfg).record(record_id))
    except LookupError as exc:
        raise click.ClickException(str(exc))


@main.command("proof")
@click.argument("record_id", type=int)
@click.pass_obj
def proof_cmd(cfg: Config, record_id: int) -> None:
    """Print a record's Merkle inclusion proof (checkable offline against the on-chain root)."""
    try:
        _emit(_service(cfg).proof(record_id))
    except LookupError as exc:
        raise click.ClickException(str(exc))


@main.command("batch")
@click.argument("batch_id", type=int, required=False)
@click.option("--limit", type=int, default=20)
@click.pass_obj
def batch_cmd(cfg: Config, batch_id: Optional[int], limit: int) -> None:
    """Show one batch (by local id) or list recent batches."""
    svc = _service(cfg)
    try:
        _emit(svc.batch_dict(batch_id) if batch_id else svc.batches(limit))
    except LookupError as exc:
        raise click.ClickException(str(exc))


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", type=int, default=8000, show_default=True)
@click.pass_obj
def serve(cfg: Config, host: str, port: int) -> None:
    """Run the HTTP API and dashboard."""
    import uvicorn

    from .api import create_app

    uvicorn.run(create_app(cfg), host=host, port=port, log_level="info")


@main.command()
@click.option("--count", type=click.IntRange(min=2), default=25, show_default=True)
@click.pass_obj
def demo(cfg: Config, count: int) -> None:
    """Run the end-to-end tamper-detection demo against the configured chain."""
    try:
        chain = make_chain(cfg)
    except (ChainError, ConfigError) as exc:
        raise click.ClickException(str(exc))
    if not chain.is_connected():
        raise click.ClickException(f"cannot reach the chain at {cfg.rpc_url}")
    result = run_demo(cfg, chain, count=count, out=click.echo)
    sys.exit(0 if result["ok"] else 1)


@main.command("eval")
@click.option("--sizes", default="1,10,100,1000", show_default=True, help="Comma-separated batch sizes.")
@click.option("--out", "out_dir", default="results", show_default=True)
@click.option("--merkle-only", is_flag=True, help="Only time the pure-Python Merkle code (no chain).")
@click.pass_obj
def eval_cmd(cfg: Config, sizes: str, out_dir: str, merkle_only: bool) -> None:
    """Measure gas and timings across batch sizes and write results/."""
    try:
        size_list = [int(x) for x in sizes.split(",") if x.strip()]
    except ValueError:
        raise click.BadParameter("sizes must be comma-separated integers")
    if not size_list or min(size_list) < 1:
        raise click.BadParameter("sizes must be positive integers")
    chain = None
    if not merkle_only:
        try:
            chain = make_chain(cfg)
        except (ChainError, ConfigError) as exc:
            raise click.ClickException(str(exc))
        if not chain.is_connected():
            raise click.ClickException(f"cannot reach the chain at {cfg.rpc_url}")
    report = run_eval(cfg, chain, size_list, out_dir)
    click.echo(json.dumps(report["chain"] or report["merkle"], indent=2))
    click.echo(f"Wrote results to {out_dir}/")


if __name__ == "__main__":  # pragma: no cover
    main()
