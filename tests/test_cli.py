import json

import pytest
from click.testing import CliRunner

import ledger.cli as cli
from ledger.demo import tamper_index_record
from tests.fakes import FakeChain


@pytest.fixture
def env(tmp_path, monkeypatch):
    fake = FakeChain()
    monkeypatch.setattr(cli, "make_chain", lambda cfg: fake)
    return {"LEDGER_DATA_DIR": str(tmp_path), "LEDGER_BATCH_SIZE": "100"}, fake, tmp_path


def run(env_vars, *args):
    return CliRunner().invoke(cli.main, list(args), env=env_vars)


def test_help_and_version():
    r = CliRunner().invoke(cli.main, ["--help"])
    assert r.exit_code == 0 and "anchor-now" in r.output and "verify" in r.output
    assert CliRunner().invoke(cli.main, ["--version"]).exit_code == 0


def test_bad_config_is_a_clean_error(tmp_path):
    r = run({"LEDGER_BATCH_SIZE": "0", "LEDGER_DATA_DIR": str(tmp_path)}, "status")
    assert r.exit_code != 0 and "configuration error" in r.output


def test_full_flow_collect_anchor_verify(env):
    e, fake, tmp = env
    assert run(e, "collect-synthetic", "--count", "12").exit_code == 0
    r = run(e, "anchor-now")
    assert r.exit_code == 0 and "merkle_root" in r.output
    assert run(e, "verify", "--batch", "1").exit_code == 0
    assert run(e, "verify", "--record", "3").exit_code == 0
    assert run(e, "verify", "--batch", "1", "--full").exit_code == 0
    st = json.loads(run(e, "status").output)
    assert st["pending"] == 0 and st["anchored"] == 12 and st["chain"]["connected"]


def test_verify_exit_codes_for_tamper_and_unreachable(env):
    e, fake, tmp = env
    run(e, "collect-synthetic", "--count", "10")
    run(e, "anchor-now")
    tamper_index_record(str(tmp / "ledger.db"), 4)
    r = run(e, "verify", "--batch", "1")
    assert r.exit_code == 1 and "TAMPER DETECTED" in r.output
    out = run(e, "verify", "--record", "4", "--json")
    assert json.loads(out.output)["status"] == "tamper_detected"
    fake.connected = False
    assert run(e, "verify", "--batch", "1").exit_code == 2


def test_verify_with_supplied_records_and_json_out(env):
    e, fake, tmp = env
    col = json.loads(run(e, "collect-synthetic", "--count", "6").output)
    run(e, "anchor-now")
    out = tmp / "verdict.json"
    r = run(e, "verify", "--batch", "1", "--records", col["snapshot"], "--json-out", str(out))
    assert r.exit_code == 0 and json.loads(out.read_text())["status"] == "verified"
    missing = run(e, "verify", "--batch", "1", "--records", str(tmp / "nope.json"))
    assert missing.exit_code != 0 and "cannot read" in missing.output


def test_verify_argument_validation(env):
    e, *_ = env
    assert run(e, "verify").exit_code == 2
    assert run(e, "verify", "--record", "1", "--batch", "1").exit_code == 2
    r = run(e, "verify", "--record", "999")
    assert r.exit_code != 0 and "not found" in r.output


def test_anchor_now_with_nothing_pending_and_on_failure(env):
    e, fake, _ = env
    assert "Nothing pending" in run(e, "anchor-now").output
    run(e, "collect-synthetic", "--count", "3")
    fake.fail_next_anchor = True
    r = run(e, "anchor-now")
    assert r.exit_code != 0 and "simulated" in r.output


def test_record_proof_batch_commands(env):
    e, *_ = env
    run(e, "collect-synthetic", "--count", "5")
    assert run(e, "proof", "1").exit_code != 0  # not anchored yet
    run(e, "anchor-now")
    rec = json.loads(run(e, "record", "2").output)
    assert rec["status"] == "anchored" and rec["batch"]["record_count"] == 5
    proof = json.loads(run(e, "proof", "2").output)
    assert proof["recomputed_root"] == proof["merkle_root"]
    assert json.loads(run(e, "batch", "1").output)["record_count"] == 5
    assert len(json.loads(run(e, "batch").output)) == 1
    assert run(e, "record", "99").exit_code != 0 and run(e, "batch", "99").exit_code != 0


def test_collect_commands_degrade_gracefully(env):
    e, _, tmp = env
    r = run(e, "collect-aegis")
    assert r.exit_code != 0 and "no Aegis database URL" in r.output
    r = run(e, "collect-aegis", "--db-url", f"sqlite:///{tmp}/missing.db")
    assert r.exit_code == 3 and "not reachable" in r.output
    r = run(e, "collect-gauntlet", "--results", str(tmp / "missing.json"))
    assert r.exit_code == 3
    bad = tmp / "bad.json"
    bad.write_text("nope")
    assert run(e, "collect-gauntlet", "--results", str(bad)).exit_code != 0


def test_collect_gauntlet_and_aegis_happy_paths(env):
    e, _, tmp = env
    from ledger.fixtures.synthetic import make_gauntlet_report
    g = tmp / "results.json"
    g.write_text(json.dumps(make_gauntlet_report(3)))
    out = json.loads(run(e, "collect-gauntlet", "--results", str(g)).output)
    assert out["findings"] == 3
    from tests.test_collector import make_aegis_sqlite
    from ledger.fixtures.synthetic import make_aegis_rows
    make_aegis_sqlite(tmp / "a.db", make_aegis_rows(4))
    out = json.loads(run(e, "collect-aegis", "--db-url", f"sqlite:///{tmp}/a.db").output)
    assert out["inserted"] == 4
    assert run(e, "anchor-now").exit_code == 0
    assert run(e, "verify", "--record", "1").exit_code == 0


def test_demo_command_passes_on_a_chain(env):
    e, *_ = env
    r = run(e, "demo", "--count", "10")
    assert r.exit_code == 0 and "DEMO PASSED" in r.output and "TAMPER" in r.output


def test_eval_merkle_only_writes_results(env):
    e, _, tmp = env
    out = tmp / "res"
    r = run(e, "eval", "--merkle-only", "--sizes", "1,5", "--out", str(out))
    assert r.exit_code == 0 and (out / "merkle_bench.json").exists() and (out / "merkle_bench.md").exists()
    assert run(e, "eval", "--sizes", "x").exit_code != 0
    assert run(e, "eval", "--sizes", "0").exit_code != 0


def test_eval_against_chain_writes_gas_table(env):
    e, _, tmp = env
    out = tmp / "res2"
    r = run(e, "eval", "--sizes", "1,10", "--out", str(out))
    assert r.exit_code == 0
    report = json.loads((out / "eval.json").read_text())
    assert [row["records"] for row in report["chain"]] == [1, 10]
    md = (out / "eval.md").read_text()
    assert "Illustrative cost" in md and "not a live price feed" in md


def test_chain_unreachable_for_demo_and_eval(tmp_path, monkeypatch):
    fake = FakeChain()
    fake.connected = False
    monkeypatch.setattr(cli, "make_chain", lambda cfg: fake)
    e = {"LEDGER_DATA_DIR": str(tmp_path)}
    assert run(e, "demo").exit_code != 0
    assert run(e, "eval", "--sizes", "1", "--out", str(tmp_path / "o")).exit_code != 0
