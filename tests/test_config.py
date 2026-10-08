import pytest

from ledger.config import ANVIL_TEST_KEY_ANCHORER, Config, ConfigError, load_config

GOOD_KEY = "0x" + "12" * 32


def test_defaults_are_local_and_valid():
    c = load_config(env={})
    assert c.is_local_chain() and c.confirmations == 1 and c.batch_size == 100


def test_env_overrides_and_coercion():
    c = load_config(env={"LEDGER_BATCH_SIZE": "7", "LEDGER_CONFIRMATIONS": "3",
                         "LEDGER_RPC_URL": "http://chain:8545"})
    assert (c.batch_size, c.confirmations, c.rpc_url) == (7, 3, "http://chain:8545")


def test_yaml_file_then_env_wins(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("batch_size: 5\nmax_wait_seconds: 9\n")
    assert load_config(f, env={}).batch_size == 5
    assert load_config(f, env={"LEDGER_BATCH_SIZE": "6"}).batch_size == 6
    assert load_config(env={"LEDGER_CONFIG": str(f)}).max_wait_seconds == 9


def test_bad_config_files(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml", env={})
    f = tmp_path / "list.yaml"
    f.write_text("- 1\n- 2\n")
    with pytest.raises(ConfigError):
        load_config(f, env={})
    g = tmp_path / "unk.yaml"
    g.write_text("nope: 1\n")
    with pytest.raises(ConfigError, match="unknown"):
        load_config(g, env={})


@pytest.mark.parametrize("env", [
    {"LEDGER_BATCH_SIZE": "0"},
    {"LEDGER_CONFIRMATIONS": "0"},
    {"LEDGER_BATCH_SIZE": "abc"},
    {"LEDGER_RPC_URL": "ftp://localhost"},
    {"LEDGER_PRIVATE_KEY": "0x1234"},
    {"LEDGER_CONTRACT_ADDRESS": "0x12"},
    {"LEDGER_MAX_WAIT_SECONDS": "-1"},
    {"LEDGER_TX_TIMEOUT_SECONDS": "0"},
])
def test_invalid_values_rejected(env):
    with pytest.raises(ConfigError):
        load_config(env=env)


def test_non_local_chain_requires_explicit_opt_in():
    with pytest.raises(ConfigError, match="not a local host"):
        load_config(env={"LEDGER_RPC_URL": "https://rpc.example.org"})


def test_test_keys_refused_on_non_local_chain():
    env = {"LEDGER_RPC_URL": "https://rpc.example.org", "LEDGER_ALLOW_NON_LOCAL_CHAIN": "true"}
    with pytest.raises(ConfigError, match="well-known"):
        load_config(env=env)
    ok = dict(env, LEDGER_PRIVATE_KEY=GOOD_KEY, LEDGER_DEPLOYER_PRIVATE_KEY="0x" + "34" * 32)
    assert not load_config(env=ok).is_local_chain()


def test_derived_paths():
    c = Config(data_dir="/x")
    assert c.database == "/x/ledger.db" and c.deployment_file == "/x/deployment.json"
    assert c.inbox == "/x/inbox" and c.source_dir == "/x/source"
    assert Config(data_dir="/x", db_path="/y.db", inbox_dir="/in").database == "/y.db"
    assert Config().private_key == ANVIL_TEST_KEY_ANCHORER
