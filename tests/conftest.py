import os
import socket
import pytest
from pathlib import Path

# Static test fernet key for reproducible offline testing
TEST_FERNET_KEY = "1F0p9ZLeH9-uwmxReOo_5Q7E4otPlwEiFJ2eKpKb7yY="


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Sets deterministic environment variables for tests."""
    monkeypatch.setenv("AEGIS_REPLAY_KEY", os.getenv("AEGIS_REPLAY_KEY", TEST_FERNET_KEY))
    if "AEGIS_AUTH_DISABLED" not in os.environ:
        monkeypatch.setenv("AEGIS_AUTH_DISABLED", "1")
    if "AEGIS_PAYLOAD_SALT" not in os.environ:
        monkeypatch.setenv("AEGIS_PAYLOAD_SALT", "test_salt_deterministic_conftest")


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Blocks real socket connections across all tests to guarantee offline execution."""
    def guarded_connect(self, *args, **kwargs):
        raise RuntimeError(f"Network access disabled during tests: attempted connect with args={args}")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


@pytest.fixture(autouse=True)
def redirect_data_directories(tmp_path, monkeypatch):
    """Redirects all data directories and persistent storage sinks to tmp_path."""
    test_data_dir = tmp_path / "data"
    test_dlq_dir = test_data_dir / "dlq"
    test_clean_sink = test_data_dir / "clean_events.jsonl"
    test_replay_db = test_data_dir / "replay_state.db"

    test_dlq_dir.mkdir(parents=True, exist_ok=True)

    import src.edge.gateway as gateway_mod
    import src.edge.dlq_router as dlq_mod
    import src.edge.replay as replay_mod

    # Redirect gateway instances
    test_router = dlq_mod.QuarantineDLQRouter(dlq_dir=str(test_dlq_dir))
    monkeypatch.setattr(gateway_mod, "DLQ_ROUTER", test_router)
    monkeypatch.setattr(gateway_mod, "CLEAN_SINK_FILE", test_clean_sink)
