"""SECLAB macOS#4 / Pentest#7 (node side) — the daemon self-reports the
security-relevant SELF-OVERRIDES it is running with, so the backend is no longer
blind to a node persistently running with signature / anti-rollback checks off.

_security_flags() reads the daemon's OWN live environment and reports ONLY the
flags that are active; a clean node reports {}.
"""
from meshembed_node import worker


_FLAG_ENVS = ("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "MESHEMBED_ALLOW_DOWNGRADE")


def _clear(monkeypatch):
    for k in _FLAG_ENVS:
        monkeypatch.delenv(k, raising=False)


def test_clean_node_reports_empty(monkeypatch):
    _clear(monkeypatch)
    assert worker._security_flags() == {}


def test_unsigned_installer_flag_reported(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "1")
    assert worker._security_flags() == {"allow_unsigned_installer": True}


def test_downgrade_flag_reported(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MESHEMBED_ALLOW_DOWNGRADE", "1")
    assert worker._security_flags() == {"allow_downgrade": True}


def test_both_flags_reported(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "1")
    monkeypatch.setenv("MESHEMBED_ALLOW_DOWNGRADE", "1")
    assert worker._security_flags() == {
        "allow_unsigned_installer": True,
        "allow_downgrade": True,
    }


def test_non_one_value_is_not_active(monkeypatch):
    # Only the exact "1" convention (matching the daemon's own gates) counts.
    _clear(monkeypatch)
    monkeypatch.setenv("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "0")
    monkeypatch.setenv("MESHEMBED_ALLOW_DOWNGRADE", "true")
    assert worker._security_flags() == {}


def test_flags_included_in_register_payload(monkeypatch):
    """The register payload carries security_flags so the backend actually
    receives the signal (regression guard against it being dropped)."""
    _clear(monkeypatch)
    monkeypatch.setenv("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "1")
    # Build just the payload dict the way _register does, via the public helper.
    # A full _register() call needs network; asserting the helper is wired into
    # the payload is done by checking the source references it.
    import inspect
    src = inspect.getsource(worker._register)
    assert '"security_flags": _security_flags()' in src
