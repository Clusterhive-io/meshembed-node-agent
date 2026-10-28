"""AR1 G9: the daemon starts the agent-host duty ONLY with the flag, on a designated host (a signed policy for THIS
node and pool), with a lane key and a socket directory owned by the daemon, group mesh-agent, 0750 (auditor 13:58Z)."""
import json
import os
import threading
import types
from pathlib import Path

import pytest

from meshembed_node import agent_daemon as D
from meshembed_node import agent_host as A

GOLD = json.loads((Path(__file__).parent / "fixtures" / "run_ticket_golden.json").read_text())
ADMIN = {GOLD["keys"]["admin"]["kid"]: GOLD["keys"]["admin"]["pub"]}
NODE, TENANT = "agent-host-1", "t-pool-1"
KEY = "meah_" + "k" * 43


CFG = None


@pytest.fixture
def host(tmp_path, monkeypatch):
    """The host config in a tmp dir: root ownership is simulated by treating OUR uid as 0 in the ownership check
    (W1); test_w1_* checks the real rule against a daemon-owned file."""
    global CFG
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    etc = tmp_path / "etc-meshembed-agent"
    etc.mkdir(mode=0o750)
    CFG = etc / "host.json"
    CFG.write_text(json.dumps({"tenant": TENANT, "admin_keys": ADMIN, "policy": GOLD["policy_personal"]}))
    os.chmod(CFG, 0o640)
    real_stat = Path.stat

    def as_root(self, *a, **k):
        st = real_stat(self, *a, **k)
        if str(self).startswith(str(etc)):
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0, st.st_gid, st.st_size,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        return st
    monkeypatch.setattr(Path, "stat", as_root)
    (home / "agent-lane.key").write_text(KEY)
    os.chmod(home / "agent-lane.key", 0o600)
    sock = tmp_path / "run"
    sock.mkdir()
    os.chmod(sock, 0o750)
    monkeypatch.setattr(D.pwd, "getpwnam", lambda n: types.SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(D.grp, "getgrnam", lambda n: types.SimpleNamespace(gr_gid=os.getgid()))
    return home, sock


ON = {"MESHEMBED_AGENT_HOST": "1"}


def test_preflight_ok(host):
    home, sock = host
    settings, reason = D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)
    assert reason == "ok" and settings["tenant"] == TENANT and settings["agent_uid"] == os.getuid()


def test_off_by_default_and_linux_only(host):
    home, sock = host
    assert D.preflight({}, home, NODE, sock, platform="linux", host_config=CFG)[1] == "agent_host_off"
    assert D.preflight({"MESHEMBED_AGENT_HOST": "true"}, home, NODE, sock, platform="linux", host_config=CFG)[1] == "agent_host_off"
    assert D.preflight(ON, home, NODE, sock, platform="win32", host_config=CFG)[1] == "agent_host_linux_only"


def test_no_mesh_agent_user(host, monkeypatch):
    home, sock = host

    def missing(n):
        raise KeyError(n)
    monkeypatch.setattr(D.pwd, "getpwnam", missing)
    assert D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)[1] == "agent_user_missing"


@pytest.mark.parametrize("mutate,reason", [
    (lambda c: c.pop("policy"), "agent_host_config_missing"),
    (lambda c: c.update(admin_keys={}), "agent_host_config_missing"),
    (lambda c: c.update(policy={"mode": "personal", "owner": "u"}), "agent_host_not_designated"),   # unsigned
    (lambda c: c.update(policy=GOLD["policy_signed_by_ticket_key"]), "agent_host_not_designated"),
    (lambda c: c.update(tenant="t-pool-2"), "agent_host_not_designated"),          # signed for another pool
])
def test_only_a_designated_host_starts(host, mutate, reason):
    home, sock = host
    c = json.loads(CFG.read_text())
    mutate(c)
    CFG.write_text(json.dumps(c))
    assert D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)[1] == reason


def test_policy_for_another_node_is_not_a_designation(host):
    home, sock = host
    assert D.preflight(ON, home, "agent-host-2", sock, platform="linux", host_config=CFG)[1] == "agent_host_not_designated"


@pytest.mark.parametrize("mode", [0o660, 0o646, 0o662])
def test_w1_host_config_writable_by_others_is_refused(host, mode):
    home, sock = host
    os.chmod(CFG, mode)
    assert D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)[1] == "agent_host_config_missing"


def test_w1_a_daemon_owned_host_config_is_refused(host, monkeypatch, tmp_path):
    """W1: not root-owned (the real ownership check, no simulation) -> refused."""
    home, sock = host
    mine = tmp_path / "mine"
    mine.mkdir(mode=0o750)
    (mine / "host.json").write_text(CFG.read_text())
    os.chmod(mine / "host.json", 0o640)
    assert D.preflight(ON, home, NODE, sock, platform="linux", host_config=mine / "host.json")[1] == \
        "agent_host_config_missing"


def test_lane_key_must_be_private(host):
    home, sock = host
    os.chmod(home / "agent-lane.key", 0o640)
    assert D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)[1] == "agent_lane_key_missing"


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o700, 0o710])
def test_socket_dir_must_be_0750_group_mesh_agent(host, mode):
    home, sock = host
    os.chmod(sock, mode)
    assert D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)[1] == "agent_socket_dir_unsafe"


def test_socket_dir_wrong_group(host, monkeypatch):
    home, sock = host
    monkeypatch.setattr(D.grp, "getgrnam", lambda n: types.SimpleNamespace(gr_gid=os.getgid() + 1))
    assert D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)[1] == "agent_socket_dir_unsafe"
    assert D.preflight(ON, home, NODE, sock / "missing", platform="linux", host_config=CFG)[1] == "agent_socket_dir_missing"


def _bridge(host):
    home, sock = host
    settings, _ = D.preflight(ON, home, NODE, sock, platform="linux", host_config=CFG)
    calls = []
    b = D.make_bridge(NODE, settings, home, lambda p, j, h, t: (calls.append((p, j, h)) or (200, {})))
    return b, calls


def test_intake_and_revocations(host):
    b, calls = _bridge(host)
    assert D.intake_once(b, lambda p, j, t: (204, None), NODE) == "idle"
    assert D.intake_once(b, lambda p, j, t: (500, None), NODE) == "poll_failed"

    def boom(*a):
        raise OSError("down")
    assert D.intake_once(b, boom, NODE) == "poll_failed"
    assert D.refresh_revocations(b, lambda p, t: (200, {"definitions": [["a", 1]], "tickets": ["rt-x"]}), NODE) == "ok"
    assert ("a", 1) in b.ctx["revocations"].load(__import__("time").time())["definitions"]
    for bad in ({"definitions": [["a", True]], "tickets": []}, {"definitions": "x", "tickets": []}, None):
        assert D.refresh_revocations(b, lambda p, t: (200, bad), NODE) == "fetch_failed"
    assert D.refresh_revocations(b, boom, NODE) == "fetch_failed"


def test_start_end_to_end_over_the_socket(host):
    home, sock = host
    stop = threading.Event()
    try:
        assert D.start(NODE, ON, home, node_post=lambda p, j, t: (204, None),
                       node_get=lambda p, t: (200, {"definitions": [], "tickets": []}),
                       lane_post=lambda *a: (200, {}), stop=stop, socket_dir=sock, host_config=CFG) == "ok"
        assert A.BridgeClient(str(sock / "agent.sock"), timeout=5).call("next_run") == {"code": "no_run"}
    finally:
        stop.set()
    assert D.start(NODE, {}, home, node_post=None, node_get=None, lane_post=None, stop=stop,
                   socket_dir=sock, host_config=CFG) == "agent_host_off"


def test_worker_starts_nothing_by_default(monkeypatch):
    from meshembed_node import worker
    monkeypatch.delenv("MESHEMBED_AGENT_HOST", raising=False)
    cfg = types.SimpleNamespace(backend_url="http://x", api_key="k", node_id="n")
    assert worker._start_agent_host(cfg) == "agent_host_off"
