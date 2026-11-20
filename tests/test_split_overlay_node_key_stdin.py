"""WG-STDIN: configure() gives the WireGuard private key to `wg set` on STDIN, never as a path the confined `wg` must open
(Ubuntu 26.04 AppArmor profile "wg" denies /etc/meshembed-node/wg/private.key, 2026-11-19), and never in argv, env or a log."""
import os
import stat

import pytest

from meshembed_node import split_overlay_node as O

ME, PEER = "node-me", "node-peer"
OWN_PUB = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
PEER_PUB = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
KEY = b"KEY-BYTES-THAT-MUST-NEVER-BE-IN-ARGV\n"


def _body():
    return {"members": [
        {"node_id": ME, "overlay_ip": "10.44.0.10", "wg_pubkey": OWN_PUB, "endpoint": None},
        {"node_id": PEER, "overlay_ip": "10.44.0.11", "wg_pubkey": PEER_PUB, "endpoint": "192.168.30.153:51820"},
    ]}


def _dir(tmp_path, mode=0o600):
    d = tmp_path / "wg"
    d.mkdir(mode=0o700)
    k = d / "private.key"
    k.write_bytes(KEY)
    os.chmod(k, mode)
    return d


def _recorder():
    calls = []

    def run(argv, stdin=None):
        calls.append((tuple(argv), stdin))
        return b""
    return calls, run


def test_wg_set_gets_the_key_on_stdin_and_a_stdin_path_not_the_key_file(tmp_path):
    d = _dir(tmp_path)
    calls, run = _recorder()
    O.configure(_body(), ME, OWN_PUB, wg_dir=d, runner=run, owner_uid=os.getuid())
    wgset = [c for c in calls if c[0][:2] == ("wg", "set")]
    assert len(wgset) == 1
    argv, stdin = wgset[0]
    assert argv[:4] == ("wg", "set", "meshdi0", "private-key") and argv[4] == "/dev/stdin"
    assert stdin == KEY                                            # the key travels on stdin only
    assert str(d / "private.key") not in " ".join(argv)           # the confined wg is never pointed at the key file
    assert KEY.decode().strip() not in " ".join(" ".join(c[0]) for c in calls)   # and the key is in no argv
    assert all(c[1] is None for c in calls if c is not wgset[0])  # no other command gets stdin


def test_a_key_file_readable_by_group_or_others_is_refused_before_anything_is_configured(tmp_path):
    d = _dir(tmp_path, mode=0o640)
    calls, run = _recorder()
    with pytest.raises(O.Refused, match="wg_private_key_permissions"):
        O.configure(_body(), ME, OWN_PUB, wg_dir=d, runner=run, owner_uid=os.getuid())
    assert not any(c[0][:2] == ("wg", "set") for c in calls)


def test_the_peer_arguments_and_the_netns_prefix_are_unchanged(tmp_path):
    d = _dir(tmp_path)
    calls, run = _recorder()
    out = O.configure(_body(), ME, OWN_PUB, wg_dir=d, runner=run, netns="ns1", owner_uid=os.getuid())
    wgset = next(c for c in calls if "wg" in c[0] and "set" in c[0])
    argv = wgset[0]
    assert argv[:5] == ("ip", "netns", "exec", "ns1", "wg")
    assert "peer" in argv and PEER_PUB in argv and "10.44.0.11/32" in argv and "192.168.30.153:51820" in argv
    assert out["own_ip"] == "10.44.0.10" and out["peers"] == ["10.44.0.11"]


def test_a_symlinked_key_is_never_followed(tmp_path):
    d = _dir(tmp_path)
    real = tmp_path / "elsewhere.key"
    real.write_bytes(KEY)
    os.chmod(real, 0o600)
    (d / "private.key").unlink()
    (d / "private.key").symlink_to(real)                             # O_NOFOLLOW: refused, not read
    calls, run = _recorder()
    with pytest.raises(O.Refused, match="wg_private_key_permissions"):
        O.configure(_body(), ME, OWN_PUB, wg_dir=d, runner=run, owner_uid=os.getuid())
    assert calls == []
    with pytest.raises(O.Refused, match="wg_private_key_permissions"):
        O.ensure_key(d, runner=run, owner_uid=os.getuid())


def test_a_key_owned_by_someone_else_is_refused_both_in_configure_and_ensure_key(tmp_path):
    d = _dir(tmp_path)
    calls, run = _recorder()
    other = os.getuid() + 1                                          # the default is root (0): the launcher runs as root
    with pytest.raises(O.Refused, match="wg_private_key_permissions"):
        O.configure(_body(), ME, OWN_PUB, wg_dir=d, runner=run, owner_uid=other)
    with pytest.raises(O.Refused, match="wg_private_key_permissions"):
        O.ensure_key(d, runner=run, owner_uid=other)
    assert calls == []


def test_ensure_key_hands_wg_pubkey_the_key_on_stdin_from_the_checked_fd(tmp_path):
    d = _dir(tmp_path)
    seen = []

    def run(argv, stdin=None):
        seen.append((tuple(argv), stdin))
        return (PUB + "\n").encode()
    PUB_ = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    globals()["PUB"] = PUB_
    assert O.ensure_key(d, runner=run, owner_uid=os.getuid()) == PUB_
    assert seen == [(("wg", "pubkey"), KEY)]
