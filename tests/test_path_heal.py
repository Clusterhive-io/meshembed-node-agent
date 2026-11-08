"""PATH-LIMIT, the heal timer (auditor 2026-11-03 13:38:41Z, HT-1..HT-4): one root oneshot heals FAILED .path units from
a fixed list; node-update.path at most once per hour; any unit healed 3 times in 24 h is stopped and reported; the counts
reach hw; the installer writes the pair hardened, and the package uninstall removes it."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from meshembed_node import path_heal as P
from meshembed_node import worker

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()
T0 = 1_800_000_000


class Host:
    def __init__(self, failed=()):
        self.failed, self.calls = set(failed), []

    def is_failed(self, u):
        return u in self.failed

    def systemctl(self, *a):
        self.calls.append(a)
        if a[0] == "start":
            self.failed.discard(a[1])


def test_ht1_only_failed_units_from_the_fixed_list_are_healed(tmp_path):
    h = Host(failed={"meshembed-split-launch.path", "something-else.path"})
    lines = P.run(tmp_path, T0, is_failed=h.is_failed, systemctl=h.systemctl)
    assert h.calls == [("reset-failed", "meshembed-split-launch.path"), ("start", "meshembed-split-launch.path")]
    assert lines == ["path_unit_healed meshembed-split-launch.path heals_24h 1"]
    assert P.run(tmp_path, T0 + 60, is_failed=Host().is_failed, systemctl=h.systemctl) == []   # healthy: nothing
    assert P.UNITS == ("meshembed-split-launch.path", "meshembed-serve-launch.path", "meshembed-node-update.path",
                       "meshembed-limits-apply.path", "meshembed-limits-reconcile.path")


def test_ht2_node_update_at_most_once_per_hour(tmp_path):
    u = "meshembed-node-update.path"
    h = Host(failed={u})
    assert P.run(tmp_path, T0, is_failed=h.is_failed, systemctl=h.systemctl)[0].startswith("path_unit_healed " + u)
    h.failed.add(u)
    assert P.run(tmp_path, T0 + 600, is_failed=h.is_failed, systemctl=h.systemctl) == [f"path_unit_heal_deferred {u}"]
    assert P.run(tmp_path, T0 + 3600, is_failed=h.is_failed, systemctl=h.systemctl)[0].startswith("path_unit_healed")
    # the negative control: split-launch has no hourly bound (it is healed every pass while failed)
    s = "meshembed-split-launch.path"
    h2 = Host(failed={s})
    P.run(tmp_path / "b", T0, is_failed=h2.is_failed, systemctl=h2.systemctl)
    h2.failed.add(s)
    assert P.run(tmp_path / "b", T0 + 600, is_failed=h2.is_failed, systemctl=h2.systemctl)[0].startswith("path_unit_healed")


def test_ht2_three_heals_in_24h_then_stopped_and_reported(tmp_path):
    s = "meshembed-split-launch.path"
    h = Host()
    for k in range(3):
        h.failed.add(s)
        assert P.run(tmp_path, T0 + 600 * k, is_failed=h.is_failed, systemctl=h.systemctl)[0].startswith("path_unit_healed")
    h.failed.add(s)
    n = len(h.calls)
    assert P.run(tmp_path, T0 + 1800, is_failed=h.is_failed, systemctl=h.systemctl) == [
        f"path_unit_heal_stopped {s} heals_24h 3"]
    assert len(h.calls) == n                                         # no systemctl call once stopped
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary[s] == {"heals_24h": 3, "stopped": True}
    assert oct((tmp_path / "heals.json").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "summary.json").stat().st_mode & 0o777) == "0o644"


def test_ht3_the_daemon_reports_the_summary_counts_and_flags_only(tmp_path):
    p = tmp_path / "summary.json"
    p.write_text(json.dumps({"meshembed-split-launch.path": {"heals_24h": 2, "stopped": False},
                             "meshembed-node-update.path": {"heals_24h": 0, "stopped": False},
                             "evil.path": {"heals_24h": 1, "stopped": True},
                             "meshembed-serve-launch.path": {"heals_24h": "3", "stopped": False}}))
    assert worker._path_heal_report(str(p)) == {"meshembed-split-launch.path": {"heals_24h": 2, "stopped": False}}
    assert worker._path_heal_report(str(tmp_path / "absent.json")) is None


def _unit(name):
    m = re.search(r"cat > /etc/systemd/system/" + re.escape(name) + r" << UNIT\n(.*?)\nUNIT\n", INSTALL, re.S)
    assert m, name
    return m.group(1)


def test_ht1_ht4_the_installer_writes_the_pair_hardened():
    svc, tmr = _unit("meshembed-path-heal.service"), _unit("meshembed-path-heal.timer")
    for line in ("LimitCORE=0", "Type=oneshot", "User=root", "NoNewPrivileges=yes", "ProtectSystem=strict",
                 "IPAddressDeny=any", "ReadWritePaths=/var/lib/meshembed-path-heal"):
        assert re.search(r"^" + re.escape(line) + r"$", svc, re.M), line
    assert re.search(r"^ExecStart=\$v/bin/python -I -m meshembed_node.path_heal$", svc, re.M)   # fixed argv
    assert "EnvironmentFile" not in svc and "Path" not in tmr.split("[Timer]")[0].replace("Description", "")
    assert re.search(r"^OnUnitActiveSec=10min$", tmr, re.M)
    assert "systemctl enable --now meshembed-path-heal.timer" in INSTALL


def test_ht4_the_package_uninstall_removes_the_pair():
    pre = (ROOT / "packaging" / "preuninstall.sh").read_text()
    assert "systemctl disable --now meshembed-path-heal.timer" in pre
    assert "rm -f /etc/systemd/system/meshembed-path-heal.timer /etc/systemd/system/meshembed-path-heal.service" in pre


def test_ht5_the_pair_is_written_only_from_the_root_owned_opt_venv():
    fn = INSTALL[INSTALL.index("_root_venv_ok() {"):INSTALL.index("install_updater_units() {")]
    assert '[ "$v" = /opt/meshembed-node/.venv ]' in fn and '_root_only "$p" || return 1' in fn
    assert "! -user root -o -perm -g+w -o -perm -o+w" in fn
    body = INSTALL[INSTALL.index("install_updater_units() {"):INSTALL.index("install_updater_units_from_unit() {")]
    guard = body.index('if ! _root_venv_ok "$v"; then')
    assert guard < body.index("cat > /etc/systemd/system/meshembed-path-heal.service")
    assert "return 0" in body[guard:body.index("cat > /etc/systemd/system/meshembed-path-heal.service")]


def _guard(venv: str, fake_stat: str = "") -> str:
    """Run install.sh's real _root_venv_ok on `venv` (the /opt literal replaced by it, nothing else changed), with an
    optional bash `stat` override for ownership/mode that a non-root test cannot create on disk."""
    import subprocess
    fn = INSTALL[INSTALL.index("_root_venv_ok() {"):INSTALL.index("install_updater_units() {")]
    fn = fn.replace("/opt/meshembed-node/.venv", venv)
    r = subprocess.run(["bash", "-c", fake_stat + "\n" + fn + f'\n_root_venv_ok "{venv}" && echo OK || echo REFUSED'],
                       capture_output=True, text=True)
    return r.stdout.strip()


def test_ht5_only_the_opt_path_is_ever_accepted(tmp_path):
    import subprocess
    fn = INSTALL[INSTALL.index("_root_venv_ok() {"):INSTALL.index("install_updater_units() {")]
    r = subprocess.run(["bash", "-c", fn + f'\n_root_venv_ok "{tmp_path}" && echo OK || echo REFUSED'],
                       capture_output=True, text=True)
    assert r.stdout.strip() == "REFUSED"                              # any other path, whatever its owner


def test_ht5_a_root_only_layout_passes_and_the_negatives_refuse(tmp_path):
    v = tmp_path / "opt" / "meshembed-node" / ".venv"
    (v / "bin").mkdir(parents=True)
    (v / "lib.py").write_text("x")
    root = Path("/usr/bin/python3").resolve()
    (v / "bin" / "python").symlink_to(root)
    # everything under tmp_path reads root:755 (a non-root test cannot chown); real paths outside it keep their real stat
    pat = "|".join([f"{tmp_path}*"] + [str(p) for p in tmp_path.parents])   # the fixture tree + its exact ancestors
    fake = (f'stat() {{ local f="${{@: -1}}"; case "$f" in {pat}) case "$2" in %u) echo 0;; %a) echo 755;; esac;; '
            f'*) command stat "$@";; esac; }}\nfind() {{ case "$*" in *"! -user root"*) return 0;; *) command find "$@";; esac; }}')
    assert _guard(str(v), fake) == "OK"                               # the normal layout (python -> /usr/bin/python3.x)
    # HT-5a: a parent that is group-writable refuses
    gw = fake.replace("%a) echo 755;;", f'%a) [ "$f" = "{v.parent}" ] && echo 775 || echo 755;;')
    assert _guard(str(v), gw) == "REFUSED"
    # HT-5b: a link whose target is not root-owned refuses (the target here is a real file of the test user)
    user_file = tmp_path.parent / f"user-target-{tmp_path.name}"
    user_file.write_text("x")
    (v / "bin" / "evil").symlink_to(user_file)
    assert _guard(str(v), fake) == "REFUSED"
    user_file.unlink()


def test_ht5_the_start_check_names_a_non_root_path(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("x")
    assert P.drift([str(f)]) is not None                             # a test-user file: refused at start
    assert P.drift(["/usr/bin"]) is None                              # a real root-owned path and its parents pass


def test_ht5_both_launchers_refuse_on_drift_before_anything_runs(monkeypatch, capsys):
    from meshembed_node import path_heal, serve_launch, split_launch
    ran = []
    monkeypatch.setattr(serve_launch.os, "geteuid", lambda: 0)
    monkeypatch.setattr(split_launch.os, "geteuid", lambda: 0)
    monkeypatch.setattr(path_heal, "drift", lambda paths=None: "/opt/meshembed-node/.venv/lib/evil.py")
    monkeypatch.setattr(serve_launch, "run", lambda *a, **k: ran.append("serve") or "ran")
    monkeypatch.setattr(split_launch, "run_once", lambda *a, **k: ran.append("split") or "ran")
    assert serve_launch.main(["--request", "/x", "--owner", "u"]) == 3
    assert split_launch.main(["--request", "/x", "--owner", "u"]) == 3
    out = capsys.readouterr().out
    assert "serve_launch: refused venv_drift" in out and "split_launch: refused venv_drift" in out and ran == []
    # the negative control: no drift -> each runs its pass
    monkeypatch.setattr(path_heal, "drift", lambda paths=None: None)
    assert serve_launch.main(["--request", "/x", "--owner", "u"]) == 0
    assert split_launch.main(["--request", "/x", "--owner", "u"]) == 0
    assert ran == ["serve", "split"]


def test_ht5_the_limits_applier_refuses_on_drift_too(monkeypatch, capsys):
    # the v0.3.82 composition: IO-CAP's root applier (#22) is a fourth root entry point; the same start check
    from meshembed_node import limits_apply, path_heal
    ran = []
    monkeypatch.setattr(limits_apply.os, "geteuid", lambda: 0)
    monkeypatch.setattr(limits_apply, "run", lambda *a, **k: ran.append("apply") or "applied")
    monkeypatch.setattr(limits_apply, "reconcile", lambda *a, **k: ran.append("reconcile") or "applied")
    monkeypatch.setattr(path_heal, "drift", lambda paths=None: "/opt/meshembed-node/.venv/lib/evil.py")
    assert limits_apply.main(["--request", "/x", "--owner", "u"]) == 3
    assert limits_apply.main(["--request", "/x", "--owner", "u", "--reconcile"]) == 3
    assert "limits_apply: refused venv_drift" in capsys.readouterr().out and ran == []
    monkeypatch.setattr(path_heal, "drift", lambda paths=None: None)       # the negative control
    assert limits_apply.main(["--request", "/x", "--owner", "u"]) == 0
    assert limits_apply.main(["--request", "/x", "--owner", "u", "--reconcile"]) == 0
    assert ran == ["apply", "reconcile"]


@pytest.mark.parametrize("u", ["meshembed-limits-apply.path", "meshembed-limits-reconcile.path"])
def test_cd4_the_limits_path_units_are_healed_by_the_same_rules(tmp_path, u):
    # CD-4: healed every pass while failed (no hourly bound: that is node-update's only), stopped after 3 in 24 h
    h = Host()
    for k in range(3):
        h.failed.add(u)
        assert P.run(tmp_path, T0 + 600 * k, is_failed=h.is_failed, systemctl=h.systemctl) == [
            f"path_unit_healed {u} heals_24h {k + 1}"]
    h.failed.add(u)
    assert P.run(tmp_path, T0 + 1800, is_failed=h.is_failed, systemctl=h.systemctl) == [
        f"path_unit_heal_stopped {u} heals_24h 3"]
    assert u not in P.MIN_GAP_S
