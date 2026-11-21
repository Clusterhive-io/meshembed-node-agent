"""W3 (0.3.87, design Rev 4 1117538e; auditor code GO 09:35:29Z W3-w): the CREATE path passes NO mode on Windows, /setowner is /L with no /T
and is followed by the reparse post-check, the repair never changes the locked tree in place. Windows calls are proven on 160 (PB-W)."""
import inspect
import re
from pathlib import Path

import pytest

from meshembed_node import embed_pins, pinned_acl as PA

pytestmark = pytest.mark.unit
SID = "S-1-5-21-1-2-3-1001"
ROOT = Path(__file__).resolve().parents[1]


class Fake(PA.Ops):
    def __init__(self, existing=(), reparse_after_setowner=False, tree_bad=None, fail_makedirs_after_rename=False, setowner_raises=False, locked=True, reparse_existing=False):
        super().__init__()
        self.fs = set(existing)
        self.reparse_after = reparse_after_setowner
        self.tree_bad = tree_bad
        self.fail_mk = fail_makedirs_after_rename
        self.renamed = False
        self.setowner_raises = setowner_raises
        self.owned = []
        self.locked = locked
        self.reparse_existing = reparse_existing

    def makedirs(self, path):
        self.calls.append(("makedirs", path))
        if self.fail_mk and self.renamed:
            raise OSError("boom")
        self.fs.add(path)

    def setowner(self, path, sid):
        self.calls.append(("setowner", path, sid))
        if self.setowner_raises:
            raise OSError("icacls")
        self.owned.append(path)

    def is_reparse(self, path):
        self.calls.append(("is_reparse", path))
        return self.reparse_existing if (path in self.fs and not self.owned) else self.reparse_after

    def tree_reparse(self, path):
        self.calls.append(("tree_reparse", path))
        return self.tree_bad

    def rename(self, src, dst):
        self.calls.append(("rename", src, dst))
        self.fs.discard(src)
        self.fs.add(dst)
        self.renamed = True

    def exists(self, path):
        return path in self.fs

    def user_sid(self):
        return SID

    def is_locked(self, path, user_sid):
        self.calls.append(("is_locked", path, user_sid))
        return self.locked

    def tree_bytes(self, path):
        return 1234


def test_windows_create_passes_no_mode_and_posix_keeps_0o700(monkeypatch, tmp_path):
    rec = []
    monkeypatch.setattr(PA.os, "makedirs", lambda p, mode=None, exist_ok=False: rec.append((p, mode)))
    PA.private_makedirs(str(tmp_path / "a"), nt=False)
    assert rec == [(str(tmp_path / "a"), 0o700)]
    ops = Fake()
    assert PA.private_makedirs("C:/p", ops, nt=True) == "ok"
    assert ("makedirs", "C:/p") in ops.calls and rec == [(str(tmp_path / "a"), 0o700)]     # the nt path never calls os.makedirs with a mode


def test_the_windows_source_never_passes_a_mode_to_makedirs():
    src = inspect.getsource(PA)
    code = [l for l in src.splitlines() if "makedirs(" in l and not l.strip().startswith(("#", '"""'))]
    assert not any("0o700" in l and "nt" in l.lower() for l in code)
    win = inspect.getsource(PA.WinOps.makedirs)
    assert "mode=" not in win


def test_embed_pins_has_no_direct_makedirs_with_a_mode():
    src = inspect.getsource(embed_pins)
    assert not re.search(r"os\.makedirs\([^)]*mode=", src.replace("(os.makedirs(mode=0o700)", ""))


def test_create_path_is_setowner_L_C_no_T_then_the_reparse_check_in_that_order():
    ops = Fake()
    assert PA.private_makedirs("C:/p", ops, nt=True) == "ok"
    names = [c[0] for c in ops.calls]
    assert names == ["makedirs", "setowner", "is_reparse"]
    ws = inspect.getsource(PA.WinOps.setowner)
    assert '"/L"' in ws and '"/C"' in ws and '"/T"' not in ws and "/reset" not in ws


def test_a_reparse_point_after_setowner_refuses_even_though_setowner_returned_ok():
    ops = Fake(reparse_after_setowner=True)
    assert PA.private_makedirs("C:/p", ops, nt=True) == "refused:reparse_point"
    assert ("is_reparse", "C:/p") in ops.calls


def test_an_existing_dir_is_left_alone_by_the_create_path():
    ops = Fake(existing={"C:/p"})
    assert PA.private_makedirs("C:/p", ops, nt=True) == "ok"
    assert not any(c[0] == "setowner" for c in ops.calls)


def test_setowner_failure_is_a_closed_failed_word_not_a_raise():
    assert PA.private_makedirs("C:/p", Fake(setowner_raises=True), nt=True) == "failed:setowner"


def test_repair_sequence_scan_rename_create_setowner_check_marker(tmp_path):
    ops = Fake(existing={"C:/h/pm"})
    res = PA.repair_locked_dir("C:/h/pm", "C:/h", True, ops, now=lambda: 1700000000)
    assert res == "repaired"
    seq = [c[0] if isinstance(c, tuple) else c for c in ops.calls]
    assert seq == ["tree_reparse", "rename", "makedirs", "setowner", "is_reparse", "marker"]
    assert ("rename", "C:/h/pm", "C:/h/pm.locked-1700000000") in ops.calls
    assert "C:/h/pm.locked-1700000000" in ops.fs                     # kept, never deleted
    assert not any(c[0] == "setowner" and c[1].endswith("locked-1700000000") for c in ops.calls if isinstance(c, tuple))


def test_a_reparse_point_anywhere_in_the_tree_refuses_before_any_rename():
    ops = Fake(existing={"C:/h/pm"}, tree_bad="a/b/link")
    assert PA.repair_locked_dir("C:/h/pm", "C:/h", True, ops) == "refused:reparse_point:a/b/link"
    assert not any(isinstance(c, tuple) and c[0] == "rename" for c in ops.calls) and "marker" not in ops.calls


def test_a_reparse_point_planted_after_the_rename_refuses_and_writes_no_marker():
    ops = Fake(existing={"C:/h/pm"}, reparse_after_setowner=True)
    assert PA.repair_locked_dir("C:/h/pm", "C:/h", True, ops, now=lambda: 5) == "refused:reparse_point"
    assert "marker" not in ops.calls and "C:/h/pm.locked-5" in ops.fs


def test_fresh_dir_failure_after_rename_leaves_no_marker_and_keeps_the_aside_dir():
    ops = Fake(existing={"C:/h/pm"}, fail_makedirs_after_rename=True)
    res = PA.repair_locked_dir("C:/h/pm", "C:/h", True, ops, now=lambda: 5)
    assert res.startswith("failed:") and "marker" not in ops.calls and "C:/h/pm.locked-5" in ops.fs


def test_marker_present_or_not_locked_or_missing_is_unchanged():
    assert PA.repair_locked_dir("C:/h/pm", "C:/h", True, Fake(existing={"C:/h/pm", "C:/h/" + PA.MARKER_NAME})) == "unchanged"
    assert PA.repair_locked_dir("C:/h/pm", "C:/h", False, Fake(existing={"C:/h/pm"})) == "unchanged"
    assert PA.repair_locked_dir("C:/h/pm", "C:/h", True, Fake()) == "unchanged"


def test_no_recursive_or_reset_icacls_anywhere_in_the_module():
    src = inspect.getsource(PA)
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert '"/T"' not in code and "/reset" not in code.replace("`icacls /reset`", "").replace("no `icacls /reset`", "")


# ---- auditor 09:42:54Z / 09:49:20Z: c1 (existing path), c2 (wiring + predicate), c4 (SID forms), c5 (aside size), c6 (no bare tool names) ----
def test_c1_an_existing_reparse_path_refuses_and_prepare_writes_no_link(monkeypatch, tmp_path):
    ops = Fake(existing={"C:/h/pm"}, reparse_existing=True)
    assert PA.private_makedirs("C:/h/pm", ops, nt=True) == "refused:reparse_point"
    assert not any(c[0] == "setowner" for c in ops.calls)
    from meshembed_node import embed_pins
    monkeypatch.setattr(PA, "private_makedirs", lambda path, *a, **k: "refused:reparse_point")
    with pytest.raises(embed_pins.PinError) as e:
        embed_pins._private_makedirs(str(tmp_path / "x"))
    assert "reparse_point" in str(e.value) and not (tmp_path / "x").exists()


def test_c4_only_the_two_account_sid_forms_may_become_the_owner():
    for ok in ("S-1-5-21-1-2-3-1001", "S-1-12-1-111-222-333-444"):
        assert PA.valid_user_sid(ok)
    for bad in ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-1-2-3-4-5", "S-1-5-21-1-2-1001", "S-1-12-1-1-2-3", "", "x", None, "S-1-5-21-1-2-3-1001 /T"):
        assert not PA.valid_user_sid(bad)
    ops = Fake()
    ops.user_sid = lambda: "S-1-5-18"
    assert PA.private_makedirs("C:/p", ops, nt=True) == "failed:user_sid"
    assert not any(c[0] == "setowner" for c in ops.calls)


def test_c2_ensure_at_start_computes_locked_from_the_dir_and_repairs_once():
    ops = Fake(existing={"C:/h/pm"}, locked=True)
    assert PA.ensure_at_start(ops, nt=True, root="C:/h/pm") == "repaired"
    assert ("is_locked", "C:/h/pm", SID) in ops.calls
    ops2 = Fake(existing={"C:/h/pm"}, locked=False)
    assert PA.ensure_at_start(ops2, nt=True, root="C:/h/pm") == "unchanged" and not any(c[0] == "rename" for c in ops2.calls if isinstance(c, tuple))
    assert PA.ensure_at_start(Fake(), nt=False, root="C:/h/pm") is None
    assert PA.ensure_at_start(Fake(), nt=True, root="C:/h/missing") == "unchanged"


def test_c2_the_worker_calls_it_after_warn_at_start_and_before_cpu_load():
    src = (ROOT / "meshembed_node" / "worker.py").read_text(encoding="utf-8")
    a, b, c = src.index("_admin_token_start.warn_at_start()"), src.index("from .pinned_acl import ensure_at_start as _w3"), src.index("_cpu_load.start()")
    assert a < b < c


def test_c5_the_aside_size_is_logged(caplog):
    ops = Fake(existing={"C:/h/pm"})
    with caplog.at_level("WARNING", logger="meshembed.pinned_acl"):
        PA.repair_locked_dir("C:/h/pm", "C:/h", True, ops, now=lambda: 9)
    assert any("moved_aside:pm.locked-9 bytes=1234" in r.getMessage() for r in caplog.records)


def test_c6_no_tool_is_started_by_bare_name_and_whoami_is_gone():
    src = inspect.getsource(PA)
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "whoami" not in code.replace("no whoami", "")
    assert 'subprocess.run(["icacls"' not in code and "subprocess.run(['icacls'" not in code
    assert "GetSystemDirectoryW" in code and "icacls.exe" in code
    for m in re.finditer(r"subprocess\.\w+\(\s*\[([^\]]*)\]", code):
        first = m.group(1).split(",")[0].strip()
        assert first.startswith("os.path.join(_system32()"), first
