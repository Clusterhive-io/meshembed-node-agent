"""T2 / TT-3 (operator 2026-11-13 06:31Z; auditor 05:46:28Z, 06:19Z): a POSIX-only permission check must fail in CI, not on a
Windows host after the fleet moved.

v0.3.84 refused EVERY embedding model on Windows because embed_pins.check_private_dir ran a group / other write-bit test on a
Windows directory (CPython reports any non-read-only directory there as 0o777; st_mode is not the ACL). PB-W found it; nothing in
CI could. HP3-WIN fixed it and tests that module with Windows semantics. THIS test makes the sweep durable:

  * every module under meshembed_node that tests file modes / owners (st_mode &, S_IW*, S_IMODE, st_uid, st_gid, os.getuid /
    geteuid) must be listed below with the reason it never runs that check on Windows, or be tested with Windows semantics;
  * a NEW such module fails here until someone adds it with a reason (or a guard + a Windows-semantics test);
  * a listed module that no longer has such a check, or whose named guard is gone, fails too (no stale claims).
"""
from __future__ import annotations

import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "meshembed_node"
# WS-1 (auditor 06:43:11Z): any use of st_mode that is not a file-TYPE test, any owner / group id, getuid / getgid in all their
# forms, and os.access(.., W_OK / X_OK) (on Windows it reads only the read-only attribute). Indirect forms count too:
# `m = st.st_mode` followed by `m & 0o022` is caught at the `st_mode` read.
_TYPE_TEST = re.compile(r"\bS_IS\w+\((?:[^()]|\([^()]*\))*\)")                    # stat.S_ISREG(st.st_mode) etc.: platform-neutral
_ACCESS = re.compile(r"\bos\.access\((?:[^()]|\([^()]*\))*[WX]_OK")
_FORMS = re.compile(r"\bst_mode\b|\bS_I(?:W|R|X)(?:GRP|OTH|USR)\b|\bS_IMODE\b|\bst_uid\b|\bst_gid\b|\bos\.get(?:e)?[ug]id\(\)")


class _Check:
    """CHECK.search(text) keeps the old call shape: True when the text holds a mode / owner / access test."""
    @staticmethod
    def search(text: str):
        stripped = _TYPE_TEST.sub("", text)
        return _FORMS.search(stripped) or _ACCESS.search(stripped)


CHECK = _Check()

# module -> (why it never runs that check on Windows, a source snippet that must still be present as proof, or "")
NOT_ON_WINDOWS = {
    "llm.py": ("HASFILE serve_files() returns [] for os.name == 'nt' before any stat (the serve launcher's root-owned models dir is Linux only)",
               'if os.name == "nt":'),
    "pause.py": ("admin_owned() returns None for a win* platform before any stat", 'platform.startswith("win")'),
    "serve_duty.py": ("why_off() returns 'serve_linux_only' for a non-linux platform before the unit's lstat",
                      'not platform.startswith("linux")'),
    "worker.py": ("a cross-platform module: its only os.access(.., W_OK) is behind os.name == 'posix' (_hardened_with_updater)",
                  'os.name == "posix" and not os.access('),
    "agent_daemon.py": ("start() returns 'agent_host_linux_only' for a non-linux platform before anything else",
                        'not platform.startswith("linux")'),
    "agent_bridge.py": ("imported only by agent_daemon (Linux-gated above)", ""),
    "limits_apply.py": ("root systemd oneshot (python -m meshembed_node.limits_apply); the applier is not installed on Windows", ""),
    "maintenance.py": ("os.getuid() only builds the macOS restart hint, inside the platform.system() == 'Darwin' branch "
                       "(Windows has its own branch)", 'if system == "Darwin":'),
    "path_heal.py": ("root systemd heal oneshot (python -m meshembed_node.path_heal)", ""),
    "serve_launch.py": ("root systemd launcher (python -m meshembed_node.serve_launch)", ""),
    "split_launch.py": ("root systemd split launcher, imported only by serve_launch / limits_apply", ""),
    "split_overlay_node.py": ("imported only by split_launch (root, Linux)", ""),
    "updater.py": ("root systemd updater (python -m meshembed_node.updater); a Windows node updates through install.ps1", ""),
    # embed_pins.py is NOT here: it is cross-platform and tested with Windows semantics (test_embed_pins.py::test_hp3_win_*).
}
WINDOWS_TESTED = {"embed_pins.py": "tests/test_embed_pins.py::test_hp3_win_*  (check_private_dir behind _posix_modes())",
                  "model_blocks.py": "tests/test_model_blocks.py::test_windows_there_is_no_uid_*  (the owner check is skipped where os.getuid does not exist; no st_mode test)"}


def _imports_of(path: Path) -> set:
    """The meshembed_node modules a file imports, from the AST (function-level imports included)."""
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            if n.level >= 1 and n.module is None:
                out |= {a.name for a in n.names}                          # from . import pause
            elif n.level >= 1:
                out.add(n.module.split(".")[0])                           # from .path_heal import drift
            elif n.module and n.module.startswith("meshembed_node."):
                out.add(n.module.split(".")[1])
        elif isinstance(n, ast.Import):
            out |= {a.name.split(".")[1] for a in n.names if a.name.startswith("meshembed_node.")}
    return out


# the ONLY allowed imports OF a root-unit-only module (empty guard snippet) by a module that is not itself root-unit-only:
# (importer, imported) -> why it is safe, and a source snippet of the importer that must still be there.
ROOT_UNIT_EDGES = {
    ("agent_daemon", "agent_bridge"): ("agent_daemon is Linux-gated before it uses the bridge", "agent_bridge as B"),
    ("split_launch", "split_overlay_node"): ("split_overlay_node is part of the root split launcher", "split_overlay_node as _real_ovl"),
    ("worker", "path_heal"): ("imports the UNITS constant only, and only AFTER reading the root-written summary file, which does "
                              "not exist on Windows (the OSError returns None before the import)", "from .path_heal import UNITS"),
}


def _modules_with_checks() -> set:
    return {p.name for p in PKG.rglob("*.py") if CHECK.search(p.read_text(encoding="utf-8"))}


def test_every_module_that_checks_modes_or_owners_is_accounted_for():
    found = _modules_with_checks()
    unknown = sorted(found - set(NOT_ON_WINDOWS) - set(WINDOWS_TESTED))
    assert not unknown, (
        f"{unknown} test file modes / owners (st_mode &, S_IW*, st_uid, os.getuid ...) and are not accounted for. On Windows "
        "st_mode is 0o777 for a normal directory and there is no uid: guard the check with os.name / sys.platform and add a "
        "Windows-semantics test (os.name patched ONLY around the call; see test_embed_pins.py::test_hp3_win_*), or, if the module "
        "can only run as a root Linux unit, add it to NOT_ON_WINDOWS with the reason.")


def test_no_stale_entries_a_listed_module_still_has_a_check_and_its_guard():
    found = _modules_with_checks()
    stale = sorted((set(NOT_ON_WINDOWS) | set(WINDOWS_TESTED)) - found)
    assert not stale, f"listed but no longer containing a mode / owner check (remove the entry): {stale}"
    for mod, (why, snippet) in NOT_ON_WINDOWS.items():
        if snippet:
            assert snippet in (PKG / mod).read_text(encoding="utf-8"), (
                f"{mod}: the guard this entry relies on ({why!r}) is gone; the module may now run the POSIX check on Windows")


def test_embed_pins_keeps_its_windows_branch_ahead_of_the_mode_test():
    src = (PKG / "embed_pins.py").read_text(encoding="utf-8")
    body = src[src.index("def check_private_dir"):]
    body = body[:body.index("\ndef ", 1)]
    assert "_posix_modes()" in body and body.index("_posix_modes()") < body.index("S_IWGRP"), \
        "check_private_dir must return on Windows BEFORE the group / other write-bit test (HP3-WIN)"


def test_the_scanner_sees_the_real_check_that_broke_v0_3_84():
    # Negative control for the scanner itself: the exact line that refused every model on Windows must match.
    assert CHECK.search("    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):")
    assert CHECK.search("if st.st_uid != os.getuid():")
    assert not CHECK.search("if not stat.S_ISREG(st.st_mode) or st.st_size > 5:")        # file-type checks are platform-neutral


def test_ws2_no_cross_platform_module_imports_a_root_unit_only_module():
    # An entry with an empty snippet has no in-code guard: its only proof is "nothing cross-platform imports it". So a later
    # cross-platform import of such a module (the way v0.3.84 reached Windows) fails CI here.
    root_only = {m[:-3] for m, (_, snippet) in NOT_ON_WINDOWS.items() if not snippet}
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        me = path.stem
        if me in root_only:
            continue                                                       # a root unit may import other root units
        for dep in sorted(_imports_of(path) & root_only):
            if (me, dep) in ROOT_UNIT_EDGES:
                continue
            offenders.append(f"{path.name} imports {dep}")
    assert not offenders, (
        f"{offenders}: a module that is not a root systemd unit imports one that is. Those modules carry no in-code Windows "
        "guard (their NOT_ON_WINDOWS entry has no snippet), so a cross-platform import can run their POSIX checks on Windows. "
        "Guard the use (os.name / sys.platform) and give the entry a snippet, or move the shared part to a neutral module.")


def test_ws1_the_widened_scanner_sees_the_indirect_forms_and_ignores_file_type_tests():
    for line in ("m = st.st_mode", "g = os.getgid()", "os.access(path, os.W_OK)",
                 "os.access(str(p), os.X_OK | os.R_OK)", "os.getegid()", "stat.S_IMODE(st.st_mode)", "st.st_gid != 0"):
        assert CHECK.search(line), line
    for line in ("if not stat.S_ISREG(st.st_mode):", "stat.S_ISDIR(os.stat(p).st_mode)", "os.access(path, os.R_OK)",
                 "x = st.st_size"):
        assert not CHECK.search(line), line


def test_ws2_every_documented_edge_still_exists_and_its_proof_is_still_in_the_importer():
    for (me, dep), (why, snippet) in ROOT_UNIT_EDGES.items():
        assert dep in _imports_of(PKG / f"{me}.py"), f"stale edge {me} -> {dep}: no longer imported (remove it)"
        assert snippet in (PKG / f"{me}.py").read_text(encoding="utf-8"), f"{me}: the proof for {me} -> {dep} ({why}) is gone"
