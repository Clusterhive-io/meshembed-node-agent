"""WS-3 (auditor 2026-10-25 19:29Z): our PowerShell names Windows principals by well-known SID, never by name.

A localized Windows has no group called "Administrators" (es-ES: "Administradores"; Users = "Usuarios"), so an
NTAccount lookup, an access rule built from a name, or an owner check that matches a display name fails or misreports
there. That is what stopped pause proof 2 on 160 at block 1. 189 has no PowerShell, so this is a static lint over
every .ps1 in the repository (the pause tool is a here-string inside install.ps1, so it is covered with it).
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PS_FILES = sorted(p for p in ROOT.rglob("*.ps1") if ".venv" not in p.parts and "node_modules" not in p.parts)

NAMES = r"(?:NT AUTHORITY\\)?(?:SYSTEM|Administrators|Administradores|Users|Usuarios|Everyone|Authenticated Users)"
FORBIDDEN = [
    (re.compile(r"NTAccount\s*\("), "an NTAccount (name) lookup"),
    (re.compile(r"['\"]" + NAMES + r"['\"]"), "a principal named in a string"),
    (re.compile(r"BUILTIN\\"), "a BUILTIN\\ name"),
    (re.compile(r"icacls\b.*\b" + NAMES + r"\b(?!.*\*S-1-)"), "icacls with a principal name (use *S-1-5-...)"),
    (re.compile(r"-match\s+['\"][^'\"]*(?:Administrators|SYSTEM)"), "an owner/name match on a display name"),
]


def _code_lines(text):
    """(line number, line) without PowerShell comments (a '#' comment, the rest of the line)."""
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        if stripped.strip():
            yield i, stripped


def _violations(text):
    out = []
    for i, line in _code_lines(text):
        for rx, why in FORBIDDEN:
            if rx.search(line):
                out.append((i, why, line.strip()[:120]))
    return out


def test_there_are_ps1_files_to_check():
    assert any(p.name == "install.ps1" for p in PS_FILES), PS_FILES


def test_no_principal_is_named_in_any_ps1():
    bad = []
    for p in PS_FILES:
        for i, why, line in _violations(p.read_text(encoding="utf-8", errors="replace")):
            bad.append(f"{p.relative_to(ROOT)}:{i}: {why}: {line}")
    assert not bad, "\n".join(bad)


def test_the_pause_tool_uses_the_well_known_sids():
    src = (ROOT / "node-agent" / "install.ps1").read_text(encoding="utf-8")
    tool = src[src.index("$PauseToolSource"):]
    for sid in ("S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"):
        assert f"SecurityIdentifier('{sid}')" in tool, sid
    assert "GetOwner([System.Security.Principal.SecurityIdentifier])" in tool       # WS-2: the status compares SIDs
    assert "acl_failed" in tool and "pause_incomplete" in tool                        # WS-4: never a false "paused"


def test_the_lint_catches_the_old_code():
    old = (
        "    foreach ($id in 'SYSTEM', 'Administrators') {\n"
        "    $acl.SetOwner((New-Object System.Security.Principal.NTAccount('Administrators')))\n"
        "      if ($owner -match '(\\\\|^)(Administrators|SYSTEM)$') { 'paused' }\n"
        "    & icacls.exe $d /grant Administrators:F\n"
        "    # a comment naming 'Administrators' is fine\n"
    )
    kinds = {why for _, why, _ in _violations(old)}
    assert kinds == {"a principal named in a string", "an NTAccount (name) lookup",
                     "an owner/name match on a display name", "icacls with a principal name (use *S-1-5-...)"}, kinds
    assert all(i != 5 for i, _, _ in _violations(old))                               # comments are not code
