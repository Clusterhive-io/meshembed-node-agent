"""RQ-1 (v0.3.85; auditor 2026-11-11T18:25:09Z B1-B3): node-agent/requirements.txt (read by the node Dockerfile and by
scripts/generate-sbom.sh) carries EXACTLY pyproject.toml's [project].dependencies: the set every installer installs.
B1: name + full specifier + marker compared exactly (whitespace-normalised strings). B2: one named exception."""
import re
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[1]
# B2: the ONLY line allowed beyond pyproject. A second entry needs a review.
ALLOWED_EXTRA = {
    "jinja2>=3.1.6": "the LLM-path dependency (chat templates); hash-pinned on native nodes via install.sh LLM_DEP_PINS",
}


def _norm(req: str) -> str:
    req = re.sub(r"\s+", " ", req.strip())
    return re.sub(r"\s*;\s*", " ; ", req)


def _requirements() -> list:
    out = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(_norm(line))
    return out


def _pyproject() -> list:
    return [_norm(d) for d in tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]]


def test_requirements_txt_is_exactly_pyprojects_dependencies_plus_the_named_allow_list():
    req, pyp = _requirements(), _pyproject()
    assert len(req) == len(set(req)), "a duplicated line in requirements.txt"
    missing = [d for d in pyp if d not in req]
    extra = [r for r in req if r not in pyp and r not in ALLOWED_EXTRA]
    assert not missing, f"in pyproject but not in requirements.txt: {missing}"
    assert not extra, f"in requirements.txt but not in pyproject (and not allowed): {extra}"


def test_the_allow_list_is_one_named_entry_and_it_is_present():
    assert list(ALLOWED_EXTRA) == ["jinja2>=3.1.6"] and all(ALLOWED_EXTRA.values())
    assert "jinja2>=3.1.6" in _requirements()


def test_a_drifted_specifier_or_marker_is_caught(tmp_path, monkeypatch):
    """The comparison is exact: an old exact pin (the pre-RQ-1 numpy==2.3.3) or a dropped marker is drift."""
    pyp = _pyproject()
    for drifted in (["numpy==2.3.3" if d.startswith("numpy") else d for d in pyp],
                    [d.split(" ; ")[0] if d.startswith("pynacl>=1.5,<1.6") else d for d in pyp]):
        assert any(d not in pyp for d in drifted)
