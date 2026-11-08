"""Every backend path the node agent calls is routed by the public nginx, to the backend, with its URI unchanged.

2026-09-27: /node_heartbeat (fast flip) was missing from the daemon-paths
location, so a node on the public name would have heartbeated into the SPA and
never flipped. LAN nodes hit :18080 directly and would not have shown it.

2026-11-02 (NGX-SERVE, W3b): /nodes/serve/next and five more were missing and this test still passed: its scan read
only the backend_url + "..." spellings, and the serve, agent and probe clients take an injected post(path, ...). The
scan now takes EVERY string literal in the node code that names a backend route (read from the backend's own route
table), however the call is written, and the routing check follows nginx's location selection, not one regex.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NGINX = ROOT / "frontend" / "nginx.conf"
BACKEND = ROOT / "backend" / "app"
NODE_CODE = (ROOT / "node-agent", ROOT / "packaging")       # packaging/msi/deregister.py: the MSI's uninstall helper
SKIP_DIRS = {"tests", ".venv", "venv", "build", "dist", "__pycache__"}

# A monorepo contract: the public node-agent repo has no frontend/ or backend/ to check.
pytestmark = [pytest.mark.unit,
              pytest.mark.skipif(not (NGINX.exists() and BACKEND.exists()), reason="monorepo only")]

# Known and recorded; remove an entry when it is routed (a test below fails on a stale one).
KNOWN_UNROUTED = {
    # ATT-1 (auditor 2026-11-04 16:55:03Z): /attestation/challenge and /attestation/quote are now routed (the node-path
    # location); backend/tests/test_attestation_guard.py pins that nothing GATES on a quote without EK pinning.
    # AGL-1 (2026-11-02): the agent lane (opt-in, MESHEMBED_AGENT_HOST=1, Linux only). A model step waits up to 130 s,
    # over nginx's 60 s proxy_read_timeout and Cloudflare's 100 s: routing it needs its own design, not one more name.
    "/agent/v1/steps/chat", "/agent/v1/runs/{}/state", "/agent/v1/runs/{}/result",
}
# The llama-server's own API, spoken over the engine's unix socket: a backend route of the same name, never a call to it.
LOCAL_ONLY = {"/v1/chat/completions": {"node-agent/meshembed_node/serve_client.py",
                                       "node-agent/meshembed_node/split_engine.py"}}


def _backend_routes():
    routes = []
    for f in sorted(BACKEND.rglob("*.py")):
        src = f.read_text()
        prefix = re.findall(r'APIRouter\([^)]*prefix="([^"]*)"', src)
        assert len(prefix) <= 1, f
        for m in re.finditer(r'@\w+\.(?:get|post|put|patch|delete|api_route)\(\s*"(/[^"]*)"', src):
            path = (prefix[0] if prefix else "") + m.group(1)
            routes.append(re.compile(re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(path))))
    return routes


def _literals(tree):
    """Every string constant starting with "/"; in an f-string, from each such part to its end, placeholders as {}
    (f"{backend}/nodes/register", f"/agent/v1/runs/{tid}/state"); the query string cut off."""
    parts = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr):
            parts |= {id(v) for v in n.values}
            for k, v in enumerate(n.values):
                if isinstance(v, ast.Constant) and v.value.startswith("/"):
                    yield "".join(w.value if isinstance(w, ast.Constant) else "{}" for w in n.values[k:]).split("?")[0]
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("/") and id(n) not in parts:
            yield n.value.split("?")[0]


def _node_paths():
    """{backend path the node code names: the files naming it}."""
    routes, found = _backend_routes(), {}
    for top in NODE_CODE:
        for f in sorted(top.rglob("*.py")):
            if SKIP_DIRS & set(f.relative_to(ROOT).parts):
                continue
            for p in _literals(ast.parse(f.read_text())):
                if any(r.fullmatch(p) for r in routes):
                    found.setdefault(p, set()).add(str(f.relative_to(ROOT)))
    return found


# --- nginx's location selection, for the one server block ------------------------------------------------------------
def _locations():
    conf = NGINX.read_text()
    out = []
    for m in re.finditer(r"^    location\s+(=|~\*|~|\^~)?\s*(\S+)\s*\{", conf, re.M):
        depth, i = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(conf[i], 0)
            i += 1
        out.append((m.group(1) or "", m.group(2).strip('"'), conf[m.end():i - 1]))
    assert len(out) > 10, "locations not parsed"
    return out


def _select(path):
    """exact =, else the longest prefix (final if ^~), else the first regex in order, else that longest prefix."""
    locs = _locations()
    for mod, arg, body in locs:
        if mod == "=" and arg == path:
            return mod, arg, body
    prefixes = [loc for loc in locs if loc[0] in ("", "^~") and path.startswith(loc[1])]
    longest = max(prefixes, key=lambda loc: len(loc[1]), default=None)
    if longest and longest[0] == "^~":
        return longest
    for mod, arg, body in locs:
        if mod in ("~", "~*") and re.search(arg, path, re.I if mod == "~*" else 0):
            return mod, arg, body
    return longest


def _reaches_backend_unchanged(body):
    """proxy_pass with no URI part passes the request URI as is; a return or rewrite would answer or change it."""
    return (re.search(r"^\s*proxy_pass\s+http://backend:18080;", body, re.M)
            and not re.search(r"^\s*(return|rewrite)\s", body, re.M))


def _routed():
    paths = set(_node_paths()) - KNOWN_UNROUTED - set(LOCAL_ONLY)
    return {p: _select(p) for p in paths}


def test_the_route_table_and_the_scan_are_not_empty():
    assert len(_backend_routes()) > 50
    assert {"/get_job", "/report_result", "/node_heartbeat", "/register_node", "/nodes/register",
            "/nodes/me/deregister", "/nodes/serve/next", "/nodes/serve/result", "/nodes/agent/next",
            "/nodes/agent/revocations", "/node_probe_plan", "/node_probe_report",
            "/location/probe-plan"} <= set(_node_paths())


def test_the_selection_model_sends_other_paths_where_nginx_does():
    assert _select("/nodes/serve/nextx")[1] == "/"                 # anchored: a longer name is the SPA's
    assert _select("/dashboard")[1] == "/"
    assert _select("/api/v1/models")[1] == "/api/"
    assert _select("/api/auth/login")[:2] == ("=", "/api/auth/login")
    assert _select("/node_heartbeat")[:2] == ("=", "/node_heartbeat")
    assert _select("/assets/index-abc.js")[1] == "/assets/"
    assert not _reaches_backend_unchanged(_select("/api/v1/models")[2])        # /api/ strips its prefix


def test_every_node_path_reaches_the_backend_with_its_uri_unchanged():
    wrong = {p: loc[1] for p, loc in _routed().items() if not (loc and _reaches_backend_unchanged(loc[2]))}
    assert not wrong, f"node paths not routed to the backend by nginx.conf (path: location chosen): {wrong}"


def test_every_node_path_is_rate_limited_per_key_and_per_ip():
    """A key zone ignores requests without a key, so each has an IP zone too."""
    for p, (_, arg, body) in _routed().items():
        assert re.search(r"limit_req zone=node\w*_key ", body) and re.search(r"limit_req zone=node\w*_ip ", body), p


def test_every_node_path_overwrites_cf_connecting_ip():
    for p, (_, arg, body) in _routed().items():
        assert "proxy_set_header   CF-Connecting-IP  $remote_addr;" in body, p


def test_the_stream_frames_path_is_routed_before_any_node_names_it():
    """NGX-FRAMES (2026-11-05): EP1-n (unreleased) posts its pieces to /nodes/serve/frames, so the scan above cannot
    see it yet. The backend route exists (EP1-b) and nginx must route it, rate-limited per key AND per IP in the SAME
    zones as the other node paths (auditor 2026-11-05T18:33:49Z, option (a): node_ip is never raised for it)."""
    p = "/nodes/serve/frames"
    assert any(r.fullmatch(p) for r in _backend_routes()), "no backend route /nodes/serve/frames"
    mod, arg, body = _select(p)
    assert arg != "/" and _reaches_backend_unchanged(body), arg
    assert "limit_req zone=node_key burst=400 nodelay;" in body and "limit_req zone=node_ip  burst=800 nodelay;" in body
    assert "proxy_set_header   CF-Connecting-IP  $remote_addr;" in body
    conf = NGINX.read_text()
    assert "zone=node_key:10m     rate=1200r/m;" in conf and "zone=node_ip:10m      rate=2400r/m;" in conf
    assert _select("/nodes/serve/framesx")[1] == "/"               # anchored


def test_every_known_unrouted_entry_is_still_named_and_still_unrouted():
    named = set(_node_paths())
    for p in KNOWN_UNROUTED:
        assert p in named, f"{p}: no longer named by the node code; drop it from KNOWN_UNROUTED"
        concrete = p.replace("{}", "rt-" + "0" * 24)
        loc = _select(concrete)
        assert not (loc and _reaches_backend_unchanged(loc[2])), f"{p}: routed now; drop it from KNOWN_UNROUTED"


def test_a_local_only_path_is_named_only_by_the_socket_clients():
    found = _node_paths()
    for p, files in LOCAL_ONLY.items():
        assert found.get(p, set()) <= files, f"{p} named outside the engine-socket clients: {found[p] - files}"
        for f in files:
            src = (ROOT / f).read_text()
            assert "backend_url" not in src and "AF_UNIX" in src, f
