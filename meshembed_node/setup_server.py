"""Local-browser setup flow for a fresh daemon.

When `meshembed-node run` starts and there's no API key on disk, we
don't bail out — we start a tiny HTTP server bound to 127.0.0.1:7842
and open the operator's default browser to a single-page setup
form. The operator pastes the invite token, hits Connect, the daemon
calls `POST /nodes/register` against the backend, persists the
credentials, and the setup server returns success + the user sees
"Connected as N-0004". The daemon then transitions to its normal
poll loop with the credentials it just got.

Why 127.0.0.1 (loopback only): no firewall punch required, no DDoS
surface, no signing of a desktop UI bundle, no JS framework — the
single HTML page is inlined here. Linear-style design tokens mirror
the main UI so the experience feels consistent.

Why stdlib http.server: zero extra deps for the daemon (the
embedding stack is already heavy enough).
"""
from __future__ import annotations

import http.server
import json
import logging
import re
import socketserver
import threading
import urllib.error
import urllib.request
import uuid
import webbrowser
from typing import Optional, Tuple


log = logging.getLogger("meshembed_node.setup")

SETUP_HOST = "127.0.0.1"
SETUP_PORT = 7842

INVITE_TOKEN_RE = re.compile(r"^[a-f0-9]{64}$")


# ---------------------------------------------------------------------------
# HTML page (inlined). Single file, no external assets, no fonts hosted off
# the box — works offline once the operator has the binary.
# ---------------------------------------------------------------------------

SETUP_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>MeshEmbed Node — Setup</title>
<style>
  :root {
    color-scheme: light;
    --bg: #fbfbfc;
    --surface: #ffffff;
    --text: #18181b;
    --text-muted: #52525b;
    --text-soft: #a1a1aa;
    --border: #e4e4e7;
    --border-strong: #d4d4d8;
    --accent: #5e6ad2;
    --accent-hover: #4a55b8;
    --accent-soft: #eef0fc;
    --accent-ring: #bbc3f3;
    --rose: #b91c1c;
    --rose-bg: #fef2f2;
    --rose-ring: #fecaca;
    --emerald: #047857;
    --emerald-bg: #ecfdf5;
    --emerald-ring: #a7f3d0;
    --amber: #b45309;
    --amber-bg: #fffbeb;
    --amber-ring: #fde68a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); }
  body { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; }
  .card {
    width: 100%;
    max-width: 480px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px 28px 24px;
    box-shadow: 0 1px 2px rgba(15,23,42,0.04), 0 1px 3px rgba(15,23,42,0.06);
  }
  header { margin-bottom: 22px; }
  .brand {
    display: flex; align-items: center; gap: 10px;
    font-size: 13px; font-weight: 600; color: var(--text);
    letter-spacing: -0.01em;
  }
  .brand-mark {
    width: 22px; height: 22px;
    background: linear-gradient(135deg, var(--accent), var(--accent-hover));
    border-radius: 6px;
  }
  .brand small { color: var(--text-muted); font-weight: 500; font-size: 11px; margin-left: 4px; }
  h1 {
    font-size: 22px; font-weight: 600; letter-spacing: -0.02em;
    margin: 16px 0 6px;
  }
  p.sub { color: var(--text-muted); font-size: 14px; line-height: 1.5; margin: 0 0 18px; }
  label.field { display: block; margin: 0 0 14px; }
  label .label {
    display: block; font-size: 11px; font-weight: 600;
    letter-spacing: 0.06em; text-transform: uppercase;
    color: var(--text-muted); margin-bottom: 6px;
  }
  input[type="text"], input[type="password"] {
    width: 100%; padding: 10px 12px; font-size: 14px;
    background: var(--surface); border: 1px solid var(--border-strong);
    border-radius: 8px; color: var(--text);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    transition: border-color 100ms, box-shadow 100ms;
  }
  input[type="text"]:focus, input[type="password"]:focus {
    outline: none; border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
  }
  .hint { font-size: 12px; color: var(--text-soft); margin-top: 6px; }
  button.primary {
    width: 100%; padding: 10px 14px; font-size: 14px; font-weight: 500;
    background: var(--accent); color: white; border: none;
    border-radius: 8px; cursor: pointer;
    transition: background 100ms, transform 80ms;
  }
  button.primary:hover:not(:disabled) { background: var(--accent-hover); }
  button.primary:active:not(:disabled) { transform: scale(0.98); }
  button.primary:disabled { opacity: 0.55; cursor: not-allowed; }
  .alert {
    padding: 10px 12px; border-radius: 8px; font-size: 13px;
    margin-bottom: 14px; line-height: 1.45;
  }
  .alert.error { background: var(--rose-bg); border: 1px solid var(--rose-ring); color: var(--rose); }
  .alert.success { background: var(--emerald-bg); border: 1px solid var(--emerald-ring); color: var(--emerald); }
  .alert.info { background: var(--amber-bg); border: 1px solid var(--amber-ring); color: var(--amber); }
  .meta {
    margin-top: 18px; padding-top: 16px;
    border-top: 1px solid var(--border);
    display: grid; grid-template-columns: max-content 1fr;
    column-gap: 14px; row-gap: 6px;
    font-size: 12px;
  }
  .meta dt { color: var(--text-muted); }
  .meta dd { margin: 0; color: var(--text); font-variant-numeric: tabular-nums; }
  .meta dd code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; }
  footer { text-align: center; margin-top: 18px; font-size: 11px; color: var(--text-soft); }
  footer a { color: var(--accent); text-decoration: none; }
  footer a:hover { text-decoration: underline; }
  p.legal {
    margin: 12px 0 0;
    font-size: 11px;
    line-height: 1.5;
    color: var(--text-soft);
    text-align: center;
  }
  p.legal a { color: var(--accent); text-decoration: none; }
  p.legal a:hover { text-decoration: underline; }
</style>
</head>
<body>
<main class="card">
  <header>
    <div class="brand">
      <div class="brand-mark"></div>
      MeshEmbed Node <small id="version">v0</small>
    </div>
    <h1>Connect this host</h1>
    <p class="sub">
      Paste your invite token below. We'll register this machine with
      the MeshEmbed control plane and start serving jobs.
    </p>
  </header>

  <div id="alert" style="display:none"></div>

  <form id="form" autocomplete="off">
    <label class="field">
      <span class="label">Invite token</span>
      <input
        type="text"
        id="token"
        placeholder="64 hex characters"
        autocomplete="off"
        spellcheck="false"
        autofocus
      />
      <div class="hint">From your operator dashboard at <span id="backend-hint">/operator</span>.</div>
    </label>
    <button type="submit" class="primary" id="connect">Connect</button>
    <p class="legal">
      By connecting, you confirm you're authorized to enroll this
      hardware on behalf of the account that issued this token, and
      that the
      <a id="legal-link" href="https://meshembed.clusterhive.io/legal/tos" target="_blank" rel="noopener">Terms of Service</a>
      and
      <a id="privacy-link" href="https://meshembed.clusterhive.io/legal/tos" target="_blank" rel="noopener">Privacy Policy</a>
      apply.
    </p>
  </form>

  <dl class="meta" id="meta">
    <dt>Backend</dt>      <dd><code id="m-backend">…</code></dd>
    <dt>GPU</dt>          <dd id="m-gpu">detecting…</dd>
    <dt>Machine ID</dt>   <dd><code id="m-fp">…</code></dd>
    <dt>Setup port</dt>   <dd><code>127.0.0.1:7842</code></dd>
  </dl>

  <footer>
    Running on this host only. Window can be closed once connected.
  </footer>
</main>

<script>
  const $ = (id) => document.getElementById(id);
  const showAlert = (kind, html) => {
    const el = $("alert");
    el.className = "alert " + kind;
    el.innerHTML = html;
    el.style.display = "block";
  };
  const hideAlert = () => { $("alert").style.display = "none"; };

  // Load environment metadata for display.
  fetch("/api/status").then(r => r.json()).then(d => {
    $("version").textContent = "v" + (d.version || "0");
    $("m-backend").textContent = d.backend_url || "unknown";
    $("m-gpu").textContent = d.gpu_model || "no GPU detected (CPU mode)";
    $("m-fp").textContent = d.machine_fingerprint
      ? d.machine_fingerprint.slice(0, 16) + "…"
      : "—";
    $("backend-hint").textContent = (d.backend_url || "") + "/operator";
    // Point legal links at whichever backend this daemon talks to.
    if (d.backend_url) {
      const base = d.backend_url.replace(/\/+$/, "");
      $("legal-link").href = base + "/legal/tos";
      $("privacy-link").href = base + "/legal/tos";
    }
    if (d.already_configured) {
      $("connect").disabled = true;
      $("token").disabled = true;
      showAlert("success",
        "<strong>Already configured.</strong> This daemon is already " +
        "registered as <code>" + (d.node_id || "?") + "</code>. " +
        "To re-enroll, delete the credentials file and restart.");
    }
  }).catch(() => {});

  // Backoff schedule for the Connect button after a failure. Same
  // intent as the backend's per-IP failure bucket: typos shouldn't
  // hammer the network.
  const backoffSeq = [0, 1000, 2000, 4000, 8000, 16000, 30000];
  let attempt = 0;

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    hideAlert();

    const token = ($("token").value || "").trim();
    if (!/^[a-f0-9]{64}$/.test(token)) {
      showAlert("error",
        "Token must be exactly 64 lowercase hex characters (got " +
        token.length + ").");
      return;
    }

    const wait = backoffSeq[Math.min(attempt, backoffSeq.length - 1)];
    if (wait > 0) {
      $("connect").disabled = true;
      $("connect").textContent = "Waiting " + Math.ceil(wait/1000) + "s…";
      await sleep(wait);
    }

    $("connect").disabled = true;
    $("connect").textContent = "Connecting…";

    try {
      const r = await fetch("/api/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ invite_token: token }),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok) {
        attempt = 0;
        showAlert("success",
          "<strong>Connected.</strong> Registered as <code>N-" +
          String(data.node_number || 0).padStart(4, "0") +
          "</code> on " + (data.backend_url || "") +
          ". The daemon is starting. You can close this window.");
        $("token").disabled = true;
        $("connect").style.display = "none";
        return;
      }
      attempt += 1;
      const detail = data.detail || ("HTTP " + r.status);
      let friendly = detail;
      if (detail === "invite_token_format_invalid") friendly = "Token format invalid — copy it again from the operator dashboard.";
      else if (detail === "invite_token_not_found") friendly = "Token not recognized — it may have been mistyped.";
      else if (detail === "invite_token_already_used") friendly = "Token already used — generate a new one from the operator dashboard.";
      else if (detail === "invite_token_expired") friendly = "Token expired (tokens are valid for 24h) — generate a new one.";
      else if (detail === "hardware_already_registered_by_another_operator") friendly = "This machine is already registered under a different operator. Contact platform admin.";
      else if (detail === "rate_limited") friendly = "Too many attempts — slow down and try again in a minute.";
      showAlert("error", "<strong>Couldn't connect.</strong> " + friendly +
        " <span style='opacity:0.7'>(" + detail + ")</span>");
    } catch (err) {
      attempt += 1;
      showAlert("error",
        "<strong>Network error.</strong> Could not reach the backend. " +
        "Check the host's internet connection and the backend URL.");
    } finally {
      $("connect").disabled = false;
      $("connect").textContent = "Connect";
    }
  });
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    # These are filled in by start_setup_server() before binding.
    backend_url: str = ""
    gpu_model: str = ""
    machine_fingerprint: Optional[str] = None
    gpu_uuid: Optional[str] = None
    agent_version: str = "0.2.0"
    on_success: Optional[callable] = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args) -> None:
        log.info("setup_http %s - " + fmt, self.address_string(), *args)

    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'",
        )
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 — stdlib API
        if self.path in ("/", "/setup", "/setup/"):
            self._send_html(200, SETUP_HTML)
            return
        if self.path == "/api/status":
            self._send_json(200, {
                "version": _Handler.agent_version,
                "backend_url": _Handler.backend_url,
                "gpu_model": _Handler.gpu_model,
                "machine_fingerprint": _Handler.machine_fingerprint,
                "gpu_uuid": _Handler.gpu_uuid,
                "already_configured": False,
            })
            return
        self._send_json(404, {"detail": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/setup":
            self._send_json(404, {"detail": "not_found"})
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 4096:
            self._send_json(400, {"detail": "invalid_body"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._send_json(400, {"detail": "invalid_json"})
            return

        token = (payload.get("invite_token") or "").strip()
        if not INVITE_TOKEN_RE.match(token):
            self._send_json(400, {"detail": "invite_token_format_invalid"})
            return

        # Generate a fresh node_id for first-time registration.
        node_id = uuid.uuid4().hex
        body = {
            "invite_token": token,
            "node_id": node_id,
            "gpu_model": _Handler.gpu_model or "unknown",
            "agent_version": _Handler.agent_version,
            "machine_fingerprint": _Handler.machine_fingerprint,
            "gpu_uuid": _Handler.gpu_uuid,
        }

        req = urllib.request.Request(
            url=f"{_Handler.backend_url.rstrip('/')}/nodes/register",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read().decode("utf-8")
                resp_data = json.loads(resp_body)
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
                detail = err_body.get("detail", f"http_{e.code}")
            except Exception:
                detail = f"http_{e.code}"
            self._send_json(e.code, {"detail": detail})
            return
        except urllib.error.URLError as e:
            log.warning("setup.register.network_error: %s", e)
            self._send_json(502, {"detail": "backend_unreachable"})
            return
        except Exception as e:
            log.exception("setup.register.unexpected")
            self._send_json(500, {"detail": "internal_error"})
            return

        # Persist credentials to ~/.meshembed/.env (chmod 600) and
        # signal the main thread that we're done.
        try:
            _save_credentials(
                _Handler.backend_url,
                node_id,
                resp_data["api_key"],
            )
        except Exception:
            log.exception("setup.save_credentials.failed")
            self._send_json(500, {"detail": "save_failed"})
            return

        log.info(
            "setup.success node_id=%s node_number=%s",
            node_id,
            resp_data.get("node_number"),
        )
        self._send_json(200, {
            "node_id": node_id,
            "node_number": resp_data.get("node_number"),
            "backend_url": _Handler.backend_url,
        })

        # Fire the on-success callback in a background thread so we
        # don't block the HTTP response.
        if _Handler.on_success is not None:
            threading.Thread(
                target=_Handler.on_success,
                name="setup-on-success",
                daemon=True,
            ).start()


def _save_credentials(backend_url: str, node_id: str, api_key: str) -> None:
    import pathlib
    env_dir = pathlib.Path.home() / ".meshembed"
    env_dir.mkdir(parents=True, exist_ok=True)
    env_file = env_dir / ".env"
    env_file.write_text(
        f"MESHEMBED_BACKEND={backend_url}\n"
        f"MESHEMBED_NODE_API_KEY={api_key}\n"
        f"MESHEMBED_NODE_ID={node_id}\n"
    )
    env_file.chmod(0o600)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

class _ReusableServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_setup_server(
    backend_url: str,
    gpu_model: str,
    machine_fingerprint: Optional[str],
    gpu_uuid: Optional[str],
    agent_version: str = "0.2.0",
    on_success: Optional[callable] = None,  # type: ignore[assignment]
    open_browser: bool = True,
) -> Tuple[_ReusableServer, threading.Event]:
    """Start the setup HTTP server. Returns (server, done_event).

    Caller blocks on `done_event.wait()`. When the operator successfully
    submits an invite token, the `on_success` callback runs in a
    background thread; pass a closure that sets the event and any other
    state you need.

    Bound to 127.0.0.1 only — no LAN/WAN exposure.
    """
    _Handler.backend_url = backend_url
    _Handler.gpu_model = gpu_model
    _Handler.machine_fingerprint = machine_fingerprint
    _Handler.gpu_uuid = gpu_uuid
    _Handler.agent_version = agent_version
    _Handler.on_success = on_success

    server = _ReusableServer((SETUP_HOST, SETUP_PORT), _Handler)
    done = threading.Event()

    thread = threading.Thread(
        target=server.serve_forever,
        name="meshembed-setup-server",
        daemon=True,
    )
    thread.start()

    url = f"http://{SETUP_HOST}:{SETUP_PORT}/"
    log.info("setup_server.listening url=%s", url)

    # Banner so a headless operator sees the URL in their terminal.
    print()
    print("┌" + "─" * 60 + "┐")
    print("│  MeshEmbed Node — Setup required" + " " * 26 + "│")
    print("│" + " " * 60 + "│")
    print(f"│  Open this URL in your browser:" + " " * 27 + "│")
    print(f"│    {url:<56}│")
    print("│" + " " * 60 + "│")
    print("│  This window stays open until setup completes.            │")
    print("└" + "─" * 60 + "┘")
    print(flush=True)

    if open_browser:
        try:
            webbrowser.open_new(url)
        except Exception:
            # Headless server — fine, operator types the URL manually.
            pass

    return server, done


__all__ = ["start_setup_server", "SETUP_HOST", "SETUP_PORT"]
