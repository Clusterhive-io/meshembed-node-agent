"""Entry point: meshembed-node <command> [options]

Commands:
  register  --backend URL --invite TOKEN [--node-id ID] [--json]
  run       (daemon loop)
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid

from .config import Config
from .worker import run


def _save_credentials(backend: str, node_id: str, api_key: str) -> None:
    import pathlib, stat
    config_dir = pathlib.Path.home() / ".meshembed"
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    env_file = config_dir / ".env"
    env_file.write_text(
        f"MESHEMBED_BACKEND={backend}\n"
        f"MESHEMBED_NODE_API_KEY={api_key}\n"
        f"MESHEMBED_NODE_ID={node_id}\n"
    )
    env_file.chmod(0o600)


_INVITE_TOKEN_RE = __import__("re").compile(r"^[a-f0-9]{64}$")


def _cmd_register(args: argparse.Namespace) -> None:
    """Consume an invite token and register this node. Prints the API key."""
    import requests

    backend = args.backend.rstrip("/")
    node_id = args.node_id or uuid.uuid4().hex

    # Client-side format pre-check — fast feedback on typos, and matches
    # what the backend will accept anyway (anti-DDoS layer 1). Format:
    # 64 lowercase hex chars (server uses `secrets.token_hex(32)`).
    token = (args.invite or "").strip()
    if not _INVITE_TOKEN_RE.match(token):
        print(
            "Error: invite token format invalid — expected 64 hex characters\n"
            "       (lowercase a-f and 0-9, no spaces, no quotes).\n"
            f"       Got: {token[:16]}{'…' if len(token) > 16 else ''} (length {len(token)})",
            file=sys.stderr,
        )
        sys.exit(2)
    args.invite = token

    # Phase 5 hardening — Sybil defense. `collect_fingerprint()` returns
    # (fp, gpu_uuid, is_vm) as of 2026-05-22; the previous 2-target unpack
    # silently failed with ValueError and shipped `machine_fingerprint=None`,
    # which broke duplicate-laptop detection on the backend.
    from . import __version__ as _agent_version
    from .fingerprint import collect_fingerprint
    try:
        fp, gpu_uuid, is_vm = collect_fingerprint()
    except Exception as exc:
        print(f"Warning: failed to compute hardware fingerprint: {exc}", file=sys.stderr)
        fp, gpu_uuid, is_vm = None, None, False

    # Machine resources, measured HERE at enrolment (2026-08-08).
    #
    # gpu_model was hardcoded "unknown" and no memory figures were sent at all,
    # so a freshly onboarded node showed "unknown / 0 MB / 0 MB" in the dashboard
    # until its first /get_job poll happened to fill them in. The installer has
    # ALREADY detected the GPU by this point -- it prints "NVIDIA GPU detected:
    # ..." a few lines earlier -- the value simply never reached the backend, so
    # the operator could not judge a box at the moment they onboarded it.
    #
    # Every probe is best-effort: a machine that cannot report its resources must
    # still be able to enrol. Failing registration over a metrics read would be a
    # far worse outcome than a node that reports zero.
    gpu_model, vram_free_mb, ram_free_mb = "unknown", None, None
    try:
        from .worker import GPU_MODEL as _gpu, vram_free_mb as _vram
        gpu_model = _gpu or "unknown"
        vram_free_mb = _vram()
    except Exception as exc:
        print(f"Warning: could not read GPU info: {exc}", file=sys.stderr)
    try:
        import psutil as _ps
        ram_free_mb = int(_ps.virtual_memory().available / 1024 / 1024)
    except Exception as exc:
        print(f"Warning: could not read RAM info: {exc}", file=sys.stderr)

    payload = {
        "invite_token": args.invite,
        "node_id":      node_id,
        "gpu_model":    gpu_model,
        "agent_version": _agent_version,
        "machine_fingerprint": fp,
        "gpu_uuid": gpu_uuid,
        "is_vm":        is_vm,
        "force":        bool(getattr(args, "force", False)),
        # fresh=True discards an existing node on this hardware and enrols a new
        # one (reputation from zero). Default False = RE-ESTABLISH: keep the
        # node's identity and earned history, rotate only the credentials.
        "fresh":        bool(getattr(args, "fresh", False)),
        "vram_free_mb": vram_free_mb,
        "ram_free_mb":  ram_free_mb,
    }
    try:
        resp = requests.post(f"{backend}/nodes/register", json=payload, timeout=15)
        resp.raise_for_status()
    except requests.HTTPError as exc:
        detail = ""
        try:
            detail = exc.response.json().get("detail", "")
        except Exception:
            pass
        print(f"Error: {exc} — {detail}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    # The backend may have RE-ESTABLISHED an existing node rather than creating
    # one, in which case its node_id is authoritative and differs from the uuid
    # we generated. Echoing our own would write the wrong id into .env.
    node_id = data.get("node_id") or node_id
    data["node_id"] = node_id

    if args.json:
        print(json.dumps(data))
    else:
        print(f"Node registered:")
        print(f"  node_id:     {data['node_id']}")
        print(f"  node_number: N-{data['node_number']:04d}")
        print(f"  api_key:     {data['api_key']}")
        print()

    # Save credentials to ~/.meshembed/.env unless --no-save was passed.
    if not getattr(args, "no_save", False):
        _save_credentials(args.backend, data["node_id"], data["api_key"])
        if not args.json:
            import pathlib
            env_path = pathlib.Path.home() / ".meshembed" / ".env"
            print(f"Credentials saved to {env_path}")
            print("Start the daemon with: meshembed-node run")


def _setup_logging() -> None:
    """Log to stdout AND ~/.meshembed/node.log on every platform.

    The mac LaunchAgent redirects stdout to node.log, but the Windows scheduled
    task and the systemd unit may not — so a daemon that crashed on startup left
    no trace on those platforms (this is what made the 2026-06 'node shows
    offline but the box is up' issue undiagnosable). A self-managed FileHandler
    guarantees node.log exists wherever the daemon runs. Best-effort: never block
    startup if the log file can't be opened."""
    import pathlib

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        log_dir = pathlib.Path.home() / ".meshembed"
        log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / "node.log", encoding="utf-8"))
    except Exception as exc:  # pragma: no cover — never block on logging
        print(f"Warning: could not open node.log: {exc}", file=sys.stderr)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )


def _cmd_run(args: argparse.Namespace) -> None:
    _setup_logging()

    # If credentials are missing, run the browser-based setup flow
    # first. The setup server blocks until the operator submits a
    # valid invite token, then we proceed into the normal poll loop
    # with the freshly-written credentials.
    if not _credentials_present():
        _run_setup_flow(args)

    cfg = Config()
    run(cfg)


def _credentials_present() -> bool:
    """Check if the daemon already has an API key + node id either in
    the environment or in `~/.meshembed/.env`. Mirrors what Config()
    reads — if it'd raise on missing required vars, we treat it as
    'needs setup'.
    """
    import os, pathlib
    if os.environ.get("MESHEMBED_NODE_API_KEY") and os.environ.get("MESHEMBED_NODE_ID"):
        return True
    env_file = pathlib.Path.home() / ".meshembed" / ".env"
    if not env_file.exists():
        return False
    try:
        content = env_file.read_text()
    except Exception:
        return False
    return ("MESHEMBED_NODE_API_KEY=" in content
            and "MESHEMBED_NODE_ID=" in content)


def _run_setup_flow(args: argparse.Namespace) -> None:
    """Block the daemon until first-time setup completes. Starts the
    local-browser setup server at 127.0.0.1:7842, opens the system
    browser, waits for the operator to submit a valid invite token,
    then returns.
    """
    import os, threading, time
    from . import __version__ as _agent_version
    from .setup_server import start_setup_server
    from .fingerprint import collect_fingerprint

    backend = os.environ.get(
        "MESHEMBED_BACKEND", "https://meshembed.clusterhive.io"
    ).rstrip("/")

    try:
        fp, gpu_uuid, _is_vm = collect_fingerprint()
    except Exception:
        fp, gpu_uuid, _is_vm = None, None, False

    # Best-effort GPU model name for the setup page.
    gpu_model = "unknown"
    try:
        from .worker import GPU_MODEL  # type: ignore[attr-defined]
        gpu_model = GPU_MODEL or "unknown"
    except Exception:
        pass

    done = threading.Event()

    def _on_success() -> None:
        # Tiny grace period so the HTTP 200 reaches the browser before
        # we tear the server down.
        time.sleep(1.0)
        done.set()

    server, _evt = start_setup_server(
        backend_url=backend,
        gpu_model=gpu_model,
        machine_fingerprint=fp,
        gpu_uuid=gpu_uuid,
        agent_version=_agent_version,
        on_success=_on_success,
        open_browser=True,
    )

    try:
        done.wait()
    except KeyboardInterrupt:
        print("\nSetup cancelled by user.", file=sys.stderr)
        server.shutdown()
        sys.exit(130)

    server.shutdown()
    server.server_close()
    print("Setup complete. Starting daemon…", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="meshembed-node",
        description="MeshEmbed Node daemon",
    )
    sub = parser.add_subparsers(dest="command")

    # register
    p_reg = sub.add_parser("register", help="Register this node with an invite token")
    p_reg.add_argument("--backend", required=True, help="Backend URL, e.g. https://meshembed.clusterhive.io")
    p_reg.add_argument("--invite",  required=True, help="Single-use invite token")
    p_reg.add_argument("--node-id", dest="node_id", default=None, help="Node UUID (auto-generated when omitted)")
    p_reg.add_argument("--json", action="store_true", help="JSON output (for scripts)")
    p_reg.add_argument("--no-save", dest="no_save", action="store_true", help="Do not save credentials to ~/.meshembed/.env")
    p_reg.add_argument("--force", action="store_true", help="Allow registering a second node on hardware already registered by this operator")
    p_reg.add_argument(
        "--fresh",
        action="store_true",
        help=(
            "Discard this hardware's existing node and enrol a NEW one "
            "(reputation starts from zero). Default is to re-establish: keep "
            "the node's identity and earned history, rotate credentials only."
        ),
    )

    # run
    sub.add_parser("run", help="Start the daemon (uses environment variables)")

    args = parser.parse_args()

    if args.command == "register":
        _cmd_register(args)
    elif args.command == "run":
        _cmd_run(args)
    else:
        # Backwards compatibility: no subcommand → run directly. (The service
        # registrations now pass 'run' explicitly, but a bare invocation must
        # still start the daemon, not error out.)
        _setup_logging()
        cfg = Config()
        run(cfg)


if __name__ == "__main__":
    main()
