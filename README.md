# MeshEmbed Node

GPU worker daemon for the [MeshEmbed](https://meshembed.clusterhive.io)
distributed embedding network. Runs on the operator's GPU host, polls
the MeshEmbed control plane for embedding subjobs, processes them with
a local embedding model (`intfloat/multilingual-e5-small` for v0.2.x),
and returns the vectors signed with the node's ed25519 key.

## Quick start

The fastest path is the one-liner from the operator dashboard
(https://meshembed.clusterhive.io/operator) — open it, copy the
install command, paste in your terminal.

For each OS there are **two install paths**:

* **Native package (recommended)** — a self-contained `.pkg` / `.msi` /
  `.deb` / `.rpm` that ships its own Python interpreter (via [`uv`])
  and all ML dependencies. Zero prerequisites. After install the
  daemon opens `http://127.0.0.1:7842` in your browser; paste the
  invite token there to register.
* **Shell / PowerShell script (advanced)** — requires Python 3.10+
  on the host (3.11 or 3.12 on Intel macOS — see below). The token
  is passed inline via the `INVITE` env var; the daemon registers
  and starts polling immediately. No browser step.

The dashboard auto-picks the right command for your OS. The full
walk-through lives at
[`/node-install-guide.html`](https://meshembed.clusterhive.io/node-install-guide.html).

### Linux

**Native (`.deb` / `.rpm`):**

```bash
# Debian / Ubuntu
curl -fsSL https://meshembed.clusterhive.io/install/deb -o meshembed-node.deb
sudo apt install -y ./meshembed-node.deb

# Fedora / RHEL
curl -fsSL https://meshembed.clusterhive.io/install/rpm -o meshembed-node.rpm
sudo rpm -i meshembed-node.rpm
```

**Shell script:**

```bash
curl -fsSL https://meshembed.clusterhive.io/install.sh | \
    INVITE='PASTE-TOKEN-HERE' BACKEND='https://meshembed.clusterhive.io' bash
```

### macOS

**Native (`.pkg`, recommended):**

```bash
curl -fsSL https://meshembed.clusterhive.io/install/pkg -o MeshEmbedNode.pkg
xattr -d com.apple.quarantine MeshEmbedNode.pkg 2>/dev/null
sudo installer -pkg MeshEmbedNode.pkg -target / -allowUntrusted
```

The `.pkg` isn't signed with an Apple Developer ID yet (planned for
v0.4.x), so `-allowUntrusted` and `xattr -d` are needed today. If you
prefer Finder, **right-click the .pkg → "Open"** then confirm.

**Shell script (advanced):**

```bash
curl -fsSL https://meshembed.clusterhive.io/install-mac.sh | \
    INVITE='PASTE-TOKEN-HERE' BACKEND='https://meshembed.clusterhive.io' bash
```

Requires Python 3.11 or 3.12 (`brew install python@3.12` if missing).
On Intel Mac, Python 3.13 is auto-rejected because PyTorch doesn't
ship Intel-mac 3.13 wheels yet. The `.pkg` path above sidesteps this
entirely.

### Windows (PowerShell)

**Native (`.msi`):**

```powershell
iwr https://meshembed.clusterhive.io/install/msi -OutFile MeshEmbedNode.msi
msiexec /i MeshEmbedNode.msi
```

**Shell script:**

```powershell
iwr https://meshembed.clusterhive.io/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1 -InviteToken 'PASTE-TOKEN-HERE' -BackendUrl 'https://meshembed.clusterhive.io'
```

### Native-package asset map

Pre-built packages produced by GitHub Actions on the corresponding OS
runner for every tag push:

| Asset | Platform | Bundled runtime | Service installed as |
|---|---|---|---|
| `meshembed-node_<ver>_amd64.deb` | Debian / Ubuntu | system Python | systemd `meshembed-node.service` |
| `meshembed-node-<ver>-1.x86_64.rpm` | Fedora / RHEL | system Python | systemd `meshembed-node.service` |
| `MeshEmbedNode-<ver>.pkg` | macOS | bundled `uv` + Python 3.12 (per-install venv) | LaunchAgent `io.clusterhive.meshembed-node` |
| `MeshEmbedNode-<ver>.msi` | Windows 10/11 | PyInstaller-bundled Python | Windows Service `MeshEmbedNode` |

Direct redirect endpoints (302 → current tag's GitHub Release asset):

```
https://meshembed.clusterhive.io/install/deb
https://meshembed.clusterhive.io/install/rpm
https://meshembed.clusterhive.io/install/pkg
https://meshembed.clusterhive.io/install/msi
```

[`uv`]: https://github.com/astral-sh/uv

## What the daemon does

1. On startup, looks for `MESHEMBED_NODE_API_KEY` and `MESHEMBED_NODE_ID`
   in env or in `~/.meshembed/.env`. If missing, opens the setup
   browser flow (see below).
2. Once configured, polls `POST /get_job` against the MeshEmbed
   backend every 1–30 seconds (adaptive). On each request the node
   reports its current status, GPU/RAM availability, hardware
   fingerprint and GPU UUID.
3. When assigned a subjob, runs the embedding model locally, signs
   the result with its ed25519 key, and posts to `POST /report_result`.
4. Repeats. The backend audits each result against canary jobs and
   cross-validation; nodes returning bad embeddings lose reputation
   and eventually get banned.

## First-run browser setup

When the daemon starts and has no credentials, instead of bailing it
starts a tiny HTTP server on `127.0.0.1:7842` (loopback only - never
exposed to the network) and opens the system browser. The setup page
shows:

- The MeshEmbed Node version banner.
- Detected GPU model and machine fingerprint (so the operator confirms
  they're enrolling the right host).
- A single input for the invite token.
- A Connect button that POSTs the token to the backend
  `/nodes/register` endpoint.

On success, the daemon writes the returned API key + node id to
`~/.meshembed/.env` (`chmod 600`), shuts the setup server down, and
transitions into its normal poll loop.

To re-trigger setup later (e.g. to rotate keys), delete
`~/.meshembed/.env` and restart the daemon.

## Configuration

Environment variables read at startup (and from
`~/.meshembed/.env` if present):

| Var | Default | Meaning |
|---|---|---|
| `MESHEMBED_BACKEND` | `https://meshembed.clusterhive.io` | Backend base URL |
| `MESHEMBED_NODE_API_KEY` | - | API key issued at registration |
| `MESHEMBED_NODE_ID` | - | Node UUID assigned at registration |
| `MESHEMBED_MODEL` | `intfloat/multilingual-e5-small` | Embedding model |
| `MESHEMBED_POLL_MIN_S` | `1` | Min poll interval (active periods) |
| `MESHEMBED_POLL_MAX_S` | `30` | Max poll interval (idle backoff) |
| `MESHEMBED_MAX_CHUNKS` | `1` | Max parallel chunks per assignment |
| `MESHEMBED_NODE_PRIVKEY` | (auto-generated) | ed25519 hex private key |

## Manual install / dev

```bash
git clone https://github.com/Clusterhive-io/meshembed-node-agent
cd meshembed-node-agent
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                                # +.[gpu] for CUDA hosts
meshembed-node run                              # opens browser to 127.0.0.1:7842
```

Tests:

```bash
pip install -e .[dev]
pytest tests/
```

## Hardware fingerprint

Each daemon computes a stable `machine_fingerprint` (sha256 of
CPU+RAM+MAC+disk+motherboard identifiers) and reports the NVIDIA
`gpu_uuid` (firmware-bound, hard to spoof) at registration. The
backend stores both and verifies them on every subsequent
`/get_job` and `/report_result` request - copying the daemon's
`.env` to a different physical box no longer works because the
fingerprint won't match.

See `meshembed_node/fingerprint.py` for details.

## License

Apache 2.0 - see [LICENSE](LICENSE).

## Reporting issues

The MeshEmbed control-plane code (backend + UI) is in a separate
repository. For agent-side bugs, please open an issue here. For
control-plane / API issues, contact the platform admin.
