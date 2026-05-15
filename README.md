# MeshEmbed Node

GPU worker daemon for the [MeshEmbed](https://meshembed.clusterhive.io)
distributed embedding network. Runs on the operator's GPU host, polls
the MeshEmbed control plane for embedding subjobs, processes them with
a local embedding model (`intfloat/multilingual-e5-small` for v0.2.x),
and returns the vectors signed with the node's ed25519 key.

## Quick start

The fastest path is the one-liner from the operator dashboard
(https://meshembed.clusterhive.io/operator). On first run, the daemon
opens `http://127.0.0.1:7842/` in your browser; paste the invite token
your operator dashboard gave you and you're connected.

### Linux

```bash
curl -fsSL https://meshembed.clusterhive.io/install/linux -o install.sh
bash install.sh
```

### macOS

```bash
curl -fsSL https://meshembed.clusterhive.io/install/macos -o install-mac.sh
bash install-mac.sh
```

### Windows (PowerShell)

```powershell
iwr https://meshembed.clusterhive.io/install/windows -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

After installation the daemon launches with no token. It listens on
`127.0.0.1:7842` and opens your browser to the setup page. Paste the
invite token from your operator dashboard and the node registers
itself.

## Native installer packages (when a release tag exists)

Pre-built packages for tagged releases - produced by GitHub Actions on
the corresponding OS runner:

| Asset | Platform | Service installed as |
|---|---|---|
| `meshembed-node_<ver>_amd64.deb` | Debian / Ubuntu | systemd `meshembed-node.service` |
| `meshembed-node-<ver>-1.x86_64.rpm` | Fedora / RHEL | systemd `meshembed-node.service` |
| `MeshEmbedNode-<ver>.pkg` | macOS | LaunchAgent `io.clusterhive.meshembed-node` |
| `MeshEmbedNode-<ver>.msi` | Windows 10/11 | Windows Service `MeshEmbedNode` |

Pull from the [Releases](https://github.com/Clusterhive-io/meshembed-node-agent/releases)
tab or via the redirect endpoints:

```
https://meshembed.clusterhive.io/install/deb
https://meshembed.clusterhive.io/install/rpm
https://meshembed.clusterhive.io/install/pkg
https://meshembed.clusterhive.io/install/msi
```

(302-redirected to the GitHub Release asset of the currently-active
tag.)

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
