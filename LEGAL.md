# Legal notice

## What this repository is

`meshembed-node-agent` is the source code of the daemon that operators
run on their GPU hosts to participate in the [MeshEmbed][platform]
distributed embedding network. The daemon is **open-source software**
licensed under [Apache License 2.0](LICENSE). That license governs
your right to **use, copy, modify, and redistribute the software
itself**.

It does **not** govern your relationship with the MeshEmbed service.

## When you become bound to anything

| Action | What you're agreeing to |
|---|---|
| Cloning this repo | The Apache 2.0 license (read [LICENSE](LICENSE)). Nothing else. |
| Building / running the daemon locally without an invite token | The Apache 2.0 license. The daemon does nothing — it just shows you the setup screen. |
| **Pasting an invite token + clicking Connect on `127.0.0.1:7842`** | The [MeshEmbed Terms of Service][tos] and the Privacy Policy linked from there. The invite token was issued by an operator account that already accepted the TOS at signup; by enrolling this machine you confirm you're authorized to act on behalf of that account. |
| Daemon polling and processing jobs after enrollment | Same — ongoing service use under the same TOS. |

## What the daemon sends to the control plane

After enrollment, on every `/get_job` and `/report_result`:

- `node_id` — assigned at registration.
- `machine_fingerprint` — `sha256(cpu_id + ram_size + first_mac + disk_serial + board_id)`. Hex digest. Not directly personally identifying; used to detect identity theft / Sybil registration.
- `gpu_uuid` — NVIDIA firmware-level GPU UUID, when present.
- `gpu_model`, `vram_free_mb`, `ram_free_mb`, `max_chunks` — capability snapshot.
- `agent_version` — for compatibility checks.
- IP address (server-side from the TCP connection / `X-Forwarded-For` header).

These fields are processed under GDPR Article 6(1)(b) — necessary for
the performance of the contract you formed at enrollment. See the
[Privacy Policy section of the TOS][tos] for retention timelines,
data-subject rights, and the contact address.

## What the daemon does NOT send

- No screenshots, no microphone, no clipboard.
- No general system telemetry beyond the capability snapshot above.
- No data from other processes on the host.
- The text content you embed on behalf of clients is processed
  in-memory and the input is never written to disk by the daemon.
  Embeddings (the output) are sent back to the control plane signed
  with the node's ed25519 key.

## Verifying what you're running

- Source for every release tag is in this repo. Diff against
  `git checkout v0.2.0` for what's in your binary.
- GitHub Actions builds the official binaries — workflow at
  [`.github/workflows/release.yml`](.github/workflows/release.yml).
- Each Release publishes a `SHA256SUMS` file alongside the artifacts.
  Verify with `shasum -a 256 -c SHA256SUMS` (Linux/macOS) or
  `Get-FileHash <file> -Algorithm SHA256` (Windows).

## Reporting issues

- **Code bugs / install problems**: open an issue on this repository.
- **Account, billing, payouts, KYC, takedown requests**: write to
  `legal@clusterhive.io`.
- **GDPR data-subject requests**: write to `gdpr@clusterhive.io`.

[platform]: https://meshembed.clusterhive.io
[tos]: https://meshembed.clusterhive.io/legal/tos
