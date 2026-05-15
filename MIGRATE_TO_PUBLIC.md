# Migrating `node-agent/` to its own public repo

> One-shot guide. Run these once `Clusterhive-io/meshembed-node-agent`
> exists on github.com (created as an **empty** public repo, no README
> / no license — we'll push them in step 4).

## 0. Prerequisites

- An empty public repo at `github.com/<org>/meshembed-node-agent`.
- An SSH key with push rights to that repo (you can use the same one
  you use for any other CH repo, or generate a deploy key).
- This monorepo cloned somewhere with the `node-agent/` directory
  intact (the contents of which become the new repo's root).

## 1. From this monorepo, push a snapshot

```bash
cd /home/infra/clusterhive-meshembed/repo/node-agent

# Initialize a fresh repo here (we don't want to drag the monorepo
# history into the public node-agent repo — that history is private
# to the meshembed control plane).
git init
git add -A
git commit -m "Initial public release v0.2.0"

# Push.
git branch -M main
git remote add origin git@github.com:Clusterhive-io/meshembed-node-agent.git
git push -u origin main
```

## 2. Tag the release — that triggers the build workflow

```bash
git tag v0.2.0
git push origin v0.2.0
```

Watch the Actions tab on github.com. Three jobs run (linux, macos,
windows) plus a release job that aggregates artifacts. ETA ~12-15
minutes (macos runners are the slow one).

When green: a Release page exists at
`github.com/<org>/meshembed-node-agent/releases/tag/v0.2.0` with the
four artifacts + a `SHA256SUMS` file.

## 3. Flip the env on 188 so the UI starts showing native binaries

```bash
ssh meshembed-backend
echo 'MESHEMBED_INSTALLER_TAG=v0.2.0' >> /home/automation/clusterhive-meshembed/.env
cd /home/automation/clusterhive-meshembed
sudo docker compose up -d backend
```

The frontend reads `/platform/status.installer.binaries_available` on
the next user mount. Refresh `/operator` — the binary download row
appears under Step 1 of "Add a new node" with `.deb` / `.rpm` for
Linux, `.pkg` for macOS, `.msi` for Windows. Each button is a 302 to
the GH Release asset.

## 4. (Optional) Pull the new repo back as a submodule for dev

If you want to keep developing the daemon from the monorepo:

```bash
cd /home/infra/clusterhive-meshembed/repo
rm -rf node-agent
git submodule add git@github.com:Clusterhive-io/meshembed-node-agent.git node-agent
git submodule update --init
```

The Dockerfile / scripts that reference `node-agent/install.sh` etc.
keep working — submodule mounts the same contents at the same path.

## 5. Subsequent releases

Bump version in `pyproject.toml`, commit, tag `vX.Y.Z`, push the tag.
GH Actions rebuilds everything. Then:

```bash
ssh meshembed-backend "sed -i 's/^MESHEMBED_INSTALLER_TAG=.*/MESHEMBED_INSTALLER_TAG=vX.Y.Z/' \
    /home/automation/clusterhive-meshembed/.env && \
    cd /home/automation/clusterhive-meshembed && sudo -n docker compose up -d backend"
```

No app redeploy needed — env is read per-request. Old release stays
downloadable at its tag URL; latest is whatever `MESHEMBED_INSTALLER_TAG`
points at.

## Rollback

To revert to a previous release, set the env back:
`MESHEMBED_INSTALLER_TAG=v0.1.x`. The UI immediately starts serving
that tag's assets. No data migrations involved — daemons in the field
keep running until you also push out a new install URL.

To revert to the pre-release state (script-only install), set
`MESHEMBED_INSTALLER_TAG=` (empty). The OperatorView falls back to
script-only.
