#!/usr/bin/env bash
# MeshEmbed Node - Linux installer (Ubuntu, Debian, RHEL, Arch...)
# Usage: bash install.sh [invite_token]
#
# Installs into a dedicated venv. The Python runtime is provisioned via `uv`
# (a standalone manager): on modern/minimal images the system Python is often
# 3.13+ (no torch/numpy<2 wheels) or has no pip, so uv can download a clean,
# pinned Python 3.12. If a usable system Python is present you're asked whether
# to keep it or provision a fresh one (override non-interactively with
# MESHEMBED_PYTHON=uv|system|/path/to/python).
set -euo pipefail

# ── OS check ─────────────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This script is Linux-only."
    echo "  macOS:   bash install-mac.sh"
    echo "  Windows: .\\install.ps1"
    exit 1
fi

# The operator dashboard pipes `curl ... | INVITE='token' BACKEND='url' bash`
# so honor those env vars first; fall back to positional $1 + the
# MESHEMBED_* env vars that older docs reference.
BACKEND_URL="${BACKEND:-${MESHEMBED_BACKEND:-https://meshembed.clusterhive.io}}"
INVITE_TOKEN="${1:-${INVITE:-${MESHEMBED_INVITE:-}}}"

# --- Production guard rail (ROGUE_LAB ISSUE A) ------------------------------
# BACKEND defaults to production when unset, which is correct for the
# documented operator one-liner but dangerous for test/lab installs: a
# forgotten BACKEND silently enrolls the box onto PRODUCTION. Test harnesses
# export MESHEMBED_REFUSE_PROD=1 once, and any install that would land on prod
# then aborts instead of quietly succeeding.
case "$BACKEND_URL" in
    *meshembed.clusterhive.io*)
        case "$BACKEND_URL" in
            *sandbox*) IS_PROD_BACKEND=0 ;;
            *)         IS_PROD_BACKEND=1 ;;
        esac ;;
    *) IS_PROD_BACKEND=0 ;;
esac
if [ "${MESHEMBED_REFUSE_PROD:-0}" = "1" ] && [ "$IS_PROD_BACKEND" = "1" ]; then
    echo "REFUSING TO INSTALL: backend resolves to PRODUCTION ($BACKEND_URL)" >&2
    echo "  MESHEMBED_REFUSE_PROD=1 is set, so this looks like a test install." >&2
    echo "  Set BACKEND explicitly, e.g." >&2
    echo "    BACKEND='https://sandbox-meshembed.clusterhive.io'" >&2
    exit 2
fi


bold=$(tput bold 2>/dev/null || true)
reset=$(tput sgr0 2>/dev/null || true)
green='\033[0;32m'; red='\033[0;31m'; yellow='\033[0;33m'; nc='\033[0m'

info() { echo "${bold}[meshembed]${reset} $*"; }
ok()   { echo -e "${green}✓${nc} $*"; }
warn() { echo -e "${yellow}!${nc} $*"; }
fail() { echo -e "${red}✗${nc} $*"; exit 1; }

# ── GPU detection (drives the [gpu] extra) ────────────────────────────────────
# Detecting the GPU is not enough: the torch BUILD must match the installed
# driver. The default (PyPI) torch is a CUDA-12 build and needs driver >= 525.
# On an older driver it installs fine, imports fine, and then reports
# `torch.cuda.is_available() == False` -- so the daemon silently falls back to
# CPU, the benchmark measures CPU speed, and max_chunks_auto is calibrated down.
# Entirely invisible unless someone reads the node's journal.
#
# Seen on prod: a Tesla M60 on driver 470 (CUDA 11.4) ran CPU-only for a week
# ("NVIDIA GPU detected (Tesla M60) but torch.cuda can't use it -- driver likely
# too old. Falling back to CPU."), capping that node at 2 chunks.
#
# So: read the driver version and pick the matching wheel index. CUDA 11.x has
# minor-version compatibility (any 11.x runtime works on driver >= 450.80.02),
# which is why cu118 is the right target for the 450-524 range.
CUDA_INDEX_URL=""          # empty = default PyPI (CUDA 12 build)
GPU_DRIVER_VER=""
if command -v nvidia-smi &>/dev/null; then
    GPU=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 || echo "NVIDIA")
    GPU_DRIVER_VER=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 | tr -d ' ')
    ok "NVIDIA GPU detected: $GPU (driver ${GPU_DRIVER_VER:-unknown})"
    INSTALL_EXTRAS="[gpu]"
    _drv_major="${GPU_DRIVER_VER%%.*}"
    if [ -n "$_drv_major" ] && [ "$_drv_major" -lt 525 ] 2>/dev/null; then
        CUDA_INDEX_URL="https://download.pytorch.org/whl/cu118"
        warn "  Driver ${GPU_DRIVER_VER} is older than 525: the default CUDA-12"
        warn "  torch cannot use this GPU and would silently run on CPU."
        warn "  Installing the CUDA 11.8 build instead."
    fi
else
    info "No NVIDIA GPU detected - CPU mode will be used"
    INSTALL_EXTRAS=""
fi

# ── Upgrade-vs-fresh-install detection ───────────────────────────────────────
# When the daemon's auto-update channel fires, _perform_self_update execs this
# script with the daemon's env (MESHEMBED_NODE_API_KEY + MESHEMBED_NODE_ID) but
# no INVITE. Detect that and short-circuit to "upgrade the existing venv, then
# exit" — skip the invite prompt, register, .env write, and unit reinstall.
EXISTING_ENV="$HOME/.meshembed/.env"
UPGRADE_ONLY=0
if [ -f "$EXISTING_ENV" ] && grep -q '^MESHEMBED_NODE_API_KEY=' "$EXISTING_ENV"; then
    UPGRADE_ONLY=1
elif [ -n "${MESHEMBED_NODE_API_KEY:-}" ] && [ -n "${MESHEMBED_NODE_ID:-}" ]; then
    UPGRADE_ONLY=1
elif command -v systemctl >/dev/null 2>&1 \
        && systemctl cat meshembed-node.service >/dev/null 2>&1; then
    info "Existing meshembed-node.service detected -- treating as upgrade."
    UPGRADE_ONLY=1
fi

# An explicit INVITE, or REENROLL=1, OVERRIDES all of the above.
#
# Passing an invite IS the instruction to enrol. The detection above used to win
# anyway, so an operator who had deleted a node from the dashboard and re-ran the
# documented one-liner WITH a fresh token got "UPGRADE-ONLY mode (no re-register)"
# and a node that silently kept its old identity -- which /get_job then
# auto-registered straight back, undoing the deletion within seconds.
#
# The auto-update path is unaffected: _perform_self_update execs this script with
# the daemon's env and deliberately NO invite, so it still takes the upgrade path.
if [ "$UPGRADE_ONLY" -eq 1 ] \
        && { [ -n "$INVITE_TOKEN" ] || [ "${REENROLL:-0}" = "1" ]; }; then
    if [ -n "$INVITE_TOKEN" ]; then
        info "INVITE supplied -- re-enrolling (overrides upgrade-only detection)."
    else
        info "REENROLL=1 -- forcing a clean re-enrollment."
    fi
    # Move the old credentials aside rather than deleting them: if registration
    # fails the operator still has the previous identity to fall back on, and a
    # node that has lost its key and gained nothing is worse than one that never
    # tried.
    if [ -f "$EXISTING_ENV" ]; then
        _bak="${EXISTING_ENV}.replaced-$(date +%Y%m%d-%H%M%S)"
        mv "$EXISTING_ENV" "$_bak"
        info "Previous credentials saved to $_bak"
    fi
    # These are exported into the auto-update path's environment; clear them or
    # Config() would pick the OLD identity back up after registration.
    unset MESHEMBED_NODE_API_KEY MESHEMBED_NODE_ID

    # STOP THE OLD DAEMON NOW, and remember where it lived.
    #
    # Re-enrolling replaces this box's identity. The already-running daemon still
    # holds the OLD credentials in memory, and the backend has just given its
    # node row away -- so every poll it makes from here is dead traffic against an
    # identity that no longer exists. Leaving it running is what produced two
    # hours of `get_job failed` on 2026-08-08.
    #
    # Capturing the old ExecStart matters because the daemon may live in a
    # DIFFERENT venv from the one we are about to create; without this the box
    # ends up with two installs and systemd pointing at the stale one.
    OLD_VENV=""
    if command -v systemctl >/dev/null 2>&1; then
        OLD_EXEC=$(systemctl show -p ExecStart --value meshembed-node.service 2>/dev/null || true)
        OLD_VENV=$(printf '%s' "$OLD_EXEC" | grep -oE '/[^ ]*/\.venv' | head -1 || true)
        info "Stopping the existing daemon before re-enrolling..."
        systemctl stop meshembed-node.service 2>/dev/null \
            || sudo -n systemctl stop meshembed-node.service 2>/dev/null \
            || info "  (could not stop it automatically -- it will unenroll itself on 401)"
    fi
    UPGRADE_ONLY=0
fi

# ── Invite token ──────────────────────────────────────────────────────────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Existing enrollment detected -- running in UPGRADE-ONLY mode (no re-register)."
elif [ -z "$INVITE_TOKEN" ]; then
    if [ -t 0 ]; then
        echo ""
        read -rp "Invite token (get one from the operator dashboard): " INVITE_TOKEN
    else
        fail "Invite token required. Use: curl ... | INVITE='your_token' bash    or pass it as arg 1."
    fi
fi
if [ "$UPGRADE_ONLY" -ne 1 ]; then
    [ -n "$INVITE_TOKEN" ] || fail "Invite token required"
fi

# NOTE: this literal is only a fallback for a bare `curl | bash` install. Any
# OTA passes MESHEMBED_RELEASE_TAG explicitly (see worker._perform_self_update),
# because a stale literal here silently broke every self-update: the post-install
# guard below compared the freshly-installed version against THIS value.
RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.51}"
REPO="Clusterhive-io/meshembed-node-agent"
PACKAGE_URL="${MESHEMBED_PACKAGE_URL:-https://github.com/${REPO}/archive/refs/tags/${RELEASE_TAG}.tar.gz}"

# ── Verify release signature ────────────────────────────────────────────────
# This file had NO verification at all, while COUNTERMEASURES.md claimed it
# verified against a pinned key. OTA self-update IS strictly verified (see
# worker._perform_self_update); the FIRST install was not, on any platform.
#
# Fail-closed once published: a missing SHA256SUMS warns, a present-but-invalid
# one aborts. SHA256SUMS is not published yet (measured 404 at v0.3.49/v0.3.50),
# so making it mandatory today would break every install -- see
# docs/RELEASE_SIGNING_STATE.md for the required order.
RELEASE_PUBKEY_HEX="${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-110ca603f1b4d850b5a956fbe34a9f4ba21e271afd10cb02baef6cf242236408}"
SUMS_URL="https://raw.githubusercontent.com/${REPO}/refs/tags/${RELEASE_TAG}/SHA256SUMS"
if [ -n "$RELEASE_PUBKEY_HEX" ] && [ -z "${MESHEMBED_PACKAGE_URL:-}" ]; then
    TMPSIG=$(mktemp -d)
    if curl -fsSL "$SUMS_URL" -o "$TMPSIG/SHA256SUMS" 2>/dev/null; then
        curl -fsSL "${SUMS_URL}.sig" -o "$TMPSIG/SHA256SUMS.sig" \
            || fail "SHA256SUMS published but SHA256SUMS.sig missing -- refusing to install unverified code"
        python3 - "$TMPSIG/SHA256SUMS" "$TMPSIG/SHA256SUMS.sig" "$RELEASE_PUBKEY_HEX" <<'PYEOF' \
            || fail "release signature verification FAILED -- aborting install"
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
sums, sig, pub_hex = sys.argv[1], sys.argv[2], sys.argv[3]
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
try:
    pub.verify(open(sig, 'rb').read(), open(sums, 'rb').read())
    print('ok')
except InvalidSignature:
    print('INVALID', file=sys.stderr); sys.exit(1)
PYEOF
        info "release signature valid"
        # Bind the pip TARBALL to the now-authenticated SHA256SUMS. Verifying
        # the SUMS signature only proves the LIST is genuine; the artifact we
        # actually install must match a hash IN it -- otherwise a
        # signature-verified installer script still `pip install`s an unchecked
        # archive (the gap this closes). Download it, compare its sha256 to the
        # entry for its archive name, install from the verified LOCAL copy. Not
        # listed -> warn and fall back to the URL install (graceful); listed but
        # MISMATCHED -> tampering -> abort. The tarball is GitHub's on-demand
        # source archive, so sign-release.py must hash the same bytes GitHub
        # serves for ${RELEASE_TAG} (see docs/RELEASE_SIGNING_STATE.md).
        if [ -z "${MESHEMBED_PACKAGE_URL:-}" ]; then
            _TARBALL_NAME="${RELEASE_TAG}.tar.gz"
            _WANT_SHA=$(awk -v f="$_TARBALL_NAME" '$2==f {print $1}' "$TMPSIG/SHA256SUMS" | head -1)
            if [ -n "$_WANT_SHA" ]; then
                _VTMP=$(mktemp -d)
                curl -fsSL "$PACKAGE_URL" -o "$_VTMP/$_TARBALL_NAME" \
                    || fail "could not download the release tarball to verify it"
                _GOT_SHA=$(sha256sum "$_VTMP/$_TARBALL_NAME" | awk '{print $1}')
                [ "$_GOT_SHA" = "$_WANT_SHA" ] \
                    || fail "release TARBALL sha256 mismatch -- refusing to install tampered code (expected $_WANT_SHA, got $_GOT_SHA)"
                info "release tarball verified against SHA256SUMS"
                PACKAGE_URL="file://$_VTMP/$_TARBALL_NAME"
            else
                info "SHA256SUMS does not list ${_TARBALL_NAME}; tarball hash NOT verified (installer-script sig still enforced)"
            fi
        fi
    else
        info "release signature verification SKIPPED: SHA256SUMS not published for ${RELEASE_TAG}"
        info "  (updates ARE signature-verified; this is the first-install gap)"
    fi
    rm -rf "$TMPSIG"
fi

# Canonical venv location: /opt for root, ~/.meshembed for unprivileged.
if [ "$(id -u)" -eq 0 ]; then
    VENV_DIR="${MESHEMBED_VENV_DIR:-/opt/meshembed-node/.venv}"
else
    VENV_DIR="${MESHEMBED_VENV_DIR:-$HOME/.meshembed/.venv}"
fi

ensure_uv() {
    if command -v uv >/dev/null 2>&1; then return; fi
    info "Installing uv (standalone Python/venv manager)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 \
        || fail "uv install failed -- need network access to astral.sh."
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    command -v uv >/dev/null 2>&1 || fail "uv not on PATH after install."
}

# ── Resolve the venv interpreter ──────────────────────────────────────────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    # Install into the interpreter the daemon ACTUALLY runs from. This is the
    # crux of the 2026-06-16 "updates don't flow" incident: the unit's
    # ExecStart is often a console script (e.g. <venv>/bin/meshembed-node), not
    # `python -m`. The old resolver tried `<console-script> -c 'import sys'`
    # (which fails -- a console script can't run -c), then fell back to a
    # canonical venv path that didn't match, then to the SYSTEM python -- so the
    # upgrade landed in the wrong interpreter and the daemon kept running old
    # code from its venv. Now: if ExecStart's first token is itself a usable
    # Python, use it; otherwise treat it as a console script and use the sibling
    # `python`/`python3` in the SAME bin/ dir (the venv interpreter). System
    # python3 stays the last resort only.
    VENV_PY=""
    if command -v systemctl >/dev/null 2>&1; then
        UNIT_BIN=$(systemctl cat meshembed-node.service 2>/dev/null \
            | awk -F= '/^ExecStart=/{print $2}' | awk '{print $1}' | head -1)
        if [ -n "${UNIT_BIN:-}" ]; then
            if "$UNIT_BIN" -c 'import sys' >/dev/null 2>&1; then
                VENV_PY="$UNIT_BIN"                          # ExecStart is a python
            else
                # ExecStart is a console script -> the venv python is its sibling.
                _bindir=$(dirname "$UNIT_BIN")
                for _cand in python python3; do
                    if [ -x "$_bindir/$_cand" ] && "$_bindir/$_cand" -c 'import sys' >/dev/null 2>&1; then
                        VENV_PY="$_bindir/$_cand"; break
                    fi
                done
            fi
        fi
    fi
    [ -z "$VENV_PY" ] && [ -x "$VENV_DIR/bin/python" ] && VENV_PY="$VENV_DIR/bin/python"
    [ -z "$VENV_PY" ] && VENV_PY="$(command -v python3 || true)"
    [ -n "$VENV_PY" ] || fail "Upgrade mode but no existing interpreter found."
    info "Upgrade mode: target interpreter $VENV_PY (resolved from the systemd unit)"
else
    # Fresh install: choose the base Python (warn if one already exists), then
    # build the venv with uv (uv can base it on a system python OR download 3.12).
    SYS_PY="$(command -v python3 2>/dev/null || true)"
    CHOICE="${MESHEMBED_PYTHON:-}"   # uv | system | /path | (empty = auto)
    if [ -z "$CHOICE" ]; then
        if [ -n "$SYS_PY" ]; then
            SYMIN=$("$SYS_PY" -c 'import sys;print(sys.version_info.minor)' 2>/dev/null || echo 0)
            SYSVER=$("$SYS_PY" --version 2>&1 || echo "python3")
            echo ""
            warn "A Python distribution is already installed on this node: ${SYSVER} (${SYS_PY})."
            if [ "$SYMIN" -ge 10 ] && [ "$SYMIN" -le 12 ]; then
                info "  It is compatible. You can KEEP it, or have the installer provision a"
                info "  clean, pinned Python 3.12 (isolated in a venv -- more reproducible)."
                DEFAULT="system"
            else
                warn "  It is NOT compatible: MeshEmbed needs Python 3.10-3.12 (torch/numpy have"
                warn "  no wheels on 3.13+). Recommended: provision a clean Python 3.12."
                DEFAULT="uv"
            fi
            if [ -t 0 ]; then
                read -rp "  Provision a fresh Python 3.12 [uv] or keep the existing one [system]? [${DEFAULT}]: " CHOICE
                CHOICE="${CHOICE:-$DEFAULT}"
            else
                CHOICE="$DEFAULT"
                info "  Non-interactive: choosing '${DEFAULT}'. Override with MESHEMBED_PYTHON=uv|system."
            fi
        else
            info "No system Python found -- provisioning a clean Python 3.12 via uv."
            CHOICE="uv"
        fi
    fi

    case "$CHOICE" in
        system) BASE_PY="$SYS_PY"; [ -n "$BASE_PY" ] || fail "MESHEMBED_PYTHON=system but no python3 found." ;;
        uv)     BASE_PY="3.12" ;;
        /*)     BASE_PY="$CHOICE" ;;
        *)      BASE_PY="3.12" ;;
    esac

    ensure_uv
    info "Creating virtualenv at ${VENV_DIR} (base: ${BASE_PY})..."
    mkdir -p "$(dirname "$VENV_DIR")"
    uv venv --python "$BASE_PY" "$VENV_DIR" \
        || fail "venv creation failed (base=${BASE_PY}). Try MESHEMBED_PYTHON=uv."
    VENV_PY="$VENV_DIR/bin/python"
fi

# ── Install the package into the venv ─────────────────────────────────────────
ensure_uv   # no-op if already present; needed for `uv pip` below
info "Installing meshembed-node from ${RELEASE_TAG}..."

# CPU-only nodes: install the CPU PyTorch wheel (~200 MB) from PyTorch's CPU
# index FIRST, so the default install doesn't drag in the CUDA build (~2.5 GB
# of nvidia-* libs) that fills small cloud disks and is useless without a GPU.
# Done only on fresh CPU installs; GPU nodes (and upgrades) keep their torch.
if [ "$UPGRADE_ONLY" -ne 1 ] && [ -z "$INSTALL_EXTRAS" ]; then
    info "  CPU mode: installing CPU-only PyTorch (small download)..."
    # torch ONLY — never torchvision. MeshEmbed does text embeddings; torchvision
    # is unused, and a torchvision resolved from PyPI's default index against this
    # CPU-index torch crashes transformers with `operator torchvision::nms does
    # not exist`, silently disabling embedding (the node then reports 0 models
    # and the scheduler routes it no work).
    uv pip install --python "$VENV_PY" torch \
        --index-url https://download.pytorch.org/whl/cpu \
        || fail "CPU PyTorch install failed -- see output above."
fi

# GPU node on a pre-525 driver: install the CUDA 11.8 torch BEFORE the package,
# so the dependency resolution below leaves it in place (--upgrade-package keeps
# an already-installed torch) instead of pulling the unusable CUDA-12 default.
# torch ONLY, never torchvision -- a mismatched torchvision breaks transformers
# and the node reports 0 models.
if [ "$UPGRADE_ONLY" -ne 1 ] && [ -n "$CUDA_INDEX_URL" ]; then
    info "  GPU mode: installing CUDA 11.8 PyTorch for driver ${GPU_DRIVER_VER}..."
    uv pip install --python "$VENV_PY" torch \
        --index-url "$CUDA_INDEX_URL" \
        || fail "CUDA 11.8 PyTorch install failed -- see output above."
fi

info "  Installing the agent + remaining deps; first run takes 2-5 min."
# --upgrade-package (not bare --upgrade) so an already-installed torch (e.g. the
# CPU build above) is left in place rather than re-resolved to the CUDA wheel.
# --break-system-packages: nodes installed by older installers run off the
# SYSTEM python (unit ExecStart=/usr/bin/python3), which modern Debian/Ubuntu
# mark "externally managed" (PEP 668) -- uv then refuses to install and the
# whole upgrade fails (the confirmed root cause of the stuck-OTA incident). The
# flag lets uv install into that interpreter (matching how the node was first
# set up); it's a harmless no-op on the venv path used by fresh installs.
uv pip install --python "$VENV_PY" --break-system-packages --upgrade-package meshembed-node \
    "meshembed-node${INSTALL_EXTRAS} @ ${PACKAGE_URL}" \
    || fail "package install failed -- see output above."

# Belt-and-suspenders: a torchvision left by a pre-0.3.28 install (or dragged in
# transitively) is the #1 cause of `torchvision::nms` import crashes that make
# the encoder report zero models. We never use it, so remove it if present.
uv pip uninstall --python "$VENV_PY" torchvision >/dev/null 2>&1 || true

# ── GUARD: confirm the upgrade landed in the interpreter the daemon RUNS ───────
# Prevents the entire class of "installed but daemon still runs old code" bug
# (2026-06-16 incident): if VENV_PY was mis-resolved to a different interpreter
# than the unit's, the daemon would silently keep the old version forever. We
# assert the resolved interpreter now reports the target version and FAIL LOUDLY
# otherwise, so a wrong-target install can never pass silently again.
_WANT="${RELEASE_TAG#v}"
_GOT=$("$VENV_PY" -c 'import importlib.metadata as m; print(m.version("meshembed-node"))' 2>/dev/null || echo "")
if [ -z "$_GOT" ]; then
    fail "post-install check: meshembed-node not importable from $VENV_PY after install."
fi
if [ -n "$_WANT" ] && [ "$_GOT" != "$_WANT" ]; then
    fail "post-install check: $VENV_PY reports meshembed-node $_GOT, expected $_WANT. The upgrade did not land in the daemon's interpreter -- not restarting."
fi
ok "meshembed-node $_GOT installed + verified in the daemon's interpreter (${VENV_PY})"

# ── Upgrade path: harden the unit, restart the running daemon, then exit ──────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Skipping register / .env reinstall: existing enrollment."
    if command -v systemctl >/dev/null 2>&1 && systemctl cat meshembed-node.service >/dev/null 2>&1; then
        # Uptime hardening: SURGICALLY bump Restart=on-failure -> Restart=always
        # so the daemon also comes back after a clean exit (e.g. post-self-update)
        # and after reboot. We edit only that one directive + `enable` -- we do
        # NOT rewrite the unit, to preserve custom ExecStart / EnvironmentFile
        # layouts (some nodes run a console-script venv at a non-standard path).
        _harden_unit() {
            local f="/etc/systemd/system/meshembed-node.service"
            [ -w "$f" ] || return 0
            if grep -q '^Restart=on-failure' "$f"; then
                sed -i 's|^Restart=on-failure|Restart=always|' "$f"
                systemctl daemon-reload 2>/dev/null || true
                info "Unit hardened: Restart=always (survives clean exit + reboot)."
            fi
            systemctl enable meshembed-node.service >/dev/null 2>&1 || true
        }
        info "Restarting meshembed-node.service so the new code takes effect..."
        if [ "$EUID" -eq 0 ]; then
            _harden_unit
            systemctl restart meshembed-node.service && ok "Daemon restarted -- reports new version on next poll (~30s)."
        elif sudo -n systemctl daemon-reload 2>/dev/null; then
            sudo -n sed -i 's|^Restart=on-failure|Restart=always|' /etc/systemd/system/meshembed-node.service 2>/dev/null || true
            sudo -n systemctl daemon-reload 2>/dev/null || true
            sudo -n systemctl enable meshembed-node.service >/dev/null 2>&1 || true
            sudo -n systemctl restart meshembed-node.service 2>/dev/null \
                && ok "Daemon restarted (via passwordless sudo)." \
                || echo "  (run 'sudo systemctl restart meshembed-node.service' to apply the upgrade now)"
        else
            echo "  (run 'sudo systemctl restart meshembed-node.service' to apply the upgrade now)"
        fi
    fi
    echo ""
    echo "${bold}Upgrade complete.${reset}"
    exit 0
fi

# FRESH_NODE=1 discards this hardware's existing node and enrols a NEW one
# (reputation from zero). Default is to RE-ESTABLISH: keep the node's identity
# and earned history, rotating only the credentials. The operator asked to fix
# this box, not to throw away its track record.
# ── Self-register ─────────────────────────────────────────────────────────────
info "Registering node with the backend..."
REG_ERR=$(mktemp -t meshembed-register-err.XXXXXX)
trap 'rm -f "$REG_ERR"' EXIT
FRESH_FLAG=""
if [ "${FRESH_NODE:-0}" = "1" ]; then
    FRESH_FLAG="--fresh"
    info "FRESH_NODE=1 -- enrolling a NEW node; existing reputation on this hardware is discarded."
fi
if ! REGISTER_OUT=$("$VENV_PY" -m meshembed_node register \
        --backend "$BACKEND_URL" \
        --invite  "$INVITE_TOKEN" \
        $FRESH_FLAG \
        --json 2>"$REG_ERR"); then
    fail "Registration failed:\n$(cat "$REG_ERR")"
fi
[ -n "$REGISTER_OUT" ] || fail "Registration produced no output. Stderr was:\n$(cat "$REG_ERR")"

PRIVKEY=$("$VENV_PY" -c "from meshembed_node.crypto import generate_keypair; print(generate_keypair()[0])")
NODE_ID=$(printf '%s' "$REGISTER_OUT"  | "$VENV_PY" -c "import sys,json; print(json.load(sys.stdin)['node_id'])")
API_KEY=$(printf '%s' "$REGISTER_OUT"  | "$VENV_PY" -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
NODE_NUM=$(printf '%s' "$REGISTER_OUT" | "$VENV_PY" -c "import sys,json; print(json.load(sys.stdin)['node_number'])")
ok "Node registered - N-$(printf '%04d' "$NODE_NUM")"

# ── PART75: de-root privileged installs ───────────────────────────────────────
# When installed as root, run the daemon as a dedicated unprivileged user under
# full filesystem confinement instead of as root. On a FRESH install we control
# the layout -- venv in /opt, config + HF cache in /var/lib -- so nothing the
# daemon needs lives under /home, and ProtectHome=true is safe with no path
# hidden (the failure mode the in-place migration had to work around). A non-root
# install already runs as the invoking unprivileged user, so it is left as-is.
SVC_USER="$USER"
SVC_HOME="$HOME"
SVC_HARDEN_FS=0
GPU_SUPP=""
if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    SVC_USER="${MESHEMBED_NODE_USER:-meshembed}"
    SVC_HOME="${MESHEMBED_NODE_HOME:-/var/lib/meshembed-node}"
    SVC_HARDEN_FS=1
    if ! getent passwd "$SVC_USER" >/dev/null; then
        useradd --system --home-dir "$SVC_HOME" --create-home --shell /usr/sbin/nologin "$SVC_USER" \
            || useradd --system --home-dir "$SVC_HOME" --create-home --shell /bin/false "$SVC_USER" \
            || fail "could not create service user $SVC_USER"
        ok "created unprivileged service user $SVC_USER"
    fi
    mkdir -p "$SVC_HOME/.cache/huggingface"
    chown -R "$SVC_USER:$SVC_USER" "$SVC_HOME"
    # The venv lives in /opt (read-only under ProtectSystem=strict, which is fine
    # for running); make sure the unprivileged user can read+exec it.
    chmod -R a+rX "$VENV_DIR" 2>/dev/null || true
    # GPU device access: join whatever group owns the NVIDIA/DRI nodes (nvidia
    # nodes are often 0666, so this is belt-and-braces).
    _gpu_groups=""
    for dev in /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm /dev/dri/render* /dev/dri/card*; do
        [ -e "$dev" ] || continue
        g="$(stat -c '%G' "$dev" 2>/dev/null || true)"
        case " $_gpu_groups " in *" $g "*) : ;; *) [ -n "$g" ] && [ "$g" != "root" ] && _gpu_groups="$_gpu_groups $g" ;; esac
    done
    for g in video render $_gpu_groups; do
        getent group "$g" >/dev/null 2>&1 && usermod -aG "$g" "$SVC_USER" 2>/dev/null || true
    done
    GPU_SUPP="$(id -nG "$SVC_USER" 2>/dev/null | tr ' ' '\n' | grep -E '^(video|render|nvidia|dri)' | paste -sd' ' - || true)"
    ok "daemon will run as $SVC_USER (ProtectSystem=strict, GPU groups: ${GPU_SUPP:-none})"
fi

# ── Data directory + credentials ──────────────────────────────────────────────
CONFIG_DIR="$SVC_HOME/.meshembed"
mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"
ENV_FILE="$CONFIG_DIR/.env"
cat > "$ENV_FILE" << EOF
MESHEMBED_BACKEND=$BACKEND_URL
MESHEMBED_NODE_API_KEY=$API_KEY
MESHEMBED_NODE_ID=$NODE_ID
MESHEMBED_NODE_PRIVKEY=$PRIVKEY
EOF
chmod 600 "$ENV_FILE"
[ "$SVC_HARDEN_FS" -eq 1 ] && chown -R "$SVC_USER:$SVC_USER" "$CONFIG_DIR"
ok "Credentials saved to $ENV_FILE"

# ── Systemd service (ExecStart pinned to the venv interpreter) ─────────────────
SERVICE_FILE="/etc/systemd/system/meshembed-node.service"
if command -v systemctl &>/dev/null; then
    info "Installing systemd service..."
    # Filesystem confinement + dedicated user are applied only for PRIVILEGED
    # (root) installs (SVC_HARDEN_FS=1), where the layout is ours and
    # ReadWritePaths is known-correct. Empty vars collapse to blank lines, which
    # systemd ignores, so a non-root install renders exactly the old unit.
    SUPP_LINE=""; [ -n "$GPU_SUPP" ] && SUPP_LINE="SupplementaryGroups=$GPU_SUPP"
    HARDEN_FS_BLOCK=""
    if [ "$SVC_HARDEN_FS" -eq 1 ]; then
        HARDEN_FS_BLOCK="ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$SVC_HOME"
    fi
    cat > /tmp/meshembed-node.service << EOF
[Unit]
Description=MeshEmbed Node daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
$SUPP_LINE
Environment=HOME=$SVC_HOME
Environment=HF_HOME=$SVC_HOME/.cache/huggingface
Environment=MESHEMBED_BACKEND=$BACKEND_URL
Environment=MESHEMBED_NODE_API_KEY=$API_KEY
Environment=MESHEMBED_NODE_ID=$NODE_ID
ExecStart=$VENV_PY -m meshembed_node run
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening (PART75). The privilege-escalation controls below are path-independent
# and ALWAYS applied: no new privileges (blocks setuid escalation), no kernel
# module load, no kernel-tunable / cgroup / clock tampering, no realtime. For
# PRIVILEGED (root) installs we ALSO drop to a dedicated unprivileged user with
# full filesystem confinement (ProtectSystem=strict + ProtectHome +
# ReadWritePaths=\$SVC_HOME) -- safe on a fresh install because the venv lives in
# /opt and config + HF cache in /var/lib, so nothing the daemon needs is hidden.
# A non-root install is already unprivileged and keeps the lighter profile.
# MemoryDenyWriteExecute / SystemCallFilter are omitted: torch/CUDA JIT needs W+X
# memory and a broad syscall set.
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
$HARDEN_FS_BLOCK

[Install]
WantedBy=multi-user.target
EOF
    SERVICE_INSTALLED=0
    if [ "$EUID" -eq 0 ]; then
        mv /tmp/meshembed-node.service "$SERVICE_FILE"
        systemctl daemon-reload
        systemctl enable --now meshembed-node.service
        ok "systemd service installed and started"
        SERVICE_INSTALLED=1
    elif sudo -n true 2>/dev/null; then
        # Passwordless sudo. The UPGRADE path has used this for a long time; the
        # fresh-install branch never tried, so a non-root install left the unit
        # untouched -- and on a re-enrollment that means systemd keeps running the
        # OLD venv with the OLD credentials while the script reports success.
        sudo -n mv /tmp/meshembed-node.service "$SERVICE_FILE" \
            && sudo -n systemctl daemon-reload \
            && sudo -n systemctl enable --now meshembed-node.service \
            && { ok "systemd service installed and started (via passwordless sudo)"; SERVICE_INSTALLED=1; }
    fi

    if [ "$SERVICE_INSTALLED" -eq 0 ]; then
        echo ""
        echo "To install as a systemd service (requires sudo):"
        echo "  sudo mv /tmp/meshembed-node.service $SERVICE_FILE"
        echo "  sudo systemctl daemon-reload && sudo systemctl enable --now meshembed-node"
        echo ""
        echo "Or start manually now:"
        echo "  $VENV_PY -m meshembed_node run"
    fi

    # Clean up a PREVIOUS install left in a different venv. Only after the new
    # unit is confirmed installed, and only on a re-enrollment -- otherwise an
    # upgrade could delete the very venv it is running from.
    if [ "$SERVICE_INSTALLED" -eq 1 ] && [ -n "${OLD_VENV:-}" ] \
            && [ "$OLD_VENV" != "$VENV_DIR/.venv" ] && [ -d "$OLD_VENV" ]; then
        info "Removing the previous install at $OLD_VENV"
        rm -rf "$OLD_VENV" 2>/dev/null || sudo -n rm -rf "$OLD_VENV" 2>/dev/null \
            || info "  (could not remove it; harmless, but it is now unused)"
    fi
else
    info "systemd not available - start manually:"
    echo "  $VENV_PY -m meshembed_node run"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "${bold}Installation complete.${reset}"
echo "  Node:    N-$(printf '%04d' "$NODE_NUM") ($NODE_ID)"
echo "  Python:  $VENV_PY"
echo "  Logs:    journalctl -u meshembed-node -f"
echo "  Stop:    sudo systemctl stop meshembed-node"
