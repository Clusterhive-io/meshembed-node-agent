#!/usr/bin/env bash
# deroot-node.sh -- migrate an EXISTING Linux MeshEmbed node daemon to run as a
# dedicated unprivileged user under full systemd confinement (PART75).
#
# WHY. The curl|bash installer's generated unit runs the daemon as the invoking
# user -- root when installed via sudo -- with ProtectSystem NOT set. A daemon
# RCE is then a root RCE on the box. This migrates an already-installed node to a
# dedicated `meshembed` system user + ProtectSystem=strict, WITHOUT reinstalling.
#
# SAFE BY CONSTRUCTION:
#   * It only CREATES a user and COPIES what the daemon needs -- the venv, the
#     .env, and the HF model cache -- into that user's home. The original install
#     is left byte-for-byte intact, so rollback is simply "restore the old unit".
#     Copying the venv is REQUIRED, not just tidy: ProtectHome=true hides /home
#     from the service, so a venv left under /home/<user> vanishes at exec time
#     (status=203/EXEC). The copy lives under $NEWHOME (/var/lib/...) instead, so
#     the confined daemon can reach its own interpreter. (Fix from a 2026-08-16
#     GPU-node dry-run, which auto-rolled-back on exactly this.)
#   * It snapshots the working unit first and AUTO-ROLLS-BACK if the de-rooted
#     daemon is not active-on-CUDA within the verify window. A GPU that stops
#     working under the non-root user reverts the node to exactly how it was.
#
# USAGE (run as root ON THE NODE):
#   sudo ./deroot-node.sh                 # migrate + self-verify + auto-rollback
#   sudo ./deroot-node.sh --rollback      # force revert to the pre-migration unit
#   sudo MESHEMBED_DEROOT_REQUIRE_GPU=0 ./deroot-node.sh   # CPU node (skip CUDA check)
#
# ENV KNOBS:
#   MESHEMBED_NODE_USER    (default meshembed)  the unprivileged service user
#   MESHEMBED_NODE_HOME    (default /var/lib/meshembed-node)  its home / RW root
#   MESHEMBED_DEROOT_VERIFY_SECS  (default 120)  how long to wait for healthy-on-GPU
#   MESHEMBED_DEROOT_REQUIRE_GPU  (default 1)    1 = must log "Accelerator: CUDA" or rollback
set -euo pipefail

SERVICE="meshembed-node.service"
UNIT="/etc/systemd/system/${SERVICE}"
NEWUSER="${MESHEMBED_NODE_USER:-meshembed}"
NEWHOME="${MESHEMBED_NODE_HOME:-/var/lib/meshembed-node}"
VERIFY_SECS="${MESHEMBED_DEROOT_VERIFY_SECS:-120}"
REQUIRE_GPU="${MESHEMBED_DEROOT_REQUIRE_GPU:-1}"
BACKUP="${UNIT}.pre-deroot.bak"

log()  { printf '\033[0;34m[deroot]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[ ok  ]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[warn ]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[fail ]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)."
command -v systemctl >/dev/null 2>&1 || die "systemd required."
[ -f "$UNIT" ] || die "unit not found: $UNIT (is this a systemd install?)"

unit_val() { systemctl show -p "$1" --value "$SERVICE" 2>/dev/null || true; }

# --------------------------------------------------------------------------
# --rollback: restore the pre-migration unit and restart.
# --------------------------------------------------------------------------
if [ "${1:-}" = "--rollback" ]; then
    [ -f "$BACKUP" ] || die "no backup at $BACKUP -- nothing to roll back to."
    cp -f "$BACKUP" "$UNIT"
    systemctl daemon-reload
    systemctl restart "$SERVICE"
    ok "rolled back to the pre-migration unit."
    exit 0
fi

CUR_USER="$(unit_val User)"; [ -n "$CUR_USER" ] || CUR_USER="root"
if [ "$CUR_USER" = "$NEWUSER" ]; then
    ok "already running as '$NEWUSER' -- nothing to do."
    exit 0
fi
log "current service user: $CUR_USER  ->  target: $NEWUSER"

# --------------------------------------------------------------------------
# 1. Discover the existing install from the running unit (do NOT assume layout).
# --------------------------------------------------------------------------
EXECSTART="$(unit_val ExecStart)"
# systemd renders ExecStart as a struct; pull the argv[] path list back out.
EXEC_CMD="$(printf '%s' "$EXECSTART" | sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p')"
[ -n "$EXEC_CMD" ] || EXEC_CMD="$EXECSTART"
VENV_PY="$(printf '%s' "$EXEC_CMD" | awk '{print $1}')"
[ -x "$VENV_PY" ] || die "cannot resolve the daemon interpreter from ExecStart: '$EXEC_CMD'"
log "daemon interpreter: $VENV_PY"

OLD_ENVFILE="$(unit_val EnvironmentFile)"     # may be empty (env passed inline)
# HOME the daemon currently uses (for locating the existing HF cache + .env).
OLD_HOME="$(systemctl show "$SERVICE" -p Environment --value 2>/dev/null \
            | tr ' ' '\n' | sed -n 's/^HOME=//p' | head -1)"
if [ -z "$OLD_HOME" ] && [ "$CUR_USER" != "root" ]; then
    OLD_HOME="$(getent passwd "$CUR_USER" | cut -d: -f6)"
fi
[ -n "$OLD_HOME" ] || OLD_HOME="/root"
log "current daemon HOME: $OLD_HOME"

# Preserve the inline MESHEMBED_* environment (backend URL, api key, node id).
mapfile -t OLD_ENVS < <(systemctl show "$SERVICE" -p Environment --value 2>/dev/null \
                        | tr ' ' '\n' | grep -E '^MESHEMBED_' || true)

# --------------------------------------------------------------------------
# 2. Snapshot the working unit (rollback target).
# --------------------------------------------------------------------------
cp -f "$UNIT" "$BACKUP"
ok "snapshotted working unit -> $BACKUP"

# --------------------------------------------------------------------------
# 3. Create the unprivileged service user + join the GPU device groups.
# --------------------------------------------------------------------------
if ! getent passwd "$NEWUSER" >/dev/null; then
    useradd --system --home-dir "$NEWHOME" --create-home --shell /usr/sbin/nologin "$NEWUSER" \
        || useradd --system --home-dir "$NEWHOME" --create-home --shell /bin/false "$NEWUSER" \
        || die "could not create system user $NEWUSER"
    ok "created system user $NEWUSER (home $NEWHOME)"
else
    ok "system user $NEWUSER already exists"
fi
mkdir -p "$NEWHOME"
chown "$NEWUSER:$NEWUSER" "$NEWHOME"

# GPU access: add the user to whatever group owns the NVIDIA/DRI device nodes.
# (Common driver installs make /dev/nvidia* world-rw, in which case this is
#  belt-and-braces; when they are group-owned, this is what grants access.)
GPU_GROUPS=""
for dev in /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm /dev/dri/render* /dev/dri/card*; do
    [ -e "$dev" ] || continue
    g="$(stat -c '%G' "$dev" 2>/dev/null || true)"
    case " $GPU_GROUPS " in *" $g "*) : ;; *) [ -n "$g" ] && [ "$g" != "root" ] && GPU_GROUPS="$GPU_GROUPS $g" ;; esac
done
for g in video render $GPU_GROUPS; do
    getent group "$g" >/dev/null 2>&1 || continue
    usermod -aG "$g" "$NEWUSER" 2>/dev/null && log "added $NEWUSER to group '$g'"
done
GPU_SUPP="$(id -nG "$NEWUSER" | tr ' ' '\n' | grep -Ev "^${NEWUSER}$" | grep -E '^(video|render|nvidia|dri).*' | paste -sd' ' - || true)"

# --------------------------------------------------------------------------
# 4. Copy (never move) config + HF cache into the new user's home. The originals
#    are untouched, so rollback stays trivial.
# --------------------------------------------------------------------------
NEW_CFGDIR="$NEWHOME/.meshembed"
NEW_ENVFILE="$NEW_CFGDIR/.env"
install -d -o "$NEWUSER" -g "$NEWUSER" -m 700 "$NEW_CFGDIR"
SRC_ENV="$OLD_ENVFILE"; [ -n "$SRC_ENV" ] || SRC_ENV="$OLD_HOME/.meshembed/.env"
if [ -f "$SRC_ENV" ]; then
    install -o "$NEWUSER" -g "$NEWUSER" -m 600 "$SRC_ENV" "$NEW_ENVFILE"
    ok "copied credentials -> $NEW_ENVFILE"
    HAVE_ENVFILE=1
else
    warn "no EnvironmentFile found (env is inline in the unit) -- carrying it forward inline"
    HAVE_ENVFILE=0
fi

NEW_HF="$NEWHOME/.cache/huggingface"
install -d -o "$NEWUSER" -g "$NEWUSER" -m 755 "$NEWHOME/.cache"
if [ -d "$OLD_HOME/.cache/huggingface" ] && [ ! -d "$NEW_HF" ]; then
    log "copying existing HF model cache (avoids a cold re-download)..."
    cp -a "$OLD_HOME/.cache/huggingface" "$NEW_HF" || warn "cache copy failed; models will re-download on first use"
    chown -R "$NEWUSER:$NEWUSER" "$NEW_HF" 2>/dev/null || true
fi

# The venv (the executable itself) MUST move out of /home, or ProtectHome=true
# hides it from the confined service -> 203/EXEC. Copy the whole venv into
# $NEWHOME and repoint ExecStart at the copy (copy, never move -- the original
# stays intact for rollback). nothing the daemon needs then lives under /home.
NEW_EXEC_CMD="$EXEC_CMD"
BIND_BASE=""
OLD_VENV_ROOT="$(dirname "$(dirname "$VENV_PY")")"
if [ -f "$OLD_VENV_ROOT/pyvenv.cfg" ]; then
    NEW_VENV="$NEWHOME/.venv"
    if [ ! -d "$NEW_VENV" ]; then
        log "copying venv $OLD_VENV_ROOT -> $NEW_VENV (may take a minute for a torch venv)..."
        cp -a "$OLD_VENV_ROOT" "$NEW_VENV" || die "venv copy failed"
        chown -R "$NEWUSER:$NEWUSER" "$NEW_VENV"
    fi
    NEW_VENV_PY="$NEW_VENV/bin/$(basename "$VENV_PY")"
    [ -x "$NEW_VENV_PY" ] || NEW_VENV_PY="$NEW_VENV/bin/python"
    # Repoint ExecStart's interpreter (first token), keep its args (-m ... run).
    NEW_EXEC_CMD="$NEW_VENV_PY${EXEC_CMD#"$VENV_PY"}"
    ok "venv copied; ExecStart interpreter -> $NEW_VENV_PY"
    # Edge case: a uv-managed STANDALONE base python can live under /home or
    # /root; ProtectHome=true would still hide it. If the copied interpreter
    # resolves (or pyvenv.cfg points) to a base under a home dir, bind just that
    # one python tree read-only so it survives ProtectHome (narrow, not all /home).
    BASE_REAL="$(readlink -f "$NEW_VENV_PY" 2>/dev/null || true)"
    case "$BASE_REAL" in
        /home/*|/root/*) BIND_BASE="$(dirname "$(dirname "$BASE_REAL")")" ;;
    esac
    if [ -z "$BIND_BASE" ]; then
        PV_HOME="$(sed -n 's/^home *= *//p' "$NEW_VENV/pyvenv.cfg" 2>/dev/null | head -1)"
        case "$PV_HOME" in
            /home/*|/root/*) BIND_BASE="$(dirname "$PV_HOME")" ;;
        esac
    fi
    [ -n "$BIND_BASE" ] && log "base python under a home dir -> BindReadOnlyPaths=$BIND_BASE"
else
    warn "interpreter is not in a venv ($VENV_PY); leaving ExecStart as-is (verify may fail under ProtectHome)"
fi

# --------------------------------------------------------------------------
# 5. Write the hardened, de-rooted unit.
# --------------------------------------------------------------------------
{
    cat <<EOF
[Unit]
Description=MeshEmbed Node daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$NEWUSER
Group=$NEWUSER
EOF
    [ -n "$GPU_SUPP" ] && echo "SupplementaryGroups=$GPU_SUPP"
    echo "Environment=HOME=$NEWHOME"
    echo "Environment=HF_HOME=$NEW_HF"
    for e in "${OLD_ENVS[@]}"; do [ -n "$e" ] && echo "Environment=$e"; done
    [ "$HAVE_ENVFILE" -eq 1 ] && echo "EnvironmentFile=$NEW_ENVFILE"
    [ -n "$BIND_BASE" ] && echo "BindReadOnlyPaths=$BIND_BASE"
    cat <<EOF
ExecStart=$NEW_EXEC_CMD
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening (PART75). Dedicated unprivileged user + filesystem confinement.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$NEWHOME
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
# NOTE: MemoryDenyWriteExecute / SystemCallFilter are intentionally omitted --
# torch/CUDA JIT needs W+X memory and a broad syscall set.

[Install]
WantedBy=multi-user.target
EOF
} > "${UNIT}.new"
mv -f "${UNIT}.new" "$UNIT"
systemctl daemon-reload
ok "installed hardened unit (User=$NEWUSER, ProtectSystem=strict)"

# --------------------------------------------------------------------------
# 6. Restart + self-verify, with automatic rollback on failure.
# --------------------------------------------------------------------------
rollback() {
    warn "verification FAILED -- rolling back to the pre-migration unit."
    cp -f "$BACKUP" "$UNIT"
    systemctl daemon-reload
    systemctl restart "$SERVICE" || true
    warn "rolled back. The node is running exactly as before. Investigate, then re-run."
    warn "Recent daemon log:"; journalctl -u "$SERVICE" -n 25 --no-pager || true
    exit 1
}

RESTART_AT="$(date '+%Y-%m-%d %H:%M:%S')"
systemctl restart "$SERVICE" || rollback

log "verifying (active + $([ "$REQUIRE_GPU" = 1 ] && echo 'CUDA' || echo 'CPU-ok'), up to ${VERIFY_SECS}s)..."
deadline=$(( $(date +%s) + VERIFY_SECS ))
gpu_ok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! systemctl is-active --quiet "$SERVICE"; then sleep 3; continue; fi
    if [ "$REQUIRE_GPU" != 1 ]; then gpu_ok=1; break; fi
    if journalctl -u "$SERVICE" --since "$RESTART_AT" --no-pager 2>/dev/null | grep -q "Accelerator: CUDA"; then
        gpu_ok=1; break
    fi
    # A hard CPU-fallback line means the GPU is not usable under the new user.
    if journalctl -u "$SERVICE" --since "$RESTART_AT" --no-pager 2>/dev/null \
         | grep -qiE "can't use it|Accelerator: CPU|torch not installed"; then
        warn "daemon fell back off CUDA under $NEWUSER."
        rollback
    fi
    sleep 3
done

systemctl is-active --quiet "$SERVICE" || rollback
[ "$gpu_ok" -eq 1 ] || rollback

ok "de-root complete: daemon active as '$NEWUSER'$([ "$REQUIRE_GPU" = 1 ] && echo ' on CUDA')."
ok "rollback anytime with:  sudo $0 --rollback"
