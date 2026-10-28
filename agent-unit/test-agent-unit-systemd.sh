#!/bin/bash
# AR1 G9 S5 (auditor 2026-10-23 13:19Z): prove the agent unit's sandbox under REAL systemd on a test host.
# A transient unit gets meshembed-agent.service's [Service] sandbox directives verbatim (DynamicUser stands in for
# mesh-agent); a probe inside checks: no network at all, no view of /home (the node key, a stand-in lane key), the code
# read-only, only the StateDirectory writable, /proc limited to itself, and the daemon socket refusing a foreign uid.
# Needs: sudo -n systemd-run, mkdir/chown/rm under /run. Leaves nothing behind (trap).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"              # node-agent/
UNIT_FILE="$HERE/agent-unit/meshembed-agent.service"
T=/run/meshembed-agent-test
NAME="meshembed-agent-s5-$$"
KEYDIR="$HOME/.meshembed-agent-s5-$$"
cleanup() { [ -n "${BPID:-}" ] && kill "$BPID" 2>/dev/null || true; sudo -n systemctl reset-failed "$NAME" "$NAME-nocred" 2>/dev/null || true; rm -f "/var/tmp/s5-host-marker-$$"; sudo -n rm -rf "$T" /var/lib/private/"$NAME" /var/lib/"$NAME"; rm -rf "$KEYDIR"; }
trap cleanup EXIT
mkdir -m 700 "$KEYDIR" && printf 'meah_%s\n' "$(head -c 24 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 30)" > "$KEYDIR/lane.key" && chmod 600 "$KEYDIR/lane.key"
touch "/var/tmp/s5-host-marker-$$"
sudo -n mkdir -p "$T" && sudo -n chown "$(id -u):$(id -g)" "$T" && chmod 0755 "$T"
# the daemon side: a bridge as THIS uid that serves only agent_uid 1 (so the probe's dynamic uid is foreign)
PYTHONPATH="$HERE" python3 -I -c "
import sys; sys.path.insert(0, '$HERE')
from pathlib import Path
from meshembed_node.agent_bridge import AgentBridge
b = AgentBridge(node_id='n', tenant='t', agent_uid=1, post=lambda *a: (0, None), lane_key=lambda: None, verify_ctx={})
import os; os.chmod('$T', 0o750)
s = b.listen(Path('$T/agent.sock'))
os.chmod('$T', 0o755)
while True:
    c, _ = s.accept(); b.serve_connection(c)
" 2>"$KEYDIR/bridge.err" & BPID=$!
for i in $(seq 1 50); do [ -S "$T/agent.sock" ] && break; sleep 0.1; done
[ -S "$T/agent.sock" ] || { echo "bridge did not start:"; cat "$KEYDIR/bridge.err"; exit 1; }
sudo -n chmod 0666 "$T/agent.sock"                    # let the probe reach it: the PEER CHECK must refuse it
PROPS=()
while IFS= read -r line; do
  case "$line" in
    User=*|Group=*|ExecStart=*|ExecStartPre=*|LoadCredentialEncrypted=*|BindReadOnlyPaths=*|Restart*|Type=*) ;;
    StateDirectory=*) PROPS+=(-p "StateDirectory=$NAME") ;;
    *=*) PROPS+=(-p "$line") ;;
  esac
done < <(sed -n '/^\[Service\]/,/^\[/p' "$UNIT_FILE" | grep -v -E '^\s*(#|\[|$)')
sudo -n systemd-run --wait --pipe --quiet --unit="$NAME" -p DynamicUser=yes "${PROPS[@]}" \
  -p "BindReadOnlyPaths=$HERE:/opt/agent-src" -p "BindReadOnlyPaths=$T/agent.sock:/run/meshembed/agent.sock" \
  /usr/bin/python3 -I -c "
import os, socket, json
r = {}
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM); r['inet_socket'] = 'ALLOWED'
except OSError as e:
    r['inet_socket'] = 'refused'
try:
    r['home_visible'] = os.path.exists('$KEYDIR/lane.key') or bool(os.listdir('/home'))
except OSError:
    r['home_visible'] = False
for p in ('/opt/agent-src/x', '/usr/x', '/etc/x', '/srv/x', '/run/x'):
    try:
        open(p, 'w').write('x'); r['write:' + p] = 'ALLOWED'
    except OSError:
        r['write:' + p] = 'refused'
# PrivateTmp: /tmp and /var/tmp are the unit's OWN empty directories, discarded at stop (not the host's)
open('/var/tmp/s5-marker-$$', 'w').write('x')
r['tmp_private'] = not os.path.exists('/var/tmp/s5-host-marker-$$')
sd = os.environ.get('STATE_DIRECTORY', '')
try:
    open(sd + '/ok', 'w').write('x'); r['write:state'] = 'ok'
except OSError:
    r['write:state'] = 'FAILED'
r['proc_pids'] = len([d for d in os.listdir('/proc') if d.isdigit()])
try:                                   # the checkpoint crypto under MemoryDenyWriteExecute (S3 + S4 together)
    import sys; sys.path.insert(0, '/opt/agent-src')
    from meshembed_node import agent_host as A
    run = {'ticket_id': 'rt-' + 'a' * 24, 'run_id': 'run-' + 'b' * 24, 'user_id': 'u1'}
    A.save_checkpoint(__import__('pathlib').Path(sd), b'k' * 32, run, 1, [{'role': 'user', 'content': 'x'}])
    r['checkpoint_crypto'] = 'ok' if A.load_checkpoint(__import__('pathlib').Path(sd), b'k' * 32, run) else 'FAILED'
except Exception as e:
    r['checkpoint_crypto'] = 'FAILED'
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
try:
    s.connect('/run/meshembed/agent.sock'); s.sendall(b'{\"op\": \"next_run\"}\n'); d = s.recv(100)
    r['bridge_reply'] = d.decode() or 'closed'
except OSError as e:
    r['bridge_reply'] = 'closed'
print(json.dumps(r))
" | tee /dev/stderr | python3 -c "
import json, sys
r = json.loads(sys.stdin.read().strip().splitlines()[-1])
bad = [k for k, v in r.items() if v in ('ALLOWED', 'FAILED') or v is True and k == 'home_visible'] \
      + (['tmp_private'] if r['tmp_private'] is not True else []) + (['proc_pids'] if r['proc_pids'] > 3 else []) \
      + (['bridge_reply'] if r['bridge_reply'] != 'closed' else [])
print('S5 sandbox:', 'PASS' if not bad else 'FAIL ' + ','.join(bad))
sys.exit(1 if bad else 0)"
[ ! -e "/var/tmp/s5-marker-$$" ] || { echo "S5 sandbox: FAIL the probe's /var/tmp write reached the host"; exit 1; }
# auditor 14:15Z: without the sealed state key the unit does not start at all (LoadCredentialEncrypted on a missing file)
if sudo -n systemd-run --wait --pipe --quiet --unit="$NAME-nocred" -p DynamicUser=yes \
     -p "LoadCredentialEncrypted=state-key:/nonexistent/meshembed-agent-s5-$$.cred" /bin/true 2>/dev/null; then
  echo "S5 sandbox: FAIL the unit started without its sealed state key"; exit 1
fi
echo "S5 no-credential: PASS (the unit refuses to start without state-key.cred)"
