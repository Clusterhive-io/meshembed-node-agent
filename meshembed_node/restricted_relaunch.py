"""W4 (0.3.87; design note DESIGN_W4_RESTRICTED_TOKEN_RELAUNCH Rev 2, auditor design GO fc9cc0cf incl. W4-1..W4-4): the real FX-4-W fix.

When the Windows daemon's own token holds Administrators ENABLED (or integrity >= High) it re-launches itself as a child under
CreateRestrictedToken of its own token (Administrators deny-only, every privilege but SeChangeNotify deleted, integrity Medium) and
supervises that child. Nodes whose token already reads `ok` are untouched; non-Windows never relaunches.

This module is split so everything decidable is testable without Windows:
  - should_relaunch(): the decision table (pure).
  - backoff_delay_s() / BackoffState / record_*: the child-death accounting (pure).
  - supervise(): the parent loop, driven only through the `api` seam (a fake in tests records the call order).
  - WinApi: the thin ctypes wrapper. It is proven on 160 by the spike and the PB-W card, NOT in CI.
Rules the code keeps (auditor W4-1..W4-4):
  - W4-1: bInheritHandles FALSE; the parent closes every token handle it opened and locks its own process DACL BEFORE the child resumes.
  - W4-2: a CHILD death never falls back to the admin token: restart the child with backoff (1, 5, 30 min, then doubling, cap 6 h).
  - W4-3: the in-process admin fallback exists only BEFORE the first successful child (state `first_ok` unset).
  - W4-4: the state file is parent-only, written with an explicit protected DACL (SYSTEM + Administrators).
Closed report tuple CODES (restricted_ok, relaunch_failed, relaunch_backoff, could_not_check): reported under its OWN hardware_info key admin_relaunch, never inside admin_token (W4-Q2-b).
stdlib only. No customer document text is handled here.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from . import admin_token as _admin_token

log = logging.getLogger("meshembed.restricted_relaunch")

CHILD_FLAG = "--restricted-child"
RELAUNCH_FAILED = "relaunch_failed"
RELAUNCH_BACKOFF = "relaunch_backoff"
RESTRICTED_OK = "restricted_ok"
COULD_NOT_CHECK = "could_not_check"
# W4-Q2-b (auditor GO 09:29:27Z): the relaunch outcome is its OWN closed tuple, reported under its OWN hardware_info key, never inside
# hardware_info.admin_token (whose 4 codes say what THIS process's token is).
HW_KEY = "admin_relaunch"
CODES = (RESTRICTED_OK, RELAUNCH_FAILED, RELAUNCH_BACKOFF, COULD_NOT_CHECK)

BACKOFF_MIN = (1, 5, 30)                     # minutes for the 1st, 2nd, 3rd consecutive child death
BACKOFF_CAP_S = 6 * 3600
CLEAN_RUN_RESET_S = 10 * 60                  # a child that ran >= 10 min resets n
# W4-H (auditor 14:54:54Z): on Windows the daemon ends a self-update (worker._perform_self_update) and an owner restart (worker restart path)
# with exit 3 = "relaunch me on the new code". The restricted child is the process that does that, so the PARENT must pass it on: if it
# counted 3 as a child death it would back off and restart the child under the OLD parent code (the supervisor would stay old until a reboot).
RELAUNCH_ME_EXIT = 3

ADMINISTRATORS_SID = "S-1-5-32-544"
SYSTEM_SID = "S-1-5-18"
# S2-c (auditor 09:57:06Z): the parent's own process DACL. OWNER RIGHTS (OW) limited to READ_CONTROL so the parent's owner (possibly the node
# user's SID, which the child also holds) has no implicit WRITE_DAC / WRITE_OWNER on the parent process.
PARENT_PROCESS_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;RC;;;OW)"
# S2-d: the parent-only state dir is CREATED with this descriptor atomically (CreateDirectoryW + SECURITY_ATTRIBUTES), never created then re-ACL'd.
STATE_DIR_SDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
STATE_DIR_OK_OWNERS = (SYSTEM_SID, ADMINISTRATORS_SID)
_USER_SID_RE = None


def child_default_dacl_sddl(user_sid: str) -> str:
    """Auditor 10:15:14Z (product note): the restricted child's TokenDefaultDacl = SYSTEM + the node user's SID, NEVER Administrators (deny-only in
    the child, so a BA-only default would lock the child out of its own process and the objects it creates). Refuses anything that is not a plain
    account SID (same two forms as W3-c4), so no group or service SID can be named here."""
    import re
    global _USER_SID_RE
    if _USER_SID_RE is None:
        _USER_SID_RE = re.compile(r"^(S-1-5-21-\d+-\d+-\d+-\d+|S-1-12-1-\d+-\d+-\d+-\d+)$")
    if not isinstance(user_sid, str) or not _USER_SID_RE.match(user_sid):
        raise ValueError("child_default_dacl: not an account SID")
    return f"D:(A;;GA;;;SY)(A;;GA;;;{user_sid})"
MEDIUM_INTEGRITY_SID = "S-1-16-8192"


# ---------------------------------------------------------------- decision (pure)
def should_relaunch(code: Optional[str], argv: Sequence[str], paused: bool, platform: str = sys.platform) -> bool:
    """True only on Windows, in the PARENT (no --restricted-child), not paused, and the token reads admins_enabled / integrity_high.
    `ok`, `could_not_check` (WARN as today) and a non-Windows platform never relaunch. The flag, not the token, stops recursion."""
    if not platform.startswith("win"):
        return False
    if CHILD_FLAG in argv:
        return False
    if paused:
        return False
    return code in (_admin_token.ADMINS_ENABLED, _admin_token.INTEGRITY_HIGH)


# ---------------------------------------------------------------- backoff / state (pure)
def backoff_delay_s(n: int) -> int:
    """Seconds to wait before restarting the child after its n-th consecutive death (n >= 1): 1, 5, 30 min, then doubling, cap 6 h."""
    if n < 1:
        return 0
    if n <= len(BACKOFF_MIN):
        return min(BACKOFF_MIN[n - 1] * 60, BACKOFF_CAP_S)
    return min(BACKOFF_MIN[-1] * 60 * (2 ** (n - len(BACKOFF_MIN))), BACKOFF_CAP_S)


@dataclass
class State:
    n: int = 0                               # consecutive child deaths
    at: float = 0.0                          # when the last death was recorded
    first_ok: bool = False                   # set at the FIRST successful child; from then on no admin fallback (W4-3)

    def to_json(self) -> str:
        return json.dumps({"n": self.n, "at": self.at, "first_ok": self.first_ok})

    @staticmethod
    def from_json(text: str) -> "State":
        try:
            d = json.loads(text)
            return State(n=max(0, int(d.get("n", 0))), at=float(d.get("at", 0.0)), first_ok=bool(d.get("first_ok", False)))
        except Exception:                    # unreadable state: fail toward the SAFE side only if a child ever ran, which we cannot know
            return State()                   # (the file is parent-only, so this is a fresh node or a damaged file; logged by the caller)


def reportable(raw: object) -> str:
    """W4-Q2-c: the ONLY value the child may send in hardware_info.admin_relaunch. `raw` is whatever the parent-written state file held
    for the code (any type). A value outside CODES, or anything that is not a plain str, becomes could_not_check: no free text, path or
    exception string ever reaches hardware_info. A `relaunch_failed:<api>:<err>` detail stays in the local log only."""
    if isinstance(raw, str):
        head = raw.split(":", 1)[0]
        if raw == head and head in CODES:
            return head
        if head == RELAUNCH_FAILED:
            return RELAUNCH_FAILED
    return COULD_NOT_CHECK


def _normalize_sddl(sddl: Optional[str]):
    """Windows may print the same DACL with its ACEs in another order: compare the flags prefix and the SET of ACE strings (exact otherwise)."""
    if not isinstance(sddl, str) or not sddl.startswith("D:"):
        return None
    head, _, rest = sddl.partition("(")
    aces = frozenset(a for a in ("(" + rest).replace(")(", ")\n(").split("\n") if a)
    return head, aces


def child_cmdline(executable: str, code: str, extra_args: Sequence[str] = ()) -> str:
    """The restricted child's command line (a Windows command-line string): `<python> -m meshembed_node run --restricted-child
    --admin-relaunch=<code>`. `code` must be a value of CODES (the child validates it again with reportable())."""
    import subprocess
    if code not in CODES:
        code = COULD_NOT_CHECK
    return subprocess.list2cmdline([executable, "-m", "meshembed_node", "run", CHILD_FLAG, f"{ARG_CODE}={code}", *extra_args])


ARG_CODE = "--admin-relaunch"


_fallback_code: Optional[str] = None      # W4-C: set by supervise() before the in-process (0.3.86-style) fallback so the node still reports it


def child_report(argv: Sequence[str]) -> Optional[str]:
    """In the CHILD: the closed value the parent passed (validated), or None when this process is not a restricted child (no key sent).
    Anything unreadable becomes could_not_check (W4-Q2-c)."""
    if CHILD_FLAG not in argv:
        return _fallback_code
    for a in argv:
        if isinstance(a, str) and a.startswith(ARG_CODE + "="):
            return reportable(a.split("=", 1)[1])
    return COULD_NOT_CHECK


def state_dir_decision(exists: bool, owner_sid: Optional[str], dacl_sddl: Optional[str]) -> str:
    """S2-d: what the parent does about the state dir. `create` (it does not exist: create it atomically with STATE_DIR_SDDL), `ok` (exists with an
    owner of SYSTEM / Administrators and EXACTLY the expected DACL), or a closed refusal. An existing dir that does not match is never trusted or
    repaired in place (the child might have pre-created or planted it): the parent refuses and takes the backoff path."""
    if not exists:
        return "create"
    if owner_sid not in STATE_DIR_OK_OWNERS:
        return "refused:state_dir_owner"
    if _normalize_sddl(dacl_sddl) != _normalize_sddl(STATE_DIR_SDDL):
        return "refused:state_dir_acl"
    return "ok"


def record_child_run(state: State, ran_s: float, now: float) -> State:
    """Account for a child that has ended after `ran_s` seconds. A clean run of >= 10 min resets n; any other end counts as a death."""
    if ran_s >= CLEAN_RUN_RESET_S:
        state.first_ok = True                # W4-B (auditor 10:36:09Z): "first SUCCESSFUL child" = one that ran >= 10 min, not any child end
        state.n = 0
    else:
        state.n += 1
    state.at = now
    return state


def admin_fallback_allowed(state: State) -> bool:
    """W4-3: the in-process admin daemon is allowed ONLY for a parent-side failure before the first successful child."""
    return not state.first_ok


# ---------------------------------------------------------------- the parent loop (driven through the api seam)
class RelaunchFailed(Exception):
    """A PARENT-side failure (token build / CreateProcess / repair). `.code` is the closed `relaunch_failed:<api>:<err>` string."""

    def __init__(self, api: str, err: int):
        super().__init__(f"{RELAUNCH_FAILED}:{api}:{err}")
        self.code = f"{RELAUNCH_FAILED}:{api}:{err}"


@dataclass
class Api:
    """The seam. The real one is WinApi; tests pass a fake that records `calls`."""
    calls: List[str] = field(default_factory=list)

    def prepare_parent(self) -> None: ...                       # W3 repair + `.env` move, then nothing else (raises RelaunchFailed)
    def start_child(self) -> object: ...                        # build token, CreateProcessAsUser suspended, close token handles, lock DACL,
                                                                # job assign, resume (raises RelaunchFailed); returns a child handle
    def wait_child(self, child: object) -> int: ...             # blocks, returns the exit code
    def read_state(self) -> State: ...
    def write_state(self, state: State) -> None: ...
    def paused(self) -> bool: ...


def _safe_write(api: "Api", state: State) -> None:
    """W4-A: a state-file write error (a planted or odd state dir) is logged with a closed word and never escapes; the in-memory state is kept by the caller."""
    try:
        api.write_state(state)
    except Exception as exc:
        log.warning("%s:state_write:%s", RELAUNCH_FAILED, exc.code if isinstance(exc, RelaunchFailed) else type(exc).__name__)


def supervise(api: Api, run_in_process: Callable[[], int], now: Callable[[], float] = time.time,
              sleep: Callable[[float], None] = time.sleep, max_loops: Optional[int] = None) -> int:
    """The parent. Returns the exit code the task scheduler should see (today's semantics: 0 = stopped, non-zero = restart in 1 min).

    - parent-side failure BEFORE the first success: WARN, log relaunch_failed:<api>:<err>, run the daemon in-process as 0.3.86.
    - parent-side failure AFTER the first success: backoff (never the admin daemon, W4-3).
    - child death: backoff and restart the CHILD (W4-2); n resets after a >= 10 min clean run.
    - paused: exit 0, nothing spawned.
    """
    loops = 0
    try:
        state = api.read_state()            # W4-F (auditor 10:46:30Z): read the persisted state ONCE and carry it in memory; writes only persist it,
    except Exception:                       # so a failing write can never reset the backoff (it would respawn a dying child in a tight loop)
        state = State()
    while True:
        loops += 1
        if max_loops is not None and loops > max_loops:
            return 1
        if api.paused():
            return 0
        if state.n > 0:
            wait = backoff_delay_s(state.n) - (now() - state.at)
            if wait > 0:
                log.warning("%s: n=%d, waiting %.0f s", RELAUNCH_BACKOFF, state.n, wait)
                sleep(wait)
        try:
            api.prepare_parent()
            child = api.start_child()
        except Exception as exc:            # W4-A: ANY exception here is a parent-side failure, never a crash of the parent (a crash loop on every admin node)
            code = exc.code if isinstance(exc, RelaunchFailed) else f"{RELAUNCH_FAILED}:exception:{type(exc).__name__}"
            if admin_fallback_allowed(state):
                global _fallback_code
                _fallback_code = RELAUNCH_FAILED
                log.warning("%s (FX-4-W remains on this node: in-process, admin token, as 0.3.86)", code)
                return run_in_process()
            log.warning("%s after a first success: %s, backoff, no admin daemon", RELAUNCH_BACKOFF, code)
            state.n += 1
            state.at = now()
            _safe_write(api, state)
            continue
        started = now()
        try:
            code = api.wait_child(child)
        except Exception as exc:            # W4-G: a ctypes error while waiting is a child death, never a crash of the parent
            log.warning("%s:wait:%s", RELAUNCH_FAILED, type(exc).__name__)
            code = 1
        if code == RELAUNCH_ME_EXIT:
            log.info("restricted_relaunch: child asked to be relaunched (exit %d): exiting %d so the task restarts the PARENT on the new code",
                     code, code)
            return code                     # W4-H: no backoff, no state write that counts a death
        state = record_child_run(state, now() - started, now())
        _safe_write(api, state)
        if api.paused() or code == 0:
            return 0 if api.paused() else code
        # non-zero child exit: loop = backoff + restart the CHILD; the parent never returns the admin daemon here


# ---------------------------------------------------------------- the real Windows wrapper (spike + PB-W on 160; not run in CI)
class WinApi(Api):  # pragma: no cover - Windows only (spike 1 rev2 proved the token recipe on 160; PB-W proves the rest)
    """ctypes wrapper. start_child order (W4-1, S2-c): OpenProcessToken -> CreateRestrictedToken(DISABLE_MAX_PRIVILEGE, SidsToDisable=[Administrators])
    -> TokenIntegrityLevel Medium -> TokenDefaultDacl = SYSTEM + the node user (never BA) -> CreateProcessAsUserW(CREATE_SUSPENDED | CREATE_NO_WINDOW,
    bInheritHandles=FALSE) -> close EVERY token handle -> lock the parent's own process DACL (PARENT_PROCESS_SDDL) -> Job(KILL_ON_JOB_CLOSE) assign ->
    ResumeThread. Spike 1 (160, 2026-11-21 10:13Z): CreateProcessAsUserW works from the elevated parent without SeAssignPrimaryToken (Q1 answered)."""

    def __init__(self, state_dir: Optional[str] = None, code: str = RESTRICTED_OK):
        super().__init__()
        self.state_dir = state_dir or os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "MeshEmbed", "relaunch")
        self.state_path = os.path.join(self.state_dir, "relaunch-state")
        self.code = code
        self._job = None

    # ---- helpers
    @staticmethod
    def _dlls():
        import ctypes
        return ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("advapi32", use_last_error=True)

    def _fail(self, api: str) -> "RelaunchFailed":
        import ctypes
        return RelaunchFailed(api, ctypes.get_last_error())

    def _sddl_to_dacl(self, sddl: str):
        import ctypes
        from ctypes import wintypes
        k, a = self._dlls()
        sd = ctypes.c_void_p()
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
            raise self._fail("ConvertStringSecurityDescriptor")
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        a.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
        if not a.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise self._fail("GetSecurityDescriptorDacl")
        return sd, dacl

    def _lock_own_process_dacl(self) -> None:
        """W4-1 + S2-c: SYSTEM + Administrators full control, OWNER RIGHTS = READ_CONTROL only, protected."""
        import ctypes
        from ctypes import wintypes
        k, a = self._dlls()
        sd, dacl = self._sddl_to_dacl(PARENT_PROCESS_SDDL)
        k.OpenProcess.restype = wintypes.HANDLE
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        h = k.OpenProcess(0x00040000, False, os.getpid())                       # WRITE_DAC
        if not h:
            raise self._fail("OpenProcess")
        try:
            a.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            rc = a.SetSecurityInfo(h, 6, 0x4 | 0x80000000, None, None, dacl, None)   # SE_KERNEL_OBJECT, DACL | PROTECTED_DACL
            if rc != 0:
                raise RelaunchFailed("SetSecurityInfo", rc)
        finally:
            k.CloseHandle(h)

    # ---- Api
    def prepare_parent(self) -> None:
        """Design section 5: the W3 repair runs in the parent (still holding its admin token) BEFORE the relaunch. A missing W3 module is not an error."""
        try:
            from . import pinned_acl
        except ImportError:
            return
        pinned_acl.ensure_at_start()                                              # never raises; closed words logged

    def start_child(self) -> object:
        import ctypes
        from ctypes import wintypes
        k, a = self._dlls()
        user_sid = _user_sid_string()
        self.code = RELAUNCH_BACKOFF if self.read_state().n > 0 else RESTRICTED_OK        # what the child reports (closed tuple; it validates it again)
        handles = []

        class SID_AND_ATTR(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD), ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                        ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

        def close_all():
            for h in handles:
                k.CloseHandle(h)
            handles.clear()

        try:
            k.GetCurrentProcess.restype = wintypes.HANDLE
            tok = wintypes.HANDLE()
            a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
            if not a.OpenProcessToken(k.GetCurrentProcess(), 0x0002 | 0x0001 | 0x0008 | 0x0080, ctypes.byref(tok)):   # DUPLICATE|ASSIGN_PRIMARY|QUERY|ADJUST_DEFAULT
                raise self._fail("OpenProcessToken")
            handles.append(tok)
            adm, med = ctypes.c_void_p(), ctypes.c_void_p()
            a.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
            if not a.ConvertStringSidToSidW(ADMINISTRATORS_SID, ctypes.byref(adm)) or not a.ConvertStringSidToSidW(MEDIUM_INTEGRITY_SID, ctypes.byref(med)):
                raise self._fail("ConvertStringSidToSid")
            dis = SID_AND_ATTR(adm, 0)
            rt = wintypes.HANDLE()
            a.CreateRestrictedToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                                wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]
            if not a.CreateRestrictedToken(tok, 0x1, 1, ctypes.byref(dis), 0, None, 0, None, ctypes.byref(rt)):             # DISABLE_MAX_PRIVILEGE
                raise self._fail("CreateRestrictedToken")
            handles.append(rt)
            tml = SID_AND_ATTR(med, 0x20)                                                                                   # SE_GROUP_INTEGRITY
            a.GetLengthSid.argtypes = [ctypes.c_void_p]
            a.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            if not a.SetTokenInformation(rt, 25, ctypes.byref(tml), ctypes.sizeof(tml) + a.GetLengthSid(med)):               # TokenIntegrityLevel
                raise self._fail("SetTokenInformation(integrity)")
            _sd, dacl = self._sddl_to_dacl(child_default_dacl_sddl(user_sid))
            tdd = ctypes.c_void_p(dacl.value)
            if not a.SetTokenInformation(rt, 6, ctypes.byref(tdd), ctypes.sizeof(tdd)):                                     # TokenDefaultDacl
                raise self._fail("SetTokenInformation(default_dacl)")
            si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
            pi = PROCESS_INFORMATION()
            cmd = ctypes.create_unicode_buffer(child_cmdline(sys.executable, self.code))
            a.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
                                               wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
            if not a.CreateProcessAsUserW(rt, None, cmd, None, None, False, 0x00000004 | 0x08000000, None, None, ctypes.byref(si), ctypes.byref(pi)):  # SUSPENDED | NO_WINDOW; bInheritHandles FALSE (W4-1)
                raise self._fail("CreateProcessAsUserW")
            child_p, child_t = pi.hProcess, pi.hThread
            close_all()                                                                                                     # W4-1: EVERY token handle closed before the child runs
            try:
                self._lock_own_process_dacl()                                                                               # W4-1 / S2-c
                self._job = self._make_kill_on_close_job(k)
                k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
                if not k.AssignProcessToJobObject(self._job, child_p):
                    raise self._fail("AssignProcessToJobObject")
                if k.ResumeThread(child_t) == 0xFFFFFFFF:
                    raise self._fail("ResumeThread")
            except Exception:
                k.TerminateProcess(child_p, 1)
                k.CloseHandle(child_p)
                k.CloseHandle(child_t)
                raise
            k.CloseHandle(child_t)
            return child_p
        finally:
            close_all()

    def _make_kill_on_close_job(self, k):
        import ctypes
        from ctypes import wintypes

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class IOC(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("ro", "wo", "oo", "rt", "wt", "ot")]

        class EXT(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("Io", IOC), ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        k.CreateJobObjectW.restype = wintypes.HANDLE
        k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        job = k.CreateJobObjectW(None, None)
        if not job:
            raise self._fail("CreateJobObject")
        info = EXT(); info.Basic.LimitFlags = 0x2000                                                                         # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        if not k.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):                                  # JobObjectExtendedLimitInformation
            raise self._fail("SetInformationJobObject")
        return job

    def wait_child(self, child: object) -> int:
        import ctypes
        from ctypes import wintypes
        k, _a = self._dlls()
        k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.WaitForSingleObject(child, 0xFFFFFFFF)
        code = wintypes.DWORD()
        k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        ok = k.GetExitCodeProcess(child, ctypes.byref(code))
        k.CloseHandle(child)
        return int(code.value) if ok else 1

    def paused(self) -> bool:
        from . import pause
        return pause.paused()

    def read_state(self) -> State:
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                return State.from_json(fh.read())
        except FileNotFoundError:
            return State()
        except OSError:
            return State()

    def _ensure_state_dir(self) -> None:
        """S2-d: create the dir ATOMICALLY with STATE_DIR_SDDL (CreateDirectoryW + SECURITY_ATTRIBUTES); an existing dir must have an owner of
        SYSTEM / Administrators and the exact DACL, else refuse (closed word, no repair in place)."""
        import ctypes
        from ctypes import wintypes
        k, a = self._dlls()
        if os.path.lexists(self.state_dir):
            from . import pinned_acl
            if pinned_acl.WinOps().is_reparse(self.state_dir):      # W4-D: GetNamedSecurityInfoW follows a junction
                raise RelaunchFailed("refused:state_dir_reparse", 0)
            owner, sddl = _dir_owner_and_dacl_sddl(self.state_dir)
            word = state_dir_decision(True, owner, sddl)
            if word != "ok":
                raise RelaunchFailed(word, 0)
            return
        sd, _d = self._sddl_to_dacl(STATE_DIR_SDDL)

        class SA(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]
        sa = SA(ctypes.sizeof(SA), sd.value, False)
        k.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SA)]
        os.makedirs(os.path.dirname(self.state_dir), exist_ok=True)
        if not k.CreateDirectoryW(self.state_dir, ctypes.byref(sa)):
            raise self._fail("CreateDirectoryW")

    def write_state(self, state: State) -> None:
        self._ensure_state_dir()
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(state.to_json())
        os.replace(tmp, self.state_path)


def _user_sid_string() -> str:  # pragma: no cover - Windows only
    from . import pinned_acl
    sid = pinned_acl.WinOps().user_sid()
    if not pinned_acl.valid_user_sid(sid):
        raise RelaunchFailed("user_sid", 0)
    return sid


def _dir_owner_and_dacl_sddl(path: str):  # pragma: no cover - Windows only
    """(owner SID string, DACL as SDDL) of an existing dir, read only."""
    import ctypes
    from ctypes import wintypes
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    from . import pinned_acl
    owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    a.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
    if a.GetNamedSecurityInfoW(path, 1, 0x1 | 0x4, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd)) != 0:
        return None, None
    try:
        out, n = wintypes.LPWSTR(), wintypes.DWORD()
        a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
        if not a.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 0x4, ctypes.byref(out), ctypes.byref(n)):          # DACL_SECURITY_INFORMATION
            return None, None
        sddl = out.value
        k.LocalFree.argtypes = [ctypes.c_void_p]
        k.LocalFree(ctypes.cast(out, ctypes.c_void_p))
        return pinned_acl._sid_to_string(owner), sddl
    finally:
        k.LocalFree(sd)


def maybe_relaunch(argv: Sequence[str], run_in_process: Callable[[], int], platform: str = sys.platform,
                   api_factory: Callable[[], Api] = WinApi,
                   check: Callable[[], Optional[str]] = _admin_token.check, paused: Callable[[], bool] = lambda: False) -> Optional[int]:
    """The single entry from __main__: returns an exit code when this process acted as the parent (the caller exits with it),
    or None when the daemon should simply run in-process (every case except Windows + admins_enabled/integrity_high, parent)."""
    if not platform.startswith("win") or CHILD_FLAG in argv:
        return None
    code = check()
    if not should_relaunch(code, argv, paused(), platform):
        return None
    return supervise(api_factory(), run_in_process)
