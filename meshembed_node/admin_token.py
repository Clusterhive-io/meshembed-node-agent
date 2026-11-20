"""FX-4-W (0.3.86; auditor GO (design) 2026-11-17 17:31:48Z, note f2f357c9, C1-C4): the daemon reads its OWN effective token at start.

FX-4 (the installer's Test-NodeTaskPrincipal) reads the task's declared principal (RunLevel Limited); it never looked at the token the
daemon process really runs under. On 160 an S4U task registered "Limited" still ran with BUILTIN\\Administrators ENABLED (the daemon created
pinned-models owned by Administradores). This module is the self-check, the one read that needs no elevation:

  - C1 (binding): detect what was PROVEN: BUILTIN\\Administrators (S-1-5-32-544) ENABLED in the daemon's own token (CheckTokenMembership
    with a NULL token = the calling process's effective token), and/or the token integrity level >= High. NOT TokenElevationType Full: an
    unfiltered S4U token has no linked token and reports Default, which would pass on 160.
  - C2: WARN, not refuse, in this release (a refuse without a fallback account would stop most solo-admin home nodes; tied to the operator's
    A/B). A closed-vocabulary log line at every start, and a closed-vocabulary value in hardware_info the backend can count.
  - C3: a failure to read is "could_not_check", logged, never silent and never a pass.
Windows only. stdlib only (ctypes). Everything else returns None (no claim).
"""
from __future__ import annotations

import logging
import sys
from typing import Callable, Dict, Optional, Tuple

log = logging.getLogger("meshembed.admin_token")

ADMINISTRATORS_SID = "S-1-5-32-544"
HIGH_INTEGRITY_RID = 0x3000                      # SECURITY_MANDATORY_HIGH_RID
# the closed vocabulary (log line, `maintenance status`, hardware_info.admin_token):
OK, ADMINS_ENABLED, INTEGRITY_HIGH, COULD_NOT_CHECK = "ok", "admins_enabled", "integrity_high", "could_not_check"
CODES = (OK, ADMINS_ENABLED, INTEGRITY_HIGH, COULD_NOT_CHECK)

_state: Dict[str, str] = {}


def classify(admins_enabled: bool, integrity_rid: int) -> str:
    """The closed code for a token read. Administrators enabled is the proven FX-4-W condition and wins; a High (or System)
    integrity level with Administrators NOT enabled is the second signal."""
    if admins_enabled:
        return ADMINS_ENABLED
    if integrity_rid >= HIGH_INTEGRITY_RID:
        return INTEGRITY_HIGH
    return OK


def _read_token() -> Tuple[bool, int]:
    """(Administrators enabled in this process's token, its integrity RID). Windows only; raises on any failure (the caller says
    could_not_check)."""
    import ctypes
    from ctypes import wintypes
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sid = ctypes.c_void_p()
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    if not advapi32.ConvertStringSidToSidW(ADMINISTRATORS_SID, ctypes.byref(sid)):
        raise OSError("ConvertStringSidToSidW")
    try:
        member = wintypes.BOOL()
        advapi32.CheckTokenMembership.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL)]
        if not advapi32.CheckTokenMembership(None, sid, ctypes.byref(member)):    # NULL token = the effective token of this process
            raise OSError("CheckTokenMembership")
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree(sid)
    # the integrity level of the process token
    token = wintypes.HANDLE()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):      # TOKEN_QUERY
        raise OSError("OpenProcessToken")
    try:
        need = wintypes.DWORD()
        advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                                 ctypes.POINTER(wintypes.DWORD)]
        advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(need))                          # TokenIntegrityLevel
        buf = ctypes.create_string_buffer(need.value)
        if not advapi32.GetTokenInformation(token, 25, buf, need, ctypes.byref(need)):
            raise OSError("GetTokenInformation")
        # TOKEN_MANDATORY_LABEL starts with SID_AND_ATTRIBUTES: the first pointer-sized field is the SID
        psid = ctypes.c_void_p.from_buffer(buf).value
        advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
        advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
        advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        n = advapi32.GetSidSubAuthorityCount(psid).contents.value
        rid = advapi32.GetSidSubAuthority(psid, n - 1).contents.value
    finally:
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle(token)
    return bool(member.value), int(rid)


def check(platform: str = sys.platform, read: Optional[Callable[[], Tuple[bool, int]]] = None) -> Optional[str]:
    """The closed code for THIS process's token, or None when this is not Windows (no claim). Never raises."""
    if not platform.startswith("win"):
        return None
    try:
        admins, rid = (read or _read_token)()
        return classify(bool(admins), int(rid))
    except Exception as exc:                                     # C3: never silent, never a pass
        log.warning("admin_token: could_not_check (%s)", type(exc).__name__)
        return COULD_NOT_CHECK


def warn_at_start(platform: str = sys.platform, read: Optional[Callable[[], Tuple[bool, int]]] = None) -> Optional[str]:
    """Run at every daemon start (beside the pause check). WARN only in this release: nothing is refused. Records the code for
    hardware_info / `maintenance status`."""
    code = check(platform, read)
    if code is None:
        return None
    _state["code"] = code
    if code in (ADMINS_ENABLED, INTEGRITY_HIGH):
        log.warning("admin_token: %s (FX-4-W: this daemon holds Administrators / a High integrity level although the task says "
                    "RunLevel Limited; see the release notes)", code)
    else:
        log.info("admin_token: %s", code)
    return code


def last() -> Optional[str]:
    """The code recorded at this start (None: not Windows, or not run yet)."""
    return _state.get("code")
