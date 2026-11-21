"""W3 (0.3.87; design DESIGN_W3_PINNED_MODELS_ACL Rev 4 1117538e, auditor design GO 14:06:29Z incl. O1-O6, code GO 09:35:29Z 11-21).

Cause (proven on 160, the section 3 read, Python 3.12.10 >= 3.12.4 where gh-118486 / CVE-2024-4030 landed): os.makedirs(mode=0o700) on
Windows writes a PROTECTED DACL for the creator's identity; the elevated daemon's default owner is BUILTIN\\Administrators, so the node user
is locked out of the directory its own daemon made.

  4(a) private_makedirs(): on Windows create with NO mode (the dir inherits the profile folder's ACL), then -- only when this process is
       elevated or not (always called) -- /setowner to the node user with /L (act on the link itself, never a target) and NO /T, followed at
       once by a no-reparse-point post-check (O6). POSIX is unchanged (mode 0o700).
  4(b) repair_locked_dir(): an EXISTING locked dir is never changed in place (O5): scan for reparse points first (any, anywhere -> refuse the
       whole repair), rename aside (same volume, never deleted), then create a fresh empty dir through 4(a). Marker only after rename AND
       fresh dir both succeed (O3). No `icacls /reset`, no `/T`, anywhere.
Every OS call goes through the `ops` seam; the Windows ops are proven on 160 by the PB-W card, not in CI. Closed outcome words:
repaired | unchanged | refused:reparse_point[:<rel>] | failed:<code>. Never raises into the start.
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import List, Optional

log = logging.getLogger("meshembed.pinned_acl")

MARKER_NAME = "pinned-models-acl-repaired"
ADMINISTRATORS_SID = "S-1-5-32-544"
# W3-c4 (auditor 09:49:20Z): exactly a local/domain account SID or an Entra ID (Azure AD) account SID. NOT the general S-1-N-N form:
# that would let SYSTEM (S-1-5-18) or a service SID become the owner.
_USER_SID = re.compile(r"^(S-1-5-21-\d+-\d+-\d+-\d+|S-1-12-1-\d+-\d+-\d+-\d+)$")


def valid_user_sid(sid: str) -> bool:
    return isinstance(sid, str) and bool(_USER_SID.match(sid))


class Ops:
    """The seam. Real = WinOps; tests pass a fake that records `calls`."""
    calls: List[str]

    def __init__(self):
        self.calls = []

    def makedirs(self, path: str) -> None: ...
    def setowner(self, path: str, sid: str) -> None: ...          # icacls <path> /setowner *<sid> /L /C   (never /T)
    def is_reparse(self, path: str) -> bool: ...                  # the path's OWN attributes (no follow)
    def tree_reparse(self, path: str) -> Optional[str]: ...       # first relpath that is a reparse point / symlink, else None
    def rename(self, src: str, dst: str) -> None: ...             # same volume
    def exists(self, path: str) -> bool: ...
    def user_sid(self) -> str: ...
    def is_locked(self, path: str, user_sid: str) -> bool: ...    # READ ONLY: owner == S-1-5-32-544 AND no ACE for user_sid
    def tree_bytes(self, path: str) -> int: ...                   # W3-c5: size of the aside dir for the log


def private_makedirs(path: str, ops: Optional[Ops] = None, nt: Optional[bool] = None, owner_sid: Optional[str] = None) -> str:
    """Create `path` private to the node user. Returns a closed word: ok | refused:reparse_point | failed:<code>.
    POSIX: os.makedirs(mode=0o700) exactly as before. Windows: NO mode (never mode=0o700: any Python >= 3.12.4 locks the node user out)."""
    is_nt = (os.name == "nt") if nt is None else nt
    if not is_nt:
        os.makedirs(path, mode=0o700, exist_ok=True)
        return "ok"
    ops = ops or WinOps()
    existed = ops.exists(path)
    ops.makedirs(path)
    if existed:
        # W3-c1 (auditor 09:42:54Z): an EXISTING path gets the reparse check too. The node user owns these dirs after W3 and, until W4 ships, the daemon
        # is elevated: a junction planted at a view dir or the cache path before this call would otherwise make prepare() write links in its target.
        if ops.is_reparse(path):
            log.warning("pinned_models_acl: refused:reparse_point")
            return "refused:reparse_point"
        return "ok"                                               # an existing dir is repair's business (4(b)), never changed here
    try:
        sid = owner_sid or ops.user_sid()
        if not valid_user_sid(sid):                               # W3-c4
            log.warning("pinned_models_acl: failed:user_sid")
            return "failed:user_sid"
        ops.setowner(path, sid)                                   # /L /C, no /T
    except Exception as exc:
        log.warning("pinned_models_acl: failed:setowner:%s", type(exc).__name__)
        return "failed:setowner"
    if ops.is_reparse(path):                                       # O6: checked AFTER setowner, whatever setowner returned
        log.warning("pinned_models_acl: refused:reparse_point")
        return "refused:reparse_point"
    return "ok"


def repair_locked_dir(path: str, home_dir: str, locked: bool, ops: Optional[Ops] = None, now=time.time) -> str:
    """4(b), O5. `locked` = the caller's finding that the node user cannot list `path` (it is owned/locked by Administrators).
    Returns one closed word; never raises."""
    ops = ops or WinOps()
    marker = os.path.join(home_dir, MARKER_NAME)
    try:
        if ops.exists(marker) or not ops.exists(path) or not locked:
            return "unchanged"
        bad = ops.tree_reparse(path)                               # step 1: attributes only, whole tree, BEFORE any rename
        if bad is not None:
            log.warning("pinned_models_acl: refused:reparse_point:%s", bad)
            return f"refused:reparse_point:{bad}"
        aside = f"{path}.locked-{int(now())}"
        ops.rename(path, aside)                                    # step 2: never deleted, never touched again by this code
        try:
            size = ops.tree_bytes(aside)                           # W3-c5: so the operator knows what to clean by hand
        except Exception:
            size = -1
        log.warning("pinned_models_acl: moved_aside:%s bytes=%d", os.path.basename(aside), size)
        res = private_makedirs(path, ops, nt=True)                 # step 3: the single create path (O6 inside)
        if res != "ok":
            return res                                             # no marker; the aside dir is NOT restored or deleted
        _write_marker(ops, marker)                                 # O3: only now
        return "repaired"
    except Exception as exc:
        log.warning("pinned_models_acl: failed:%s", type(exc).__name__)
        return f"failed:{type(exc).__name__}"


def _write_marker(ops: Ops, marker: str) -> None:
    if isinstance(ops, WinOps):
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write("1\n")
    else:
        ops.calls.append("marker")


def ensure_at_start(ops: Optional[Ops] = None, nt: Optional[bool] = None, root: Optional[str] = None) -> Optional[str]:
    """W3-c2: once per daemon start, Windows only, BEFORE the first prepare(): repair an existing locked pinned-models dir (O5). `locked` is
    computed here from the dir's security info (read only): owner == S-1-5-32-544 AND no ACE for the node user's SID. Returns the closed word
    (or None when not Windows). Never raises."""
    is_nt = (os.name == "nt") if nt is None else nt
    if not is_nt:
        return None
    try:
        ops = ops or WinOps()
        if root is None:
            from . import embed_pins
            root = embed_pins.pinned_root()
        sid = ops.user_sid()
        if not valid_user_sid(sid):
            log.warning("pinned_models_acl: failed:user_sid")
            return "failed:user_sid"
        home_dir = os.path.dirname(root)
        locked = ops.exists(root) and ops.is_locked(root, sid)
        word = repair_locked_dir(root, home_dir, locked, ops)
        log.info("pinned_models_acl: %s", word)
        return word
    except Exception as exc:
        log.warning("pinned_models_acl: failed:%s", type(exc).__name__)
        return f"failed:{type(exc).__name__}"


def _system32() -> str:  # pragma: no cover - Windows only
    """W3-c6 (auditor 09:49:20Z): the ABSOLUTE System32 directory from GetSystemDirectoryW. No tool is ever started by bare name from the elevated daemon
    (CreateProcess would search the interpreter's directory and the cwd before System32, both possibly user-writable)."""
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    n = ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260)
    if n == 0 or n >= 260:
        raise OSError("GetSystemDirectoryW")
    return buf.value


def _sid_to_string(psid) -> str:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes
    out = wintypes.LPWSTR()
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        raise OSError("ConvertSidToStringSidW")
    try:
        return out.value
    finally:
        k = ctypes.WinDLL("kernel32")
        k.LocalFree.argtypes = [ctypes.c_void_p]
        k.LocalFree(ctypes.cast(out, ctypes.c_void_p))


class WinOps(Ops):  # pragma: no cover - Windows only (PB-W on 160)
    def makedirs(self, path):
        os.makedirs(path, exist_ok=True)                          # NO mode

    def setowner(self, path, sid):
        import subprocess
        subprocess.run([os.path.join(_system32(), "icacls.exe"), path, "/setowner", "*" + sid, "/L", "/C"],
                       check=True, capture_output=True, timeout=60)

    def is_reparse(self, path):
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
        if attrs == 0xFFFFFFFF:
            raise OSError("GetFileAttributesW")
        return bool(attrs & 0x400)                                # FILE_ATTRIBUTE_REPARSE_POINT

    def tree_reparse(self, path):
        for root, dirs, files in os.walk(path, followlinks=False):
            for n in dirs + files:
                p = os.path.join(root, n)
                if os.path.islink(p) or self.is_reparse(p):
                    return os.path.relpath(p, path)
        return None

    def tree_bytes(self, path):
        total = 0
        for root, _d, files in os.walk(path, followlinks=False):
            for f in files:
                try:
                    total += os.lstat(os.path.join(root, f)).st_size
                except OSError:
                    pass
        return total

    def rename(self, src, dst):
        os.rename(src, dst)

    def exists(self, path):
        return os.path.lexists(path)

    def user_sid(self):
        """W3-c6: GetTokenInformation(TokenUser) + ConvertSidToStringSidW. No process is started (no whoami)."""
        import ctypes
        from ctypes import wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        a = ctypes.WinDLL("advapi32", use_last_error=True)
        k.GetCurrentProcess.restype = wintypes.HANDLE
        a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        tok = wintypes.HANDLE()
        if not a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):          # TOKEN_QUERY
            raise OSError("OpenProcessToken")
        try:
            need = wintypes.DWORD()
            a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
            a.GetTokenInformation(tok, 1, None, 0, ctypes.byref(need))                          # TokenUser
            buf = ctypes.create_string_buffer(need.value)
            if not a.GetTokenInformation(tok, 1, buf, need, ctypes.byref(need)):
                raise OSError("GetTokenInformation")
            return _sid_to_string(ctypes.c_void_p.from_buffer(buf).value)                       # TOKEN_USER.User.Sid is the first pointer
        finally:
            k.CloseHandle.argtypes = [wintypes.HANDLE]
            k.CloseHandle(tok)

    def is_locked(self, path, user_sid):
        """READ ONLY (auditor W3-c2): owner == S-1-5-32-544 AND no ACCESS_ALLOWED ACE for the node user's SID, via GetNamedSecurityInfoW."""
        import ctypes
        from ctypes import wintypes
        a = ctypes.WinDLL("advapi32", use_last_error=True)
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        a.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]
        rc = a.GetNamedSecurityInfoW(path, 1, 0x1 | 0x4, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd))   # SE_FILE_OBJECT, OWNER|DACL
        if rc != 0:
            raise OSError(f"GetNamedSecurityInfoW:{rc}")
        try:
            if _sid_to_string(owner) != ADMINISTRATORS_SID:
                return False
            if not dacl.value:                                    # a NULL DACL grants everyone: not the locked state
                return False

            class _AclSize(ctypes.Structure):
                _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD)]
            info = _AclSize()
            a.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
            if not a.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):            # AclSizeInformation
                raise OSError("GetAclInformation")
            a.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
            for i in range(info.AceCount):
                pace = ctypes.c_void_p()
                if not a.GetAce(dacl, i, ctypes.byref(pace)):
                    raise OSError("GetAce")
                if ctypes.c_ubyte.from_address(pace.value).value != 0:                               # ACCESS_ALLOWED_ACE_TYPE only
                    continue
                if _sid_to_string(pace.value + 8) == user_sid:                                       # ACCESS_ALLOWED_ACE.SidStart
                    return False
            return True
        finally:
            k.LocalFree.argtypes = [ctypes.c_void_p]
            k.LocalFree(sd)
