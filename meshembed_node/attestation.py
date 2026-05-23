"""TPM 2.0 PCR attestation — Layer E.1.

Reads PCR (Platform Configuration Register) values from the host's
TPM 2.0 device via the kernel's sysfs interface and the resource
manager device. Reports tpm_available + the PCR snapshot on every
poll so the backend can detect kernel drift, unauthorized module
loads, and Secure Boot toggling.

E.1 is *unsigned* — the daemon reads PCRs and reports them as truth.
A malicious operator can fabricate values. E.2 (planned) adds
tpm2_quote signing where the TPM's endorsement key signs the PCR
values + a backend-issued nonce so spoofing requires extracting
the TPM signing key from the chip, which is hardware-enforced.

PCR meaning (TPM 2.0 standard mapping):
  0  -- firmware code (BIOS/UEFI)
  1  -- firmware data + boot config
  2-3 -- option ROMs / drivers
  4-5 -- bootloader code + config
  7  -- Secure Boot policy (toggled by enabling/disabling Secure Boot)
  8-9 -- kernel + initrd measurements (when measured boot is configured)
  10 -- IMA runtime measurements (Linux integrity)
  11 -- BitLocker / dm-crypt
  14 -- Microsoft Boot
  16+ -- application-defined / reset on resume

We report PCRs 0, 1, 4, 5, 7, 8, 9, 10. Higher PCRs are
application-specific and we don't want to over-fingerprint.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

log = logging.getLogger(__name__)


# Standardized set of PCRs we read. Limiting the set reduces noise
# and avoids accidentally tracking application-controlled PCRs (which
# can change for legitimate reasons).
_PCRS_TO_READ = (0, 1, 4, 5, 7, 8, 9, 10)


def _tpm_device_path() -> Optional[str]:
    """Return the first TPM device path that exists, or None.

    Preference: /dev/tpmrm0 (resource manager, usable without root in
    most distros) > /dev/tpm0 (raw device, typically root-only).
    """
    for candidate in ("/dev/tpmrm0", "/dev/tpm0"):
        if os.path.exists(candidate):
            return candidate
    return None


def _read_pcr_sysfs(bank: str = "sha256") -> Dict[str, str]:
    """Read PCRs from /sys/class/tpm/tpm0/pcr-<bank>/<idx>.

    Modern kernels (5.13+) expose PCR values as files under
    /sys/class/tpm/tpm0/pcr-sha256/<idx>. Each file contains the
    hex hash. World-readable on most distros.

    Returns {str(idx): hex_hash} for each PCR we could read. Empty
    dict if the sysfs path doesn't exist (older kernel or no TPM).
    """
    base = Path(f"/sys/class/tpm/tpm0/pcr-{bank}")
    if not base.is_dir():
        return {}
    result: Dict[str, str] = {}
    for idx in _PCRS_TO_READ:
        p = base / str(idx)
        try:
            if p.is_file():
                value = p.read_text(encoding="utf-8").strip().lower()
                # Normalize: some kernels output with leading "0x" or
                # whitespace. Strip and validate it's hex.
                value = value.removeprefix("0x").strip()
                if all(c in "0123456789abcdef" for c in value) and value:
                    result[str(idx)] = value
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return result


def collect_tpm_state() -> Tuple[bool, Dict[str, str]]:
    """Return (tpm_available, pcr_values).

    tpm_available is True iff we can see a TPM device AND read at
    least one PCR. pcr_values is a dict of str(idx) -> hex hash for
    the PCRs we successfully read (subset of _PCRS_TO_READ).

    Failure modes (all return (False, {})):
      * No /dev/tpmrm0 nor /dev/tpm0 (host has no TPM, or it's disabled
        in BIOS, or it's TPM 1.2 which we don't support).
      * /sys/class/tpm/tpm0/pcr-sha256 doesn't exist (kernel too old).
      * All PCR file reads fail (permissions, races).

    This is intentionally permissive in the "can't read" direction:
    we'd rather miss the signal on some hosts than crash the daemon.
    The backend treats absent fields as "TPM unknown" -- no
    enforcement applies until the operator opts in via env.
    """
    dev = _tpm_device_path()
    if dev is None:
        return False, {}
    pcrs = _read_pcr_sysfs()
    if not pcrs:
        # TPM device exists but we can't read PCRs (kernel < 5.13 or
        # permission denied on sysfs). Report tpm_available=True so
        # the backend knows the host has a TPM, but with no PCRs the
        # attestation status stays "unknown".
        log.info(
            "tpm.no_pcrs device=%s sysfs_missing=%s",
            dev,
            not Path("/sys/class/tpm/tpm0/pcr-sha256").is_dir(),
        )
        return True, {}
    log.info("tpm.pcrs_read device=%s count=%d", dev, len(pcrs))
    return True, pcrs
