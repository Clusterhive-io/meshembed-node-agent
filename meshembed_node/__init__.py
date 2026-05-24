"""MeshEmbed Node — GPU worker daemon."""
from __future__ import annotations

try:
    from importlib.metadata import version as _pkg_version, PackageNotFoundError
    try:
        __version__ = _pkg_version("meshembed-node")
    except PackageNotFoundError:
        __version__ = "0.0.0+unknown"
except Exception:
    __version__ = "0.0.0+unknown"
