"""Sanity checks on an uploaded macOS installer package.

Reads the xar table of contents to detect whether a package is a product archive and signed,
which are required for MDM delivery to succeed on the device.
"""
import struct
import zlib
from typing import Any, BinaryIO, Dict, List

_XAR_MAGIC = b"xar!"
_HEADER_LEN = 28  # magic(4) header_size(2) version(2) toc_zlen(8) toc_len(8) cksum(4)
# A TOC is a few KB. Refuse to inflate anything claiming to be larger rather than trust an uploaded file's header.
_MAX_TOC_LEN = 16 * 1024 * 1024

WARN_COMPONENT = (
    "This looks like a component package (built with pkgbuild). macOS only "
    "installs MDM-delivered packages that are product archives: wrap it with "
    "productbuild --package before uploading, or the device will refuse it "
    "with \"Could not create PKProduct\"."
)
WARN_UNSIGNED = (
    "This package is not signed. macOS expects a Developer ID Installer signature on packages installed through MDM; an"
    " unsigned one may be refused on the device."
)


def inspect_pkg(fileobj: BinaryIO) -> Dict[str, Any]:
    """Return {"format": "xar"|"unknown", "distribution": bool, "signed": bool, "warnings": [str]}.

    Reads from current position and seeks back so an upload handler can inspect before storing.
    """
    start = fileobj.tell()
    try:
        header = fileobj.read(_HEADER_LEN)
        if len(header) < _HEADER_LEN or header[:4] != _XAR_MAGIC:
            return {"format": "unknown", "distribution": False, "signed": False,
                    "warnings": []}
        _magic, header_size, _version, toc_zlen, toc_len, _cksum = struct.unpack(
            ">4sHHQQI", header)
        if toc_zlen > _MAX_TOC_LEN or toc_len > _MAX_TOC_LEN:
            return {"format": "xar", "distribution": False, "signed": False,
                    "warnings": ["The package table of contents is implausibly large; "
                                 "the file may be corrupt."]}
        fileobj.seek(start + header_size)
        toc = zlib.decompress(fileobj.read(toc_zlen), zlib.MAX_WBITS, toc_len or 0)
    except (OSError, zlib.error, struct.error):
        return {"format": "unknown", "distribution": False, "signed": False,
                "warnings": []}
    finally:
        try:
            fileobj.seek(start)
        except OSError:
            pass
    text = toc.decode("utf-8", errors="replace")
    distribution = "<name>Distribution</name>" in text
    signed = "<signature" in text
    warnings: List[str] = []
    if not distribution:
        warnings.append(WARN_COMPONENT)
    if not signed:
        warnings.append(WARN_UNSIGNED)
    return {"format": "xar", "distribution": distribution, "signed": signed,
            "warnings": warnings}
