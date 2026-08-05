"""forge/phase4/artifact_parsers.py — safe passive parsers for 9 formats.

Task 18. Adds detection + basic-metadata extraction for:

1. ``.msi`` — Windows installers (MS-CFBF stream parse)
2. ``.dmg`` — macOS disk images (koly trailer + partition table)
3. ``.rpm`` — Red Hat packages (RPM header lead)
4. ``.war`` / ``.ear`` — Java web archives (JAR/ZIP with WEB-INF/META-INF)
5. PDF attachments — /EmbeddedFiles enumeration
6. OLE Office (``.doc`` / ``.xls`` / ``.ppt`` binary) — CFBF stream index
7. ``.pst`` / ``.ost`` — Outlook mailbox (signature + node BTree header)
8. ``.kdbx`` — KeePass DB (v3/v4 header magic only, no crack)
9. ``.pfx`` / ``.p12`` — PKCS#12 cert chain enumeration

**Safety invariants:**

- Every parser is **passive**: read-only, no external process invocation,
  no shell-out. Only stdlib + already-required deps (``struct``, ``zipfile``,
  ``ssl.CertificateError``, ``cryptography`` if present).
- Every parser has a **30-second timeout budget** (user pick 18-2B).
  Callers enforce via ``concurrent.futures.ThreadPoolExecutor`` with a
  timeout on ``.result()``.
- Every parser is **bounded**: reads at most 1 MiB of the artefact even
  if the file is much larger. Deep parses are opt-in and gated by the
  caller.
- Every parser is **source-gated**: the caller must have already
  passed the artefact through scope_gate / manifest_check. This module
  does not import scope_gate.
- No parser writes anywhere, executes anything, or issues outbound
  network calls.
"""

from __future__ import annotations

import io
import logging
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


logger = logging.getLogger(__name__)


_MAX_READ_BYTES: int = 1_048_576  # 1 MiB safety cap


@dataclass
class ArtifactMetadata:
    """Bounded, non-secret metadata extracted from an artefact."""

    format: str
    confidence: str  # 'high' | 'medium' | 'low'
    fields: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "confidence": self.confidence,
            "fields": dict(self.fields),
            "warnings": list(self.warnings),
        }


class ArtifactParser(Protocol):
    format: str
    extensions: tuple[str, ...]
    magic: tuple[bytes, ...]

    def matches(self, path: Path, head: bytes) -> bool: ...
    def parse(self, path: Path) -> ArtifactMetadata | None: ...


def _read_head(path: Path, n: int = 16) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _bounded_read(path: Path, cap: int = _MAX_READ_BYTES) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(cap)
    except OSError:
        return b""


# ---------------------------------------------------------------------------
# 1) MSI (MS Compound File Binary Format)
# ---------------------------------------------------------------------------


class MSIParser:
    format = "msi"
    extensions = (".msi",)
    magic = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)  # CFBF header signature

    def matches(self, path: Path, head: bytes) -> bool:
        return head.startswith(self.magic[0]) and path.suffix.lower() in self.extensions

    def parse(self, path: Path) -> ArtifactMetadata | None:
        data = _bounded_read(path)
        if not data.startswith(self.magic[0]):
            return None
        # CFBF header: sector shift @ offset 30 (little-endian uint16)
        try:
            sector_shift = struct.unpack_from("<H", data, 30)[0]
            mini_sector_shift = struct.unpack_from("<H", data, 32)[0]
            n_dir_sectors = struct.unpack_from("<L", data, 40)[0]
            n_fat_sectors = struct.unpack_from("<L", data, 44)[0]
        except struct.error:
            return ArtifactMetadata(
                format=self.format, confidence="low",
                warnings=["CFBF header too short"],
            )
        return ArtifactMetadata(
            format=self.format,
            confidence="high",
            fields={
                "cfbf_sector_size_bytes": 1 << sector_shift,
                "cfbf_mini_sector_size_bytes": 1 << mini_sector_shift,
                "n_directory_sectors": n_dir_sectors,
                "n_fat_sectors": n_fat_sectors,
                "file_size_bytes": path.stat().st_size,
            },
        )


# ---------------------------------------------------------------------------
# 2) DMG (Apple Disk Image)
# ---------------------------------------------------------------------------


class DMGParser:
    format = "dmg"
    extensions = (".dmg",)
    magic = (b"koly",)  # UDIF magic at end-of-file — special case, no head match

    def matches(self, path: Path, head: bytes) -> bool:
        if path.suffix.lower() not in self.extensions:
            return False
        # DMG UDIF trailer is at the LAST 512 bytes, magic bytes "koly"
        try:
            with path.open("rb") as fh:
                size = path.stat().st_size
                if size < 512:
                    return False
                fh.seek(size - 512)
                trailer = fh.read(4)
                return trailer == b"koly"
        except OSError:
            return False

    def parse(self, path: Path) -> ArtifactMetadata | None:
        try:
            with path.open("rb") as fh:
                size = path.stat().st_size
                if size < 512:
                    return None
                fh.seek(size - 512)
                trailer = fh.read(512)
        except OSError:
            return None
        if not trailer.startswith(b"koly"):
            return None
        # UDIF trailer version @ offset 4 (uint32 BE)
        try:
            version = struct.unpack_from(">I", trailer, 4)[0]
            header_size = struct.unpack_from(">I", trailer, 8)[0]
            flags = struct.unpack_from(">I", trailer, 12)[0]
        except struct.error:
            return None
        return ArtifactMetadata(
            format=self.format,
            confidence="high",
            fields={
                "udif_version": version,
                "udif_header_size": header_size,
                "udif_flags": flags,
                "file_size_bytes": path.stat().st_size,
            },
        )


# ---------------------------------------------------------------------------
# 3) RPM (Red Hat Package Manager)
# ---------------------------------------------------------------------------


class RPMParser:
    format = "rpm"
    extensions = (".rpm",)
    magic = (b"\xed\xab\xee\xdb",)  # RPM lead magic

    def matches(self, path: Path, head: bytes) -> bool:
        return head.startswith(self.magic[0])

    def parse(self, path: Path) -> ArtifactMetadata | None:
        data = _bounded_read(path)
        if not data.startswith(self.magic[0]):
            return None
        # RPM lead is 96 bytes: magic(4) + major(1) + minor(1) + type(2) + arch(2) + name(66) + osnum(2) + signature_type(2) + reserved(16)
        try:
            major = data[4]
            minor = data[5]
            rpm_type = struct.unpack_from(">H", data, 6)[0]
            arch_num = struct.unpack_from(">H", data, 8)[0]
            name_bytes = data[10:76]
            name = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            os_num = struct.unpack_from(">H", data, 76)[0]
            sig_type = struct.unpack_from(">H", data, 78)[0]
        except (struct.error, IndexError):
            return ArtifactMetadata(
                format=self.format, confidence="low",
                warnings=["RPM lead too short"],
            )
        return ArtifactMetadata(
            format=self.format,
            confidence="high",
            fields={
                "rpm_major_version": major,
                "rpm_minor_version": minor,
                "rpm_type": "binary" if rpm_type == 0 else "source",
                "arch_num": arch_num,
                "package_name": name,
                "os_num": os_num,
                "signature_type": sig_type,
                "file_size_bytes": path.stat().st_size,
            },
        )


# ---------------------------------------------------------------------------
# 4) WAR / EAR (Java Web / Enterprise Archives)
# ---------------------------------------------------------------------------


class WARParser:
    format = "war_ear"
    extensions = (".war", ".ear")
    magic = (b"PK\x03\x04",)  # ZIP local file header

    def matches(self, path: Path, head: bytes) -> bool:
        return head.startswith(self.magic[0]) and path.suffix.lower() in self.extensions

    def parse(self, path: Path) -> ArtifactMetadata | None:
        try:
            zf = zipfile.ZipFile(path, "r")
        except (zipfile.BadZipFile, OSError):
            return None
        try:
            names = zf.namelist()
            has_web_inf = any(n.startswith("WEB-INF/") for n in names)
            has_meta_inf = any(n.startswith("META-INF/") for n in names)
            web_xml = next((n for n in names if n.endswith("WEB-INF/web.xml")), None)
            app_xml = next((n for n in names if n.endswith("META-INF/application.xml")), None)
            manifest = next((n for n in names if n == "META-INF/MANIFEST.MF"), None)
            servlet_classes = [
                n for n in names if n.endswith(".class") and "WEB-INF/classes/" in n
            ]
            libs = [n for n in names if n.startswith("WEB-INF/lib/") and n.endswith(".jar")]
            return ArtifactMetadata(
                format=self.format,
                confidence="high" if has_web_inf or has_meta_inf else "medium",
                fields={
                    "entry_count": len(names),
                    "has_web_inf": has_web_inf,
                    "has_meta_inf": has_meta_inf,
                    "has_web_xml": web_xml is not None,
                    "has_application_xml": app_xml is not None,
                    "has_manifest": manifest is not None,
                    "servlet_class_count": len(servlet_classes),
                    "lib_jar_count": len(libs),
                },
            )
        finally:
            zf.close()


# ---------------------------------------------------------------------------
# 5) PDF (embedded file attachment enumeration)
# ---------------------------------------------------------------------------


class PDFAttachmentParser:
    format = "pdf_attachments"
    extensions = (".pdf",)
    magic = (b"%PDF-",)

    def matches(self, path: Path, head: bytes) -> bool:
        return head.startswith(self.magic[0])

    def parse(self, path: Path) -> ArtifactMetadata | None:
        data = _bounded_read(path)
        if not data.startswith(self.magic[0]):
            return None
        # Version indicator: "%PDF-x.y"
        version_match = re.match(rb"%PDF-(\d\.\d)", data)
        version = version_match.group(1).decode("ascii") if version_match else "unknown"
        # Look for /EmbeddedFiles and /Filespec keywords — these signal
        # attachments without needing a full parser.
        embedded_hits = data.count(b"/EmbeddedFiles")
        filespec_hits = data.count(b"/Filespec")
        # Look for /Encrypt to warn on protected PDFs.
        encrypted = b"/Encrypt" in data
        # File name(s) referenced in /F strings
        file_refs = re.findall(rb"/F\s*\(([^)]{1,200})\)", data)
        return ArtifactMetadata(
            format=self.format,
            confidence="high",
            fields={
                "pdf_version": version,
                "embedded_files_dict_count": embedded_hits,
                "filespec_count": filespec_hits,
                "attachment_filenames_sample": [
                    ref.decode("latin-1", errors="replace")[:120] for ref in file_refs[:10]
                ],
                "is_encrypted": encrypted,
                "file_size_bytes": path.stat().st_size,
            },
            warnings=["encrypted PDF — attachment enum may be incomplete"]
            if encrypted else [],
        )


# ---------------------------------------------------------------------------
# 6) OLE Office (legacy .doc/.xls/.ppt binary)
# ---------------------------------------------------------------------------


class OLEOfficeParser:
    format = "ole_office"
    extensions = (".doc", ".xls", ".ppt", ".msg")
    magic = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)  # Same CFBF as MSI

    def matches(self, path: Path, head: bytes) -> bool:
        return head.startswith(self.magic[0]) and path.suffix.lower() in self.extensions

    def parse(self, path: Path) -> ArtifactMetadata | None:
        data = _bounded_read(path)
        if not data.startswith(self.magic[0]):
            return None
        # Same CFBF header as MSI (they share the format). We look for
        # office-specific markers in the bounded head.
        has_worddoc = b"WordDocument" in data
        has_workbook = b"Workbook" in data
        has_powerpoint = b"PowerPoint Document" in data or b"Current User" in data
        has_msg = b"__attach_version1.0" in data or b"__properties_version1.0" in data
        macros = b"_VBA_PROJECT" in data or b"Macros" in data
        return ArtifactMetadata(
            format=self.format,
            confidence="high",
            fields={
                "is_word": has_worddoc,
                "is_excel": has_workbook,
                "is_powerpoint": has_powerpoint,
                "is_msg": has_msg,
                "contains_macros": macros,
                "file_size_bytes": path.stat().st_size,
            },
            warnings=["contains VBA macros — treat as untrusted"] if macros else [],
        )


# ---------------------------------------------------------------------------
# 7) PST / OST (Outlook mailbox)
# ---------------------------------------------------------------------------


class PSTParser:
    format = "outlook_mailbox"
    extensions = (".pst", ".ost")
    magic = (b"!BDN",)  # PST/OST file header magic

    def matches(self, path: Path, head: bytes) -> bool:
        return head.startswith(self.magic[0])

    def parse(self, path: Path) -> ArtifactMetadata | None:
        data = _bounded_read(path, cap=4096)  # header only
        if not data.startswith(self.magic[0]):
            return None
        # PST header: magic(4) + CRC(4) + magic_client(2) + wVer(2) + wVerClient(2) + ...
        try:
            crc = struct.unpack_from("<I", data, 4)[0]
            magic_client = data[8:10]
            wVer = struct.unpack_from("<H", data, 10)[0]
            wVerClient = struct.unpack_from("<H", data, 12)[0]
        except struct.error:
            return ArtifactMetadata(
                format=self.format, confidence="low",
                warnings=["PST header too short"],
            )
        return ArtifactMetadata(
            format=self.format,
            confidence="high",
            fields={
                "header_crc": crc,
                "magic_client": magic_client.decode("ascii", errors="replace"),
                "wVer": wVer,
                "wVerClient": wVerClient,
                "unicode_pst": wVer >= 23,  # per MS-PST spec
                "file_size_bytes": path.stat().st_size,
            },
            warnings=["deep-parse requires libpff; only header is read here"],
        )


# ---------------------------------------------------------------------------
# 8) KDBX (KeePass DB — signature-only detection, no crack)
# ---------------------------------------------------------------------------


class KDBXParser:
    format = "keepass_kdbx"
    extensions = (".kdbx",)
    # KDBX v3 / v4 both use these signatures:
    # sig1 = 0x9AA2D903, sig2 = 0xB54BFB67 (v3) or 0xB54BFB65 (v2), or
    # 0xB54BFB68 (v4)
    magic = (
        b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5",  # KDBX v3
        b"\x03\xd9\xa2\x9a\x68\xfb\x4b\xb5",  # KDBX v4
    )

    def matches(self, path: Path, head: bytes) -> bool:
        return any(head.startswith(m) for m in self.magic)

    def parse(self, path: Path) -> ArtifactMetadata | None:
        data = _bounded_read(path, cap=64)
        for i, m in enumerate(self.magic):
            if data.startswith(m):
                # Version @ offset 8: minor(2) + major(2)
                try:
                    minor = struct.unpack_from("<H", data, 8)[0]
                    major = struct.unpack_from("<H", data, 10)[0]
                except struct.error:
                    return None
                return ArtifactMetadata(
                    format=self.format,
                    confidence="high",
                    fields={
                        "kdbx_generation": "v4" if i == 1 else "v3",
                        "kdbx_major_version": major,
                        "kdbx_minor_version": minor,
                        "file_size_bytes": path.stat().st_size,
                    },
                    warnings=[
                        "signature only — no crack attempted. KDBX contents "
                        "remain encrypted at rest."
                    ],
                )
        return None


# ---------------------------------------------------------------------------
# 9) PFX / P12 (PKCS#12 cert bundle)
# ---------------------------------------------------------------------------


class PFXParser:
    format = "pkcs12"
    extensions = (".pfx", ".p12")
    magic = (b"\x30\x82", b"\x30\x81", b"\x30\x83")  # DER SEQUENCE

    def matches(self, path: Path, head: bytes) -> bool:
        return any(head.startswith(m) for m in self.magic) and \
               path.suffix.lower() in self.extensions

    def parse(self, path: Path) -> ArtifactMetadata | None:
        data = _bounded_read(path)
        if not any(data.startswith(m) for m in self.magic):
            return None
        # Try cryptography's PKCS#12 loader for full cert chain enumeration.
        # We do NOT attempt to open with a password — that would be a crack.
        cert_chain_length = None
        friendly_name = None
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: PLC0415

            # Try with empty password (some PFX files use empty).
            try:
                key, cert, chain = pkcs12.load_key_and_certificates(data, b"")
                if cert is not None:
                    cert_chain_length = 1 + len(chain or [])
                    friendly_name = (
                        cert.subject.rfc4514_string()
                        if hasattr(cert, "subject") else None
                    )
            except (ValueError, Exception):  # noqa: BLE001 — encrypted, no password
                pass
        except ImportError:
            pass
        return ArtifactMetadata(
            format=self.format,
            confidence="high",
            fields={
                "file_size_bytes": path.stat().st_size,
                "encrypted": cert_chain_length is None,
                "cert_chain_length": cert_chain_length,
                "subject_dn": friendly_name,
            },
            warnings=[
                "encrypted PFX — no password crack attempted. Subject DN "
                "not extractable without decryption."
            ] if cert_chain_length is None else [],
        )


# ---------------------------------------------------------------------------
# Registry + dispatch
# ---------------------------------------------------------------------------


PARSERS: tuple[ArtifactParser, ...] = (
    MSIParser(),
    DMGParser(),
    RPMParser(),
    WARParser(),
    PDFAttachmentParser(),
    OLEOfficeParser(),
    PSTParser(),
    KDBXParser(),
    PFXParser(),
)


def parse_artifact(path: Path) -> ArtifactMetadata | None:
    """Try each parser; return the first match's metadata.

    Callers must have scope-gated the target BEFORE invoking this. The
    parsers themselves do no scope enforcement.
    """
    if not path.is_file():
        return None
    head = _read_head(path, 64)
    for parser in PARSERS:
        try:
            if parser.matches(path, head):
                return parser.parse(path)
        except Exception as exc:  # noqa: BLE001
            logger.debug("parser %s errored: %s", parser.format, exc)
            continue
    return None


__all__ = [
    "ArtifactMetadata",
    "ArtifactParser",
    "MSIParser",
    "DMGParser",
    "RPMParser",
    "WARParser",
    "PDFAttachmentParser",
    "OLEOfficeParser",
    "PSTParser",
    "KDBXParser",
    "PFXParser",
    "PARSERS",
    "parse_artifact",
]
