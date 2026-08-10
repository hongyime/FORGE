"""Tests for the 9 artifact parsers (task 18)."""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from forge.phase4.artifact_parsers import (
    ArtifactMetadata,
    DMGParser,
    KDBXParser,
    MSIParser,
    OLEOfficeParser,
    PARSERS,
    PDFAttachmentParser,
    PFXParser,
    PSTParser,
    RPMParser,
    WARParser,
    parse_artifact,
)


class TestMSIParser:
    def test_matches_cfbf_header_with_msi_ext(self, tmp_path: Path) -> None:
        f = tmp_path / "installer.msi"
        # CFBF header: magic(8) + clsid(16) + minor_version(2) + major_version(2)
        # + byte_order(2) + sector_shift(2) + mini_sector_shift(2) + ...
        header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16
        header += struct.pack("<HH", 0x003E, 0x0003)  # minor + major
        header += struct.pack("<H", 0xFFFE)  # byte_order
        header += struct.pack("<H", 9)  # sector_shift (2^9 = 512)
        header += struct.pack("<H", 6)  # mini_sector_shift (2^6 = 64)
        header += b"\x00" * 6  # reserved
        header += struct.pack("<L", 1)  # n_dir_sectors
        header += struct.pack("<L", 2)  # n_fat_sectors
        header += b"\x00" * 512
        f.write_bytes(header)

        meta = MSIParser().parse(f)
        assert meta is not None
        assert meta.format == "msi"
        assert meta.fields["cfbf_sector_size_bytes"] == 512
        assert meta.fields["cfbf_mini_sector_size_bytes"] == 64
        assert meta.fields["n_directory_sectors"] == 1
        assert meta.fields["n_fat_sectors"] == 2


class TestDMGParser:
    def test_detects_koly_trailer(self, tmp_path: Path) -> None:
        f = tmp_path / "image.dmg"
        # Pad with 0s + koly trailer at last 512 bytes
        # UDIF trailer: magic(4) + version(4) + header_size(4) + flags(4) + ...
        padding = b"\x00" * 1024
        trailer = b"koly"
        trailer += struct.pack(">I", 4)  # version 4
        trailer += struct.pack(">I", 512)  # header size
        trailer += struct.pack(">I", 0)  # flags
        trailer += b"\x00" * (512 - 16)
        f.write_bytes(padding + trailer)
        parser = DMGParser()
        assert parser.matches(f, b"")  # DMG doesn't need head match
        meta = parser.parse(f)
        assert meta is not None
        assert meta.fields["udif_version"] == 4
        assert meta.fields["udif_header_size"] == 512


class TestRPMParser:
    def test_matches_rpm_lead(self, tmp_path: Path) -> None:
        f = tmp_path / "pkg.rpm"
        # RPM lead: magic(4) + major(1) + minor(1) + type(2) + arch(2) + name(66) + osnum(2) + sig(2) + reserved(16)
        header = b"\xed\xab\xee\xdb"
        header += bytes([3, 0])  # major=3, minor=0
        header += struct.pack(">H", 0)  # type=binary
        header += struct.pack(">H", 1)  # arch=i386
        name_padded = b"acme-pkg-1.0.0-1.x86_64" + b"\x00" * (66 - 23)
        header += name_padded
        header += struct.pack(">H", 1)  # os_num
        header += struct.pack(">H", 5)  # sig_type
        header += b"\x00" * 16  # reserved
        f.write_bytes(header)

        meta = RPMParser().parse(f)
        assert meta is not None
        assert meta.fields["rpm_major_version"] == 3
        assert meta.fields["rpm_type"] == "binary"
        assert meta.fields["package_name"] == "acme-pkg-1.0.0-1.x86_64"


class TestWARParser:
    def test_detects_web_inf(self, tmp_path: Path) -> None:
        f = tmp_path / "app.war"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("WEB-INF/web.xml", "<web-app/>")
            zf.writestr("WEB-INF/classes/Foo.class", b"\xca\xfe\xba\xbe")
            zf.writestr("WEB-INF/lib/dep.jar", b"PK\x03\x04dummy")
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0")
        f.write_bytes(buf.getvalue())
        meta = WARParser().parse(f)
        assert meta is not None
        assert meta.fields["has_web_inf"] is True
        assert meta.fields["has_meta_inf"] is True
        assert meta.fields["servlet_class_count"] == 1
        assert meta.fields["lib_jar_count"] == 1
        assert meta.fields["has_manifest"] is True


class TestPDFAttachmentParser:
    def test_detects_embedded_files(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.pdf"
        content = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 2 0 R >> >>\n"
            b"2 0 obj\n<< /Names [(secret.zip) 3 0 R] >>\n"
            b"3 0 obj\n<< /F (secret.zip) /Type /Filespec /EF << /F 4 0 R >> >>\n"
            b"4 0 obj\n<< /Type /EmbeddedFile /Length 10 >>\nstream\nRAWBYTES!!\nendstream\nendobj\n"
        )
        f.write_bytes(content)
        meta = PDFAttachmentParser().parse(f)
        assert meta is not None
        assert meta.fields["embedded_files_dict_count"] >= 1
        assert meta.fields["filespec_count"] >= 1
        assert meta.fields["pdf_version"] == "1.7"
        assert "secret.zip" in " ".join(meta.fields["attachment_filenames_sample"])

    def test_detects_encrypted_pdf(self, tmp_path: Path) -> None:
        f = tmp_path / "enc.pdf"
        f.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Encrypt 5 0 R >>\n")
        meta = PDFAttachmentParser().parse(f)
        assert meta is not None
        assert meta.fields["is_encrypted"] is True
        assert any("encrypted" in w for w in meta.warnings)


class TestOLEOfficeParser:
    def test_detects_word_doc_with_macros(self, tmp_path: Path) -> None:
        f = tmp_path / "old.doc"
        # CFBF header + markers
        head = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100
        head += b"WordDocument"
        head += b"\x00" * 100
        head += b"_VBA_PROJECT"
        head += b"\x00" * 100
        f.write_bytes(head)
        meta = OLEOfficeParser().parse(f)
        assert meta is not None
        assert meta.fields["is_word"] is True
        assert meta.fields["contains_macros"] is True


class TestPSTParser:
    def test_detects_pst_header(self, tmp_path: Path) -> None:
        f = tmp_path / "mailbox.pst"
        # !BDN + CRC(4) + magic_client(2) + wVer(2) + wVerClient(2)
        header = b"!BDN"
        header += struct.pack("<I", 0xDEADBEEF)  # CRC
        header += b"SM"  # magic_client
        header += struct.pack("<H", 23)  # wVer (unicode PST)
        header += struct.pack("<H", 19)  # wVerClient
        header += b"\x00" * 100
        f.write_bytes(header)
        meta = PSTParser().parse(f)
        assert meta is not None
        assert meta.fields["wVer"] == 23
        assert meta.fields["unicode_pst"] is True
        assert meta.fields["magic_client"] == "SM"


class TestKDBXParser:
    def test_detects_kdbx_v4(self, tmp_path: Path) -> None:
        f = tmp_path / "vault.kdbx"
        header = b"\x03\xd9\xa2\x9a\x68\xfb\x4b\xb5"  # v4 magic
        header += struct.pack("<HH", 1, 4)  # minor=1, major=4
        header += b"\x00" * 32
        f.write_bytes(header)
        meta = KDBXParser().parse(f)
        assert meta is not None
        assert meta.fields["kdbx_generation"] == "v4"
        assert meta.fields["kdbx_major_version"] == 4

    def test_detects_kdbx_v3(self, tmp_path: Path) -> None:
        f = tmp_path / "old.kdbx"
        header = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5"  # v3 magic
        header += struct.pack("<HH", 1, 3)  # minor=1, major=3
        header += b"\x00" * 32
        f.write_bytes(header)
        meta = KDBXParser().parse(f)
        assert meta is not None
        assert meta.fields["kdbx_generation"] == "v3"


class TestPFXParser:
    def test_detects_pkcs12_der(self, tmp_path: Path) -> None:
        f = tmp_path / "cert.pfx"
        # DER SEQUENCE at start; contents dummy so cryptography load fails
        header = b"\x30\x82\x04\x00" + b"\x00" * 100
        f.write_bytes(header)
        meta = PFXParser().parse(f)
        assert meta is not None
        # Encrypted path (empty-password crack fails) — cert_chain_length None
        assert meta.fields["encrypted"] is True


class TestDispatch:
    def test_parse_artifact_returns_none_for_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "random.bin"
        f.write_bytes(b"random bytes here")
        assert parse_artifact(f) is None

    def test_parse_artifact_dispatches_to_first_match(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.pdf"
        f.write_bytes(b"%PDF-1.5\n1 0 obj\n<< >>\n")
        result = parse_artifact(f)
        assert result is not None
        assert result.format == "pdf_attachments"

    def test_registry_has_9_parsers(self) -> None:
        assert len(PARSERS) == 9
        formats = {p.format for p in PARSERS}
        assert formats == {
            "msi",
            "dmg",
            "rpm",
            "war_ear",
            "pdf_attachments",
            "ole_office",
            "outlook_mailbox",
            "keepass_kdbx",
            "pkcs12",
        }

    def test_metadata_is_json_serialisable(self, tmp_path: Path) -> None:
        import json

        f = tmp_path / "doc.pdf"
        f.write_bytes(b"%PDF-1.5\n")
        meta = parse_artifact(f)
        assert meta is not None
        json.dumps(meta.as_dict())  # must round-trip
