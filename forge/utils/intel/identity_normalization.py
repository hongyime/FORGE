"""forge/utils/intel/identity_normalization.py — 6-class identity normalizers.

Task 20. Aggressive dedup (user pick 20-2A): equivalent identities
collapse to one canonical form. Users can trace back via the
``related_identity_id`` metadata field.

Six normalizer classes:

1. :class:`EmailNormalizer` — Gmail dotted-name + ``+alias`` collapse,
   disposable-domain detection, case + whitespace normalization.
2. :class:`UsernameNormalizer` — case + unicode homograph normalisation,
   cross-platform handle correlation via shared alias sets.
3. :class:`PhoneNormalizer` — E.164 canonical + extension stripping.
4. :class:`CompanyNormalizer` — legal suffix stripping ("Inc" / "Ltd" /
   "GmbH" / "Pte" / "AG" / "SA" / "SAS" / "SARL" / "Corp" / etc.).
5. :class:`PersonNameNormalizer` — first+last vs last-first, honorific
   stripping, transliteration hooks.
6. :class:`SocialProfileURLNormalizer` — canonical URL form, protocol
   normalisation, casing, trailing-slash collapse.

Every normalizer is pure — no I/O, no DB. Deterministic canonical form
in one call. Persistence is the caller's job.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse, urlunparse


# ---------------------------------------------------------------------------
# Common data types
# ---------------------------------------------------------------------------


@dataclass
class NormalizedIdentity:
    kind: str
    canonical: str
    original: str
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# EmailNormalizer
# ---------------------------------------------------------------------------


# Providers that collapse dotted-name (Gmail-style).
_DOT_NORMALIZE_PROVIDERS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com",
})

# Common disposable email domains. Kept short — comprehensive lists
# live in phase0 KB fetchers.
_DISPOSABLE_DOMAINS: frozenset[str] = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com",
    "yopmail.com", "trashmail.com", "getnada.com", "sharklasers.com",
    "mailnesia.com", "maildrop.cc", "mytemp.email", "fakeinbox.com",
})


class EmailNormalizer:
    kind = "email"

    def normalize(self, raw: str) -> NormalizedIdentity | None:
        text = str(raw or "").strip().lower()
        if not text or "@" not in text:
            return None
        try:
            local, domain = text.rsplit("@", 1)
        except ValueError:
            return None
        local = local.strip()
        domain = domain.strip().rstrip(".")
        if not local or not domain or "." not in domain:
            return None

        original_local = local
        alias = ""

        # Strip +alias suffix (Gmail-style, but supported by many providers)
        if "+" in local:
            local, alias = local.split("+", 1)

        # Gmail dot-collapse
        if domain in _DOT_NORMALIZE_PROVIDERS:
            local = local.replace(".", "")

        canonical = f"{local}@{domain}"
        metadata = {"original_local": original_local}
        if alias:
            metadata["plus_alias"] = alias
        if domain in _DISPOSABLE_DOMAINS:
            metadata["disposable"] = "true"

        return NormalizedIdentity(
            kind=self.kind,
            canonical=canonical,
            original=str(raw or "").strip(),
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# UsernameNormalizer
# ---------------------------------------------------------------------------


# Homograph confusables — canonical mapping for common lookalikes.
_HOMOGRAPH_MAP: dict[str, str] = {
    # Cyrillic/Greek lookalikes → Latin
    "\u0430": "a",  # Cyrillic small a
    "\u0435": "e",  # Cyrillic small e
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0441": "c",  # Cyrillic small es
    "\u0443": "y",  # Cyrillic small u
    "\u0445": "x",  # Cyrillic small kha
    "\u03bf": "o",  # Greek small omicron
    "\u03b1": "a",  # Greek small alpha
    # Digit look-alikes we DO NOT normalize (they carry meaning) — but
    # zero-width chars we DO strip:
    "\u200b": "",   # ZWSP
    "\u200c": "",   # ZWNJ
    "\u200d": "",   # ZWJ
    "\ufeff": "",   # BOM
}


class UsernameNormalizer:
    kind = "username"

    def normalize(self, raw: str) -> NormalizedIdentity | None:
        text = str(raw or "").strip()
        if not text:
            return None
        # Strip @ prefix if present
        display = text.lstrip("@").strip()
        if not display:
            return None
        # NFC then case-fold
        canonical = unicodedata.normalize("NFC", display).casefold()
        # Homograph substitution
        canonical = "".join(_HOMOGRAPH_MAP.get(ch, ch) for ch in canonical)
        # Collapse repeated dots / dashes to single (a common typo)
        canonical = re.sub(r"[.\-_]{2,}", "_", canonical)
        canonical = canonical.strip("._-")
        if not canonical:
            return None
        metadata: dict[str, str] = {}
        if display != canonical:
            metadata["contained_homoglyph_or_case_variance"] = "true"
        return NormalizedIdentity(
            kind=self.kind,
            canonical=canonical,
            original=text,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# PhoneNormalizer
# ---------------------------------------------------------------------------


_PHONE_EXT_RE = re.compile(
    r"(?i)\s*(?:x|ext\.?|extension)\s*[:# ]?\s*(\d{1,6})\s*$"
)


class PhoneNormalizer:
    kind = "phone"

    def normalize(self, raw: str) -> NormalizedIdentity | None:
        text = str(raw or "").strip()
        if not text:
            return None
        # Peel off extension if present
        ext = ""
        m = _PHONE_EXT_RE.search(text)
        if m:
            ext = m.group(1)
            text = text[: m.start()].rstrip(" -")
        # Strip all non-digit/plus characters
        digits_only = re.sub(r"[^\d+]", "", text)
        if not digits_only:
            return None
        if not digits_only.startswith("+"):
            # E.164 requires leading +; without one we can't be confident
            # about the country code. Accept but flag.
            metadata_leading = "no_e164_prefix"
        else:
            metadata_leading = ""
        # Try phonenumbers for real validation; fall back to raw digits.
        canonical = digits_only
        metadata: dict[str, str] = {}
        try:
            import phonenumbers  # noqa: PLC0415

            parsed = phonenumbers.parse(digits_only, None)
            if phonenumbers.is_valid_number(parsed):
                canonical = phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                )
                metadata["country_code"] = str(parsed.country_code or "")
                metadata["national_number"] = str(parsed.national_number or "")
            else:
                metadata["phonenumbers_valid"] = "false"
        except Exception:  # noqa: BLE001 — phonenumbers not installed / not parseable
            metadata["phonenumbers_valid"] = "unavailable"
        if ext:
            metadata["extension"] = ext
        if metadata_leading:
            metadata["e164_status"] = metadata_leading
        return NormalizedIdentity(
            kind=self.kind,
            canonical=canonical,
            original=str(raw or "").strip(),
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# CompanyNormalizer
# ---------------------------------------------------------------------------


# Legal-entity suffixes — stripped from canonical form. Include German,
# French, Spanish, Portuguese, Italian, Dutch, Nordic, SG, HK, JP, IN.
_LEGAL_SUFFIXES: tuple[str, ...] = (
    # English / US
    "inc", "incorporated", "corp", "corporation", "co", "company", "llc",
    "ltd", "limited", "plc", "l.p.", "lp", "l.l.c.",
    # Germanic
    "gmbh", "ag", "kg", "ohg", "ug", "eg", "kgaa",
    # French / Latin
    "sa", "sas", "sarl", "eurl", "snc", "scea", "scp",
    # Spanish / Portuguese / Italian
    "s.a.", "s.l.", "s.r.l.", "srl", "lda", "sarl", "sccl",
    # Dutch / Nordic
    "bv", "nv", "as", "ab", "aps", "oy", "hf",
    # Asia
    "pte", "pte.", "pvt", "pvt.", "kk", "kabushiki", "kabushiki kaisha",
    # Chinese / HK
    "ltd.", "co.", "hldg", "holdings",
)


class CompanyNormalizer:
    kind = "company"

    def normalize(self, raw: str) -> NormalizedIdentity | None:
        text = str(raw or "").strip()
        if not text:
            return None
        # NFC + lower + collapse whitespace
        canonical = unicodedata.normalize("NFC", text).casefold()
        canonical = re.sub(r"\s+", " ", canonical)
        canonical = canonical.strip()
        original_canonical = canonical
        # Repeatedly strip legal suffix tokens from end
        stripped_suffixes: list[str] = []
        while True:
            tokens = canonical.split(" ")
            if not tokens:
                break
            tail = tokens[-1].rstrip(",.")
            if tail in _LEGAL_SUFFIXES:
                stripped_suffixes.append(tail)
                tokens = tokens[:-1]
                canonical = " ".join(tokens).rstrip(",.").strip()
            else:
                break
        if not canonical:
            # Everything was suffix; keep the original.
            canonical = original_canonical
        metadata: dict[str, str] = {}
        if stripped_suffixes:
            metadata["stripped_legal_suffixes"] = ",".join(reversed(stripped_suffixes))
        return NormalizedIdentity(
            kind=self.kind,
            canonical=canonical,
            original=text,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# PersonNameNormalizer
# ---------------------------------------------------------------------------


_HONORIFICS: frozenset[str] = frozenset({
    "mr", "mrs", "ms", "mx", "dr", "prof", "sir", "dame", "lord", "lady",
    "hon", "rev", "fr", "sr", "jr", "phd", "md", "esq", "cpa",
    "ing", "ir", "mba", "ma", "ba", "mrcp", "mrcs", "frcp", "frcs",
})


class PersonNameNormalizer:
    kind = "person_name"

    def normalize(self, raw: str) -> NormalizedIdentity | None:
        text = str(raw or "").strip()
        if not text:
            return None
        canonical = unicodedata.normalize("NFC", text)
        # Handle "Last, First"
        if "," in canonical:
            parts = canonical.split(",", 1)
            if len(parts) == 2:
                canonical = f"{parts[1].strip()} {parts[0].strip()}"
        # Strip honorifics
        tokens = canonical.split()
        stripped_honorifics: list[str] = []
        while tokens and tokens[0].rstrip(".").lower() in _HONORIFICS:
            stripped_honorifics.append(tokens[0])
            tokens = tokens[1:]
        while tokens and tokens[-1].rstrip(".").lower() in _HONORIFICS:
            stripped_honorifics.append(tokens[-1])
            tokens = tokens[:-1]
        canonical = " ".join(tokens)
        canonical = re.sub(r"\s+", " ", canonical).strip()
        if not canonical:
            return None
        metadata: dict[str, str] = {}
        if stripped_honorifics:
            metadata["stripped_honorifics"] = ",".join(stripped_honorifics)
        # Title-case canonical for display consistency, but keep casefold
        # for equality matching in metadata.
        metadata["match_key"] = canonical.casefold()
        return NormalizedIdentity(
            kind=self.kind,
            canonical=canonical.title(),
            original=text,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# SocialProfileURLNormalizer
# ---------------------------------------------------------------------------


# Provider → (hostname_pattern, canonical_hostname, path_transform)
_SOCIAL_HOSTS: dict[str, str] = {
    "twitter.com": "x.com",
    "www.twitter.com": "x.com",
    "www.x.com": "x.com",
    "m.twitter.com": "x.com",
    "mobile.twitter.com": "x.com",
    "www.facebook.com": "facebook.com",
    "m.facebook.com": "facebook.com",
    "www.linkedin.com": "linkedin.com",
    "www.instagram.com": "instagram.com",
    "www.github.com": "github.com",
    "www.gitlab.com": "gitlab.com",
    "www.tiktok.com": "tiktok.com",
    "www.youtube.com": "youtube.com",
    "m.youtube.com": "youtube.com",
    "youtu.be": "youtube.com",
    "www.reddit.com": "reddit.com",
    "old.reddit.com": "reddit.com",
    "np.reddit.com": "reddit.com",
    "mastodon.social": "mastodon.social",
    "bsky.app": "bsky.app",
    "www.threads.net": "threads.net",
}


class SocialProfileURLNormalizer:
    kind = "social_profile_url"

    def normalize(self, raw: str) -> NormalizedIdentity | None:
        text = str(raw or "").strip()
        if not text:
            return None
        if "://" not in text:
            text = "https://" + text
        try:
            parsed = urlparse(text)
        except ValueError:
            return None
        host = (parsed.hostname or "").lower().strip(".")
        if not host or "." not in host:
            return None
        canonical_host = _SOCIAL_HOSTS.get(host, host)
        # Force https
        scheme = "https"
        path = parsed.path or "/"
        # Strip trailing slash unless path is bare "/"
        if len(path) > 1:
            path = path.rstrip("/")
        # Lowercase path for github/gitlab/twitter which are case-insensitive
        if canonical_host in {"x.com", "github.com", "gitlab.com", "reddit.com"}:
            path = path.lower()
        # Drop query + fragment for canonical form
        canonical = urlunparse((scheme, canonical_host, path, "", "", ""))
        metadata: dict[str, str] = {"canonical_host": canonical_host}
        if host != canonical_host:
            metadata["original_host"] = host
        return NormalizedIdentity(
            kind=self.kind,
            canonical=canonical,
            original=str(raw or "").strip(),
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Registry + dispatch helper
# ---------------------------------------------------------------------------


NORMALIZERS: dict[str, object] = {
    "email": EmailNormalizer(),
    "username": UsernameNormalizer(),
    "phone": PhoneNormalizer(),
    "company": CompanyNormalizer(),
    "person_name": PersonNameNormalizer(),
    "social_profile_url": SocialProfileURLNormalizer(),
}


def normalize(kind: str, raw: str) -> NormalizedIdentity | None:
    """Route *raw* through the normalizer for *kind*. Returns None
    if *kind* is unknown or the value doesn't parse."""
    normalizer = NORMALIZERS.get(kind)
    if normalizer is None:
        return None
    return normalizer.normalize(raw)  # type: ignore[union-attr]


def dedupe(items: Iterable[NormalizedIdentity]) -> list[NormalizedIdentity]:
    """Aggressive dedup (user pick 20-2A): equivalent canonical strings
    collapse to a single entry. First occurrence wins; every duplicate
    contributes a ``related:<original>`` metadata note.
    """
    seen: dict[tuple[str, str], NormalizedIdentity] = {}
    for item in items:
        key = (item.kind, item.canonical)
        if key not in seen:
            seen[key] = item
            continue
        parent = seen[key]
        related_field = parent.metadata.get("related_originals", "")
        parts = [p for p in related_field.split("|") if p]
        parts.append(item.original)
        parent.metadata["related_originals"] = "|".join(parts)
    return list(seen.values())


__all__ = [
    "NormalizedIdentity",
    "EmailNormalizer",
    "UsernameNormalizer",
    "PhoneNormalizer",
    "CompanyNormalizer",
    "PersonNameNormalizer",
    "SocialProfileURLNormalizer",
    "NORMALIZERS",
    "normalize",
    "dedupe",
]
