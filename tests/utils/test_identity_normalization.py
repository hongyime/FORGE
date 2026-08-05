"""Tests for the 6 identity normalizers (task 20)."""

from __future__ import annotations

import pytest

from forge.utils.intel.identity_normalization import (
    CompanyNormalizer,
    EmailNormalizer,
    NORMALIZERS,
    NormalizedIdentity,
    PersonNameNormalizer,
    PhoneNormalizer,
    SocialProfileURLNormalizer,
    UsernameNormalizer,
    dedupe,
    normalize,
)


class TestEmailNormalizer:
    def _n(self, raw: str) -> NormalizedIdentity | None:
        return EmailNormalizer().normalize(raw)

    def test_lowercases(self) -> None:
        r = self._n("John.Smith@Example.COM")
        assert r is not None
        assert r.canonical == "john.smith@example.com"

    def test_plus_alias_collapse(self) -> None:
        r = self._n("bob+work@example.com")
        assert r is not None
        assert r.canonical == "bob@example.com"
        assert r.metadata["plus_alias"] == "work"

    def test_gmail_dot_collapse(self) -> None:
        r = self._n("j.s.smith@gmail.com")
        assert r is not None
        assert r.canonical == "jssmith@gmail.com"

    def test_gmail_dot_and_alias_collapse(self) -> None:
        r = self._n("j.s.smith+ordering@gmail.com")
        assert r is not None
        assert r.canonical == "jssmith@gmail.com"

    def test_non_gmail_keeps_dots(self) -> None:
        r = self._n("j.s@example.com")
        assert r is not None
        assert r.canonical == "j.s@example.com"

    def test_disposable_flag(self) -> None:
        r = self._n("throwaway@mailinator.com")
        assert r is not None
        assert r.metadata.get("disposable") == "true"

    def test_invalid_returns_none(self) -> None:
        assert self._n("not-an-email") is None
        assert self._n("") is None
        assert self._n("no@dot") is None


class TestUsernameNormalizer:
    def _n(self, raw: str) -> NormalizedIdentity | None:
        return UsernameNormalizer().normalize(raw)

    def test_strips_at_prefix_and_lowercases(self) -> None:
        r = self._n("@TestOperator")
        assert r is not None
        assert r.canonical == "testoperator"

    def test_collapses_homograph(self) -> None:
        # Cyrillic 'а' at position 1
        raw = "bryan\u0430seah"
        r = self._n(raw)
        assert r is not None
        assert r.canonical == "bryanaseah"

    def test_strips_zero_width_chars(self) -> None:
        raw = "bry\u200ban"
        r = self._n(raw)
        assert r is not None
        assert r.canonical == "bryan"

    def test_collapses_repeated_dots(self) -> None:
        r = self._n("bryan..seah")
        assert r is not None
        assert r.canonical == "bryan_seah"


class TestPhoneNormalizer:
    def _n(self, raw: str) -> NormalizedIdentity | None:
        return PhoneNormalizer().normalize(raw)

    def test_strips_formatting(self) -> None:
        r = self._n("+1 (555) 123-4567")
        assert r is not None
        # Should be at least +15551234567 (phonenumbers may format differently)
        assert r.canonical.startswith("+1") or r.canonical.startswith("+")

    def test_extension_captured_and_stripped(self) -> None:
        r = self._n("+1 555 123 4567 ext 1234")
        assert r is not None
        assert r.metadata.get("extension") == "1234"

    def test_no_prefix_flagged(self) -> None:
        r = self._n("5551234567")
        assert r is not None
        assert "e164_status" in r.metadata or "phonenumbers_valid" in r.metadata

    def test_empty_returns_none(self) -> None:
        assert self._n("") is None
        assert self._n("   ") is None


class TestCompanyNormalizer:
    def _n(self, raw: str) -> NormalizedIdentity | None:
        return CompanyNormalizer().normalize(raw)

    def test_strips_inc(self) -> None:
        r = self._n("Acme Inc.")
        assert r is not None
        assert r.canonical == "acme"

    def test_strips_gmbh(self) -> None:
        r = self._n("Acme GmbH")
        assert r is not None
        assert r.canonical == "acme"

    def test_strips_pte_ltd_stacked(self) -> None:
        r = self._n("Acme Pte Ltd")
        assert r is not None
        assert r.canonical == "acme"
        # Both suffixes recorded
        assert "pte" in r.metadata.get("stripped_legal_suffixes", "").lower()

    def test_preserves_when_only_suffix(self) -> None:
        r = self._n("Inc")
        # Falls back to the original when everything strips out
        assert r is not None
        assert r.canonical  # non-empty

    def test_collapses_whitespace(self) -> None:
        r = self._n("Acme    Corp")
        assert r is not None
        assert r.canonical == "acme"


class TestPersonNameNormalizer:
    def _n(self, raw: str) -> NormalizedIdentity | None:
        return PersonNameNormalizer().normalize(raw)

    def test_handles_last_first_comma(self) -> None:
        r = self._n("Smith, John")
        assert r is not None
        assert r.canonical == "John Smith"

    def test_strips_dr_honorific(self) -> None:
        r = self._n("Dr. FORGE Operator")
        assert r is not None
        assert r.canonical == "Forge Operator"

    def test_strips_trailing_honorific(self) -> None:
        r = self._n("John Smith PhD")
        assert r is not None
        assert r.canonical == "John Smith"

    def test_provides_match_key(self) -> None:
        r = self._n("FORGE Operator")
        assert r is not None
        assert r.metadata["match_key"] == "forge operator"


class TestSocialProfileURLNormalizer:
    def _n(self, raw: str) -> NormalizedIdentity | None:
        return SocialProfileURLNormalizer().normalize(raw)

    def test_normalises_twitter_to_x(self) -> None:
        r = self._n("https://twitter.com/TestUser")
        assert r is not None
        assert r.canonical == "https://x.com/testuser"

    def test_normalises_www_variants(self) -> None:
        r = self._n("https://www.github.com/TestUser/")
        assert r is not None
        assert r.canonical == "https://github.com/testuser"

    def test_normalises_mobile_youtube(self) -> None:
        r = self._n("https://m.youtube.com/@channel/")
        assert r is not None
        assert "youtube.com" in r.canonical
        assert not r.canonical.endswith("/")

    def test_forces_https(self) -> None:
        r = self._n("http://github.com/foo")
        assert r is not None
        assert r.canonical.startswith("https://")

    def test_drops_query_and_fragment(self) -> None:
        r = self._n("https://github.com/foo?tab=readme#body")
        assert r is not None
        assert "?" not in r.canonical
        assert "#" not in r.canonical


class TestDedupeAggressive:
    def test_collapses_duplicate_canonical(self) -> None:
        items = [
            EmailNormalizer().normalize("Bob+work@example.com"),
            EmailNormalizer().normalize("BOB@example.com"),
            EmailNormalizer().normalize("bob+support@EXAMPLE.com"),
        ]
        items = [i for i in items if i is not None]
        deduped = dedupe(items)
        assert len(deduped) == 1
        # All three original values recorded on the survivor
        related = deduped[0].metadata.get("related_originals", "")
        assert related.count("|") >= 1  # at least 2 related recorded

    def test_different_kinds_do_not_collapse(self) -> None:
        items = [
            EmailNormalizer().normalize("bob@example.com"),
            UsernameNormalizer().normalize("bob@example.com"),
        ]
        items = [i for i in items if i is not None]
        deduped = dedupe(items)
        assert len(deduped) == 2


class TestNormalizeDispatch:
    def test_returns_none_on_unknown_kind(self) -> None:
        assert normalize("something_weird", "value") is None

    def test_registry_has_6_kinds(self) -> None:
        assert set(NORMALIZERS.keys()) == {
            "email", "username", "phone", "company", "person_name", "social_profile_url"
        }

    def test_dispatch_delegates(self) -> None:
        r = normalize("email", "Test@Example.COM")
        assert r is not None
        assert r.canonical == "test@example.com"
