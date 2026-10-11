"""Tests for :mod:`forge.utils.tool_wrappers`.

Backlog item: Do Next #17 — Strix-style universal tool-wrapper hardening.

These tests pin the Strix-style wrapper contract we rely on across the
connector runner, phase4 parsers, and future MCP/LLM tool surfaces:

* ``bounded_output`` caps BOTH line count and byte count and emits a
  stable ``[TRUNCATED: ...]`` marker.
* ``coerce_arguments`` repairs the most common LLM-produced schema
  violations (null-as-string, string-when-array-expected, JSON-string-
  in-dict, numeric strings, boolean strings).
* ``safe_tool_call`` converts uncaught exceptions into string results so
  a crashing tool cannot kill the connector loop.
"""

from __future__ import annotations

import pytest

from forge.utils.tool_wrappers import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_LINES,
    bounded_output,
    coerce_arguments,
    safe_tool_call,
)


# ---------------------------------------------------------------------------
# bounded_output
# ---------------------------------------------------------------------------


class TestBoundedOutput:
    def test_short_output_is_returned_unchanged(self) -> None:
        text = "line a\nline b\nline c"
        assert bounded_output(text) == text

    def test_empty_input_returns_empty_string(self) -> None:
        assert bounded_output(None) == ""
        assert bounded_output("") == ""
        assert bounded_output(b"") == ""

    def test_line_cap_applies_truncation_marker(self) -> None:
        text = "\n".join(f"line {i}" for i in range(600))
        capped = bounded_output(text, max_lines=5)
        lines = capped.splitlines()
        assert lines[:5] == [f"line {i}" for i in range(5)]
        assert lines[-1] == "[TRUNCATED: 600 lines -> 5]"

    def test_byte_cap_applies_truncation_marker(self) -> None:
        text = "x" * 10_000
        capped = bounded_output(text, max_lines=100, max_bytes=200)
        assert len(capped.encode("utf-8")) <= 200
        assert capped.endswith("[TRUNCATED: 1 lines -> 100]")

    def test_marker_mentions_original_line_count_not_truncated_count(self) -> None:
        text = "\n".join(f"line {i}" for i in range(12))
        capped = bounded_output(text, max_lines=3)
        assert "[TRUNCATED: 12 lines -> 3]" in capped

    def test_bytes_input_is_decoded(self) -> None:
        text = b"hello\nworld"
        capped = bounded_output(text, max_lines=1)
        assert capped.startswith("hello")
        assert "[TRUNCATED: 2 lines -> 1]" in capped

    def test_list_input_is_joined_with_newlines(self) -> None:
        rows = [f"host-{i}.example" for i in range(10)]
        capped = bounded_output(rows, max_lines=3)
        assert capped.startswith("host-0.example\nhost-1.example\nhost-2.example")
        assert "[TRUNCATED: 10 lines -> 3]" in capped

    def test_default_caps_are_exposed(self) -> None:
        assert DEFAULT_MAX_LINES >= 100
        assert DEFAULT_MAX_BYTES >= 1_000

    def test_cap_floor_prevents_zero_bounds(self) -> None:
        capped = bounded_output("abc\n" * 10, max_lines=0, max_bytes=0)
        # No crash; truncation marker included.
        assert "[TRUNCATED:" in capped

    def test_utf8_multibyte_boundary_is_not_corrupted(self) -> None:
        # 4-byte UTF-8 character; byte cap must not split in the middle.
        text = "\U0001f600" * 100  # 😀 = 4 bytes each.
        capped = bounded_output(text, max_lines=100, max_bytes=50)
        # Should still be valid UTF-8 and shorter than original.
        assert isinstance(capped, str)
        assert "[TRUNCATED:" in capped
        # Encode-decode round trip should succeed.
        capped.encode("utf-8")

    def test_non_string_object_is_coerced_via_str(self) -> None:
        class _Obj:
            def __str__(self) -> str:
                return "object-repr-ok"

        assert bounded_output(_Obj()) == "object-repr-ok"


# ---------------------------------------------------------------------------
# coerce_arguments
# ---------------------------------------------------------------------------


class TestCoerceArguments:
    def test_empty_args_returns_empty_dict(self) -> None:
        assert coerce_arguments(None, None) == {}
        assert coerce_arguments({}, None) == {}
        assert coerce_arguments(None, {"x": {"type": "string"}}) == {}

    def test_passthrough_when_schema_entry_missing(self) -> None:
        schema = {"known": {"type": "string"}}
        args = {"known": "value", "unknown": {"deep": "struct"}}
        result = coerce_arguments(args, schema)
        assert result["known"] == "value"
        assert result["unknown"] == {"deep": "struct"}

    def test_null_string_becomes_none_for_null_type(self) -> None:
        result = coerce_arguments({"x": "null"}, {"x": {"type": "null"}})
        assert result["x"] is None

    def test_null_string_becomes_none_for_integer_type(self) -> None:
        result = coerce_arguments({"x": "null"}, {"x": {"type": "integer"}})
        assert result["x"] is None

    def test_string_when_array_expected_wraps_as_single_item(self) -> None:
        result = coerce_arguments({"targets": "example.com"}, {"targets": {"type": "array"}})
        assert result["targets"] == ["example.com"]

    def test_json_array_string_is_parsed_when_array_expected(self) -> None:
        result = coerce_arguments(
            {"targets": '["a.example", "b.example"]'},
            {"targets": {"type": "array"}},
        )
        assert result["targets"] == ["a.example", "b.example"]

    def test_comma_separated_string_is_split_when_array_expected(self) -> None:
        result = coerce_arguments(
            {"tags": "red, blue , green"},
            {"tags": {"type": "array"}},
        )
        assert result["tags"] == ["red", "blue", "green"]

    def test_actual_list_is_preserved_for_array_type(self) -> None:
        result = coerce_arguments({"xs": [1, 2, 3]}, {"xs": {"type": "array"}})
        assert result["xs"] == [1, 2, 3]

    def test_json_string_in_dict_is_parsed(self) -> None:
        result = coerce_arguments(
            {"meta": '{"owner": "alice", "severity": "high"}'},
            {"meta": {"type": "object"}},
        )
        assert result["meta"] == {"owner": "alice", "severity": "high"}

    def test_actual_dict_is_preserved_for_object_type(self) -> None:
        result = coerce_arguments({"meta": {"a": 1}}, {"meta": {"type": "dict"}})
        assert result["meta"] == {"a": 1}

    def test_numeric_string_becomes_int(self) -> None:
        result = coerce_arguments({"count": "42"}, {"count": {"type": "integer"}})
        assert result["count"] == 42

    def test_float_string_becomes_float(self) -> None:
        result = coerce_arguments({"ratio": "0.5"}, {"ratio": {"type": "number"}})
        assert result["ratio"] == pytest.approx(0.5)

    def test_boolean_true_string_variants(self) -> None:
        schema = {"flag": {"type": "boolean"}}
        for value in ("true", "True", "yes", "on", "1"):
            assert coerce_arguments({"flag": value}, schema)["flag"] is True

    def test_boolean_false_string_variants(self) -> None:
        schema = {"flag": {"type": "boolean"}}
        for value in ("false", "False", "no", "off", "0"):
            assert coerce_arguments({"flag": value}, schema)["flag"] is False

    def test_non_json_dict_string_is_returned_verbatim(self) -> None:
        # Not valid JSON -> keep the raw value, let downstream validate.
        result = coerce_arguments({"meta": "just a note"}, {"meta": {"type": "object"}})
        assert result["meta"] == "just a note"

    def test_bytes_string_input_is_decoded_for_string_type(self) -> None:
        result = coerce_arguments({"host": b"example.com"}, {"host": {"type": "string"}})
        assert result["host"] == "example.com"

    def test_empty_string_for_array_type_returns_empty_list(self) -> None:
        result = coerce_arguments({"xs": ""}, {"xs": {"type": "array"}})
        assert result["xs"] == []

    def test_unknown_type_is_a_passthrough(self) -> None:
        result = coerce_arguments({"x": "value"}, {"x": {"type": "exotic"}})
        assert result["x"] == "value"

    def test_returned_dict_is_a_new_object(self) -> None:
        args = {"x": "1"}
        schema = {"x": {"type": "integer"}}
        result = coerce_arguments(args, schema)
        result["x"] = 999
        assert args["x"] == "1"


# ---------------------------------------------------------------------------
# safe_tool_call
# ---------------------------------------------------------------------------


class TestSafeToolCall:
    def test_success_is_returned_verbatim(self) -> None:
        assert safe_tool_call(lambda x: x * 2, 3) == 6

    def test_success_with_kwargs_is_returned_verbatim(self) -> None:
        result = safe_tool_call(lambda **kw: kw, a=1, b=2)
        assert result == {"a": 1, "b": 2}

    def test_exception_becomes_string_result(self) -> None:
        def _boom() -> None:
            raise ValueError("nope")

        result = safe_tool_call(_boom)
        assert isinstance(result, str)
        assert result.startswith("error: ValueError:")
        assert "nope" in result

    def test_exception_type_name_is_preserved(self) -> None:
        def _boom() -> None:
            raise KeyError("missing-key")

        result = safe_tool_call(_boom)
        assert "KeyError" in result

    def test_single_line_envelope_for_multiline_exception(self) -> None:
        def _boom() -> None:
            raise RuntimeError("line one\nline two\nline three")

        result = safe_tool_call(_boom)
        assert "\n" not in result
        assert "line one" in result and "line two" in result

    def test_long_messages_are_bounded(self) -> None:
        def _boom() -> None:
            raise ValueError("x" * 10_000)

        result = safe_tool_call(_boom)
        assert len(result) < 400  # bounded by _format_error_result

    def test_keyboard_interrupt_still_propagates(self) -> None:
        def _boom() -> None:
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            safe_tool_call(_boom)

    def test_system_exit_still_propagates(self) -> None:
        def _boom() -> None:
            raise SystemExit(1)

        with pytest.raises(SystemExit):
            safe_tool_call(_boom)

    def test_zero_division_error_is_captured(self) -> None:
        result = safe_tool_call(lambda: 1 / 0)
        assert "ZeroDivisionError" in result

    def test_safe_tool_call_does_not_require_arguments(self) -> None:
        result = safe_tool_call(lambda: "hello")
        assert result == "hello"


# ---------------------------------------------------------------------------
# Integration — compose primitives
# ---------------------------------------------------------------------------


class TestComposition:
    """Smoke tests that the three wrappers compose cleanly."""

    def test_bounded_output_over_safe_tool_call_result(self) -> None:
        def _crash() -> str:
            raise RuntimeError("x" * 1000)

        rendered = safe_tool_call(_crash)
        assert bounded_output(rendered, max_lines=1, max_bytes=200).endswith(
            "[TRUNCATED: 1 lines -> 1]"
        )

    def test_coerced_args_feed_bounded_output_cap(self) -> None:
        coerced = coerce_arguments(
            {"max_lines": "25", "max_bytes": "4000"},
            {"max_lines": {"type": "integer"}, "max_bytes": {"type": "integer"}},
        )
        text = "line\n" * 100
        capped = bounded_output(text, max_lines=coerced["max_lines"], max_bytes=coerced["max_bytes"])
        assert capped.endswith("[TRUNCATED: 100 lines -> 25]")
