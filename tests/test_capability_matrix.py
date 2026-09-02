"""Validate the consolidated upgrade plan HTML capability matrix.

Tests parse ``forge-consolidated-upgrade-plan.html`` with the standard-library
``html.parser`` module and assert structural + enum invariants:

1. Exactly 15 capability rows exist in the matrix.
2. Every FORGE status cell carries a valid status class
   (``b-strong`` / ``b-partial`` / ``b-missing``).
3. Every priority cell carries a valid priority class
   (``b-keep`` / ``b-expand`` / ``b-hi`` / ``b-med`` / ``b-lo``)
   mapping to Keep / Expand / High / Medium / Low.
4. Every upgrade card (``.uc``) exposes the required subsections
   (``uc-name``, ``uc-meta``, ``uc-why``).
5. The matrix table renders with the expected thead columns and tbody row
   count -- i.e. the raw HTML is well-formed enough for a table parser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

import pytest

HTML_PATH = Path(__file__).resolve().parent.parent / "forge-consolidated-upgrade-plan.html"

VALID_STATUS_CLASSES: frozenset[str] = frozenset({"b-strong", "b-partial", "b-missing"})
VALID_PRIORITY_CLASSES: frozenset[str] = frozenset(
    {"b-keep", "b-expand", "b-hi", "b-med", "b-lo"}
)
PRIORITY_CLASS_TO_LABEL: dict[str, str] = {
    "b-keep": "Keep",
    "b-expand": "Expand",
    "b-hi": "High",
    "b-med": "Medium",
    "b-lo": "Low",
}
EXPECTED_CAPABILITY_COUNT = 15
EXPECTED_HEADER_COLUMNS = ("Capability", "FORGE Status", "Best Competitor / Reference", "Priority")
REQUIRED_CARD_SUBSECTIONS: tuple[str, ...] = ("uc-name", "uc-meta", "uc-why")


# ---------- parser primitives ----------


@dataclass
class Cell:
    """One ``<td>`` cell with recovered text and every span class inside it."""

    text: str = ""
    span_classes: list[frozenset[str]] = field(default_factory=list)


@dataclass
class Row:
    """One ``<tr>`` row -- header or body."""

    cells: list[Cell] = field(default_factory=list)
    is_header: bool = False


class CapabilityTableParser(HTMLParser):
    """Extract the FIRST ``<table>`` (the capability matrix) as structured rows.

    We use the stdlib parser only; the HTML plan is a single hand-authored
    document with a well-formed matrix, so we do not need BeautifulSoup.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[Row] = []
        self._in_table = False
        self._captured_first_table = False
        self._in_row = False
        self._in_cell = False
        self._in_header_cell = False
        self._span_depth_in_cell = 0
        self._current_row: Row | None = None
        self._current_cell: Cell | None = None
        self._current_span_classes: frozenset[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table" and not self._captured_first_table:
            self._in_table = True
            return
        if not self._in_table:
            return
        if tag == "tr":
            self._in_row = True
            self._current_row = Row()
            return
        if tag in ("td", "th"):
            self._in_cell = True
            self._in_header_cell = tag == "th"
            self._current_cell = Cell()
            return
        if tag == "span" and self._in_cell:
            self._span_depth_in_cell += 1
            classes = _extract_classes(attrs)
            self._current_span_classes = classes
            if self._current_cell is not None:
                self._current_cell.span_classes.append(classes)

    def handle_endtag(self, tag: str) -> None:
        if tag == "table" and self._in_table:
            self._in_table = False
            self._captured_first_table = True
            return
        if not self._in_table:
            return
        if tag == "tr" and self._in_row:
            if self._current_row is not None:
                self.rows.append(self._current_row)
            self._current_row = None
            self._in_row = False
            return
        if tag in ("td", "th") and self._in_cell:
            if self._current_row is not None and self._current_cell is not None:
                if self._in_header_cell:
                    self._current_row.is_header = True
                self._current_cell.text = self._current_cell.text.strip()
                self._current_row.cells.append(self._current_cell)
            self._current_cell = None
            self._in_cell = False
            self._in_header_cell = False
            return
        if tag == "span" and self._in_cell and self._span_depth_in_cell > 0:
            self._span_depth_in_cell -= 1
            self._current_span_classes = None

    def handle_data(self, data: str) -> None:
        if self._in_cell and self._current_cell is not None:
            self._current_cell.text += data


class UpgradeCardParser(HTMLParser):
    """Extract every ``.uc`` card and its inner class-tagged sections."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.cards: list[dict[str, str]] = []
        self._card_stack_depth = 0  # depth of divs inside an active card
        self._in_card = False
        self._current_card: dict[str, str] | None = None
        self._current_section: str | None = None
        self._section_buf = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "div":
            return
        classes = _extract_classes(attrs)
        if not self._in_card:
            if "uc" in classes:
                self._in_card = True
                self._card_stack_depth = 1
                self._current_card = {}
            return
        self._card_stack_depth += 1
        for section_class in REQUIRED_CARD_SUBSECTIONS:
            if section_class in classes:
                self._flush_section()
                self._current_section = section_class
                self._section_buf = ""
                return

    def handle_endtag(self, tag: str) -> None:
        if tag != "div" or not self._in_card:
            return
        self._card_stack_depth -= 1
        if self._current_section is not None and self._card_stack_depth >= 1:
            # section div closes only when depth returns to the card root (1).
            # Cards' subsection divs are direct children, so any close at
            # depth 1 (after decrement) means the section just ended.
            self._flush_section()
        if self._card_stack_depth == 0:
            self._flush_section()
            if self._current_card is not None:
                self.cards.append(self._current_card)
            self._current_card = None
            self._in_card = False

    def handle_data(self, data: str) -> None:
        if self._in_card and self._current_section is not None:
            self._section_buf += data

    def _flush_section(self) -> None:
        if self._current_section is None or self._current_card is None:
            return
        # Keep the first occurrence per section on a card.
        self._current_card.setdefault(self._current_section, self._section_buf.strip())
        self._current_section = None
        self._section_buf = ""


def _extract_classes(attrs: list[tuple[str, str | None]]) -> frozenset[str]:
    for name, value in attrs:
        if name == "class" and value:
            return frozenset(value.split())
    return frozenset()


# ---------- fixtures ----------


@pytest.fixture(scope="module")
def html_source() -> str:
    if not HTML_PATH.exists():
        pytest.skip(f"HTML plan not found at {HTML_PATH}")
    try:
        return HTML_PATH.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - defensive: unreadable file
        pytest.fail(f"failed to read HTML plan: {exc}")


@pytest.fixture(scope="module")
def matrix_rows(html_source: str) -> list[Row]:
    parser = CapabilityTableParser()
    try:
        parser.feed(html_source)
    except Exception as exc:  # noqa: BLE001 - surface any parse error
        pytest.fail(f"HTML parse error while reading capability matrix: {exc}")
    assert parser.rows, "no rows recovered from the first <table>"
    return parser.rows


@pytest.fixture(scope="module")
def header_row(matrix_rows: list[Row]) -> Row:
    headers = [r for r in matrix_rows if r.is_header]
    assert headers, "capability matrix has no header row"
    return headers[0]


@pytest.fixture(scope="module")
def body_rows(matrix_rows: list[Row]) -> list[Row]:
    return [r for r in matrix_rows if not r.is_header]


@pytest.fixture(scope="module")
def upgrade_cards(html_source: str) -> list[dict[str, str]]:
    parser = UpgradeCardParser()
    try:
        parser.feed(html_source)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"HTML parse error while reading upgrade cards: {exc}")
    return parser.cards


# ---------- tests ----------


def test_all_15_capabilities_exist(body_rows: list[Row]) -> None:
    """The matrix has exactly 15 capability rows, each with a non-empty name."""
    assert len(body_rows) == EXPECTED_CAPABILITY_COUNT, (
        f"expected {EXPECTED_CAPABILITY_COUNT} capability rows, "
        f"got {len(body_rows)}"
    )
    names = [row.cells[0].text for row in body_rows]
    assert all(names), f"one or more capabilities have empty names: {names}"
    assert len(set(names)) == EXPECTED_CAPABILITY_COUNT, (
        f"capability names must be unique, got duplicates in: {names}"
    )


def test_forge_status_values_are_valid(body_rows: list[Row]) -> None:
    """Every status cell carries exactly one of the valid status classes."""
    for row in body_rows:
        capability = row.cells[0].text
        status_cell = row.cells[1]
        status_classes: set[str] = set()
        for classes in status_cell.span_classes:
            status_classes.update(classes & VALID_STATUS_CLASSES)
        assert status_classes, (
            f"capability {capability!r} has no valid FORGE status class; "
            f"expected one of {sorted(VALID_STATUS_CLASSES)}, "
            f"got spans={status_cell.span_classes} text={status_cell.text!r}"
        )
        assert len(status_classes) == 1, (
            f"capability {capability!r} has conflicting status classes: "
            f"{sorted(status_classes)}"
        )


def test_priority_values_are_valid(body_rows: list[Row]) -> None:
    """Every priority cell carries exactly one of the valid priority classes."""
    for row in body_rows:
        capability = row.cells[0].text
        priority_cell = row.cells[3]
        priority_classes: set[str] = set()
        for classes in priority_cell.span_classes:
            priority_classes.update(classes & VALID_PRIORITY_CLASSES)
        assert priority_classes, (
            f"capability {capability!r} has no valid priority class; "
            f"expected one of {sorted(VALID_PRIORITY_CLASSES)} "
            f"(Keep/Expand/High/Medium/Low), "
            f"got spans={priority_cell.span_classes} text={priority_cell.text!r}"
        )
        assert len(priority_classes) == 1, (
            f"capability {capability!r} has conflicting priority classes: "
            f"{sorted(priority_classes)}"
        )
        priority_class = next(iter(priority_classes))
        label = PRIORITY_CLASS_TO_LABEL[priority_class]
        assert label.lower() in priority_cell.text.lower(), (
            f"capability {capability!r} priority class {priority_class} "
            f"should render as {label!r}, got text={priority_cell.text!r}"
        )


def test_capability_sections_have_required_subsections(
    upgrade_cards: list[dict[str, str]],
) -> None:
    """Every ``.uc`` card must contain ``uc-name``, ``uc-meta``, and ``uc-why``."""
    assert upgrade_cards, "no upgrade cards (.uc) found in the plan"
    for index, card in enumerate(upgrade_cards):
        missing = [s for s in REQUIRED_CARD_SUBSECTIONS if s not in card]
        assert not missing, (
            f"upgrade card #{index} (name={card.get('uc-name', '?')!r}) "
            f"missing subsections: {missing}"
        )
        for section in REQUIRED_CARD_SUBSECTIONS:
            assert card[section], (
                f"upgrade card #{index} (name={card.get('uc-name', '?')!r}) "
                f"has empty {section!r} content"
            )


def test_matrix_renders_correctly(
    header_row: Row, body_rows: list[Row]
) -> None:
    """The matrix has the expected 4-column header and 15 body rows.

    This is the structural render check: if the HTML is malformed enough that
    the first ``<table>`` cannot yield a 4-column header plus the expected
    body-row count, this fails before the enum tests confuse the picture.
    """
    header_labels = tuple(cell.text for cell in header_row.cells)
    assert header_labels == EXPECTED_HEADER_COLUMNS, (
        f"header columns drifted; expected {EXPECTED_HEADER_COLUMNS}, "
        f"got {header_labels}"
    )
    assert len(body_rows) == EXPECTED_CAPABILITY_COUNT
    for row in body_rows:
        assert len(row.cells) == len(EXPECTED_HEADER_COLUMNS), (
            f"row {row.cells[0].text if row.cells else '?'!r} has "
            f"{len(row.cells)} cells; expected {len(EXPECTED_HEADER_COLUMNS)}"
        )
