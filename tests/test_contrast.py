"""WCAG contrast checks for the colour pairs used in style.css."""

import re
from pathlib import Path

import pytest

CSS = (Path(__file__).parent.parent / "iplens" / "static" / "style.css").read_text()
ROOT = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{3,6})", CSS.split("}", 1)[0]))

AA_TEXT = 4.5
AA_NON_TEXT = 3.0  # WCAG 1.4.11: focus rings, active-tab indicator


def _hex(c: str) -> str:
    c = ROOT.get(c, c).lstrip("#")
    return "".join(ch * 2 for ch in c) if len(c) == 3 else c


def _luminance(c: str) -> float:
    def chan(v: int) -> float:
        s = v / 255
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4

    h = _hex(c)
    r, g, b = (chan(int(h[i : i + 2], 16)) for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(fg: str, bg: str) -> float:
    hi, lo = sorted((_luminance(fg), _luminance(bg)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_contrast_formula():
    assert contrast("#000", "#fff") == pytest.approx(21.0)
    assert contrast("#fff", "#fff") == pytest.approx(1.0)


TEXT_PAIRS = [
    # pages and tables
    ("fg", "bg"),
    ("fg", "card"),
    ("muted", "bg"),
    ("muted", "card"),
    ("link", "bg"),
    ("link", "card"),
    ("#fff", "link"),  # primary button
    ("#fff", "err"),  # danger button
    ("fg", "badge-bg"),  # secondary button
    # header / navigation
    ("nav-fg", "nav-bg"),
    ("nav-fg-active", "nav-bg"),
    ("nav-fg-active", "nav-bg-hover"),
    ("nav-ctx", "nav-bg"),
    ("nav-warn", "nav-bg"),  # credential problem link in the header
    # badges and flashes
    ("badge-fg", "badge-bg"),
    ("ok-fg", "ok-bg"),
    ("warn-fg", "warn-bg"),
    ("err-fg", "err-bg"),
    ("fg", "ok-bg"),
    ("fg", "warn-bg"),
    ("fg", "err-bg"),
    # rows greyed out by a rule
    ("blocked-fg", "blocked-bg"),
    ("blocked-link", "blocked-bg"),
]


@pytest.mark.parametrize("fg, bg", TEXT_PAIRS)
def test_text_contrast_meets_wcag_aa(fg, bg):
    assert contrast(fg, bg) >= AA_TEXT, f"{fg} on {bg}: {contrast(fg, bg):.2f}:1"


@pytest.mark.parametrize(
    "fg, bg",
    [("nav-accent", "nav-bg"), ("nav-accent", "nav-bg-hover"), ("focus", "bg"), ("focus", "card")],
)
def test_indicator_contrast(fg, bg):
    assert contrast(fg, bg) >= AA_NON_TEXT


def test_nav_states_are_styled():
    rules = dict(re.findall(r"(header nav a[^{,]*)\{([^}]*)\}", CSS))
    active = rules["header nav a.active "]
    assert "font-weight: 700" in active and "border-bottom-color: var(--nav-accent)" in active
    assert "text-decoration: underline" in rules["header nav a:hover "]
    assert "outline: 2px solid var(--nav-accent)" in rules["header nav a:focus-visible "]


def test_no_hardcoded_low_contrast_text_colours():
    # Text colours outside :root must go through the checked variables.
    body = CSS.split("}", 1)[1]
    literal = re.findall(r"(?<![-\w])color:\s*(#[0-9a-fA-F]{3,6})", body)
    assert set(literal) <= {"#fff"}, literal
