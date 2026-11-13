"""WCAG contrast checks for the colour pairs IPLens uses.

Colours come from the shared DadsOps theme (static/theme/dadsops-theme.css) and the few
IPLens tokens in style.css, which may refer to theme tokens with ``var(--name)``.
"""

import re
from pathlib import Path

import pytest

STATIC = Path(__file__).parent.parent / "iplens" / "static"
THEME = (STATIC / "theme" / "dadsops-theme.css").read_text()
CSS = (STATIC / "style.css").read_text()


def _root_tokens(css: str) -> dict[str, str]:
    root = re.search(r":root\s*\{([^}]*)\}", css).group(1)
    root = re.sub(r"/\*.*?\*/", "", root, flags=re.S)
    return {k: v.strip() for k, v in re.findall(r"--([\w-]+):\s*([^;]+);", root)}


THEME_TOKENS = _root_tokens(THEME)
APP_TOKENS = _root_tokens(CSS)
TOKENS = {**THEME_TOKENS, **APP_TOKENS}

AA_TEXT = 4.5
AA_NON_TEXT = 3.0  # WCAG 1.4.11: focus rings, active-menu indicator, chart marks


def _hex(c: str) -> str:
    seen = set()
    while not c.startswith("#"):
        name = c.removeprefix("var(--").removesuffix(")") if c.startswith("var(") else c
        assert name not in seen, f"token cycle at {name}"
        seen.add(name)
        c = TOKENS[name]
    c = c.lstrip("#")
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


def test_app_tokens_resolve_and_do_not_redefine_the_theme():
    # IPLens adds tokens; it never overrides a theme colour, font, size or radius.
    assert APP_TOKENS and not set(APP_TOKENS) & set(THEME_TOKENS)
    for name in APP_TOKENS:
        assert len(_hex(name)) == 6, name


TEXT_PAIRS = [
    # pages, cards, tables (rows greyed out by a rule: --fg-faint / --accent on --bg-subtle)
    ("fg", "bg"),
    ("fg", "bg-panel"),
    ("fg", "bg-subtle"),
    ("fg-muted", "bg-panel"),
    ("fg-faint", "bg"),
    ("fg-faint", "bg-panel"),
    ("fg-faint", "bg-subtle"),
    ("accent", "bg"),
    ("accent", "bg-panel"),
    ("accent", "bg-subtle"),
    # buttons
    ("accent-fg", "accent"),
    ("fg", "danger-bg"),
    # top menu, its context span, the warning links in it, the diagram tooltip
    ("header-fg", "header-bg"),
    ("header-muted", "header-bg"),
    ("header-fg", "bg-hover"),
    ("warn", "header-bg"),
    # badges, flashes, log rows, skipped job resources, tags
    ("fg-muted", "bg-hover"),
    ("ok", "ok-bg"),
    ("warn", "warn-bg"),
    ("danger", "danger-bg"),
    ("accent", "accent-bg"),
    ("fg", "ok-bg"),
    ("fg", "warn-bg"),
    # Diff deltas
    ("ok", "bg-panel"),
    ("danger", "bg-panel"),
    # Visual diagram labels (visual.js): node text on the boxes, edge labels on --bg
    ("fg", "dia-vpc-fill"),
    ("fg", "dia-subnet-fill"),
    ("fg", "dia-area-fill"),
    ("fg", "dia-tile"),
    ("fg-muted", "bg"),
    ("edge-reach", "bg"),
    ("ev-observed", "bg"),
    ("ev-configured", "bg"),
    ("ev-permitted", "bg"),
    ("ev-referenced", "bg"),
    ("edge-blocked", "bg"),
    ("edge-unverified", "bg"),
]


@pytest.mark.parametrize("fg, bg", TEXT_PAIRS)
def test_text_contrast_meets_wcag_aa(fg, bg):
    assert contrast(fg, bg) >= AA_TEXT, f"{fg} on {bg}: {contrast(fg, bg):.2f}:1"


@pytest.mark.parametrize(
    "fg, bg",
    [
        ("accent", "header-bg"),  # active menu item underline
        ("accent", "bg-hover"),
        ("accent", "bg"),  # focus ring
        ("accent", "bg-panel"),
        ("used", "bg-panel"),  # usage bars, subnet grid, trend line
        ("idle", "bg-panel"),
        ("reserved", "bg-panel"),
        ("dia-vpc", "bg-panel"),  # diagram box borders
        ("dia-subnet", "dia-vpc-fill"),
    ],
)
def test_indicator_contrast(fg, bg):
    assert contrast(fg, bg) >= AA_NON_TEXT, f"{fg} on {bg}: {contrast(fg, bg):.2f}:1"


def test_menu_states_come_from_the_theme():
    rules = dict(re.findall(r"(\.shell-header nav a[^{]*)\{([^}]*)\}", THEME))
    active = next(v for k, v in rules.items() if "a.active" in k)
    assert "font-weight: 700" in active and "border-bottom-color: var(--accent)" in active
    assert any(":hover" in k and ":focus-visible" in k for k in rules)
    # IPLens does not restyle the theme's menu links.
    assert not re.search(r"(?:^|[\s,}])(?:header|\.shell-header) nav\b", CSS)


def test_style_css_is_dark_only():
    body = CSS.split("}", 1)[1]
    # Text colours outside :root go through the checked tokens; no literal colour at all.
    assert not re.findall(r"(?<![-\w])color:\s*#", body)
    # No literal (light) backgrounds: surfaces come from theme / app tokens.
    assert not re.findall(r"background(?:-color)?:\s*#", body)
    assert "prefers-color-scheme" not in CSS and "light" not in CSS.lower()
