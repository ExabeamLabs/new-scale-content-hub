"""
Executive briefing (Word .docx) for the Exabeam MITRE coverage report.

Dark-themed, Exabeam-branded summary of the current ATT&CK coverage: score, validation,
detection health, threat exposure, an Echo validation plan and recommended actions.
Called from build_mitre_coverage_report.py; needs python-docx.
"""
import os
from datetime import datetime

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT, WD_ROW_HEIGHT_RULE
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, Inches, RGBColor, Emu

# ---------------------------------------------------------------- palette (light, restrained corporate theme)
BG = "FFFFFF"
PANEL = "F6F7F9"
PANEL_2 = "EDEFF2"
LINE = "DDE1E6"
TEXT = "2B2F36"
WHITE = "111418"      # strongest text colour (headings, key figures)
MUTED = "6B7280"
GREEN = "1F8A0E"      # Exabeam green, darkened for legibility on white
BLUE = "0B6BCB"
ACCENT = "0B6BCB"
TRACK = "E3E7ED"
BAND_HIGH = "2E8B23"
BAND_MID = "2F6FBF"
BAND_LOW = "8A4FB0"
RED = "B42318"
AMBER = "B45309"

SANS = "Segoe UI"
SANS_BOLD = "Segoe UI Semibold"
MONO = "Consolas"

CONTENT_WIDTH_IN = 7.1   # A4 portrait with 0.6" margins

STATUS_COLOUR = {"validated": BAND_HIGH, "quiet": BAND_MID, "unvalidated": BAND_LOW, "none": MUTED}
STATUS_LABEL = {"validated": "VALIDATED", "quiet": "QUIET", "unvalidated": "UNVALIDATED", "none": "NOT COVERED"}

MITRE_NOTICE = (
    "© 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE "
    "Corporation. https://attack.mitre.org/resources/terms-of-use/  ATT&CK is subject to the license linked here and the "
    "following copyright: © 2023 The MITRE Corporation. This work is reproduced and distributed with the permission of "
    "The MITRE Corporation. MITRE ATT&CK and ATT&CK are trademarks of The MITRE Corporation. Exabeam is not affiliated "
    "with, sponsored, or endorsed by The MITRE Corporation."
)


# ---------------------------------------------------------------- low-level helpers
def rgb(hex_colour: str) -> RGBColor:
    return RGBColor.from_string(hex_colour.upper())


def set_run(run, size=10, colour=TEXT, bold=False, font=SANS, italic=False, spacing=None):
    run.font.size = Pt(size)
    run.font.color.rgb = rgb(colour)
    run.font.bold = bold
    run.font.italic = italic
    run.font.name = font
    rpr = run._element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(attr), font)
    if spacing is not None:  # letter spacing in points
        sp = OxmlElement("w:spacing")
        sp.set(qn("w:val"), str(int(spacing * 20)))
        rpr.append(sp)
    return run


def para(container, text="", size=10, colour=TEXT, bold=False, font=SANS, align=None, before=0, after=6,
         line=1.25, spacing=None, italic=False):
    p = container.add_paragraph()
    pf = p.paragraph_format
    pf.space_before = Pt(before)
    pf.space_after = Pt(after)
    pf.line_spacing = line
    if align:
        p.alignment = align
    if text:
        set_run(p.add_run(text), size, colour, bold, font, italic, spacing)
    return p


def rich(container, parts, size=10, after=6, before=0, line=1.3, align=None):
    """parts: list of (text, {run options}) tuples, for inline emphasis."""
    p = para(container, size=size, after=after, before=before, line=line, align=align)
    for text, opts in parts:
        set_run(p.add_run(text), size=opts.get("size", size), colour=opts.get("colour", TEXT),
                bold=opts.get("bold", False), font=opts.get("font", SANS), italic=opts.get("italic", False))
    return p


def shade(cell, fill):
    tcpr = cell._element.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcpr.append(shd)


def cell_borders(cell, **edges):
    """edges: top/left/bottom/right = (hex colour, size in eighths of a point) or None for no border."""
    tcpr = cell._element.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for edge in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{edge}")
        spec = edges.get(edge)
        if spec:
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), str(spec[1]))
            el.set(qn("w:color"), spec[0])
        else:
            el.set(qn("w:val"), "nil")
        borders.append(el)
    tcpr.append(borders)


def cell_margins(cell, top=80, bottom=80, left=120, right=120):
    tcpr = cell._element.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for edge, val in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:w"), str(val))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tcpr.append(mar)


def fixed_table(container, rows, widths_in, borderless=True):
    table = container.add_table(rows=rows, cols=len(widths_in))
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    table.autofit = False
    tblpr = table._element.tblPr
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tblpr.append(layout)
    # zero default cell spacing / borders
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "nil")
        borders.append(el)
    tblpr.append(borders)
    grid = table._element.tblGrid
    for i, gc in enumerate(grid.findall(qn("w:gridCol"))):
        gc.set(qn("w:w"), str(int(widths_in[i] * 1440)))
    for row in table.rows:
        for i, cell in enumerate(row.cells):
            cell.width = Inches(widths_in[i])
    return table


def clear_cell(cell):
    """Remove the empty first paragraph so content starts flush."""
    for p in list(cell.paragraphs):
        p._element.getparent().remove(p._element)


def row_height(row, inches, exact=True):
    row.height = Inches(inches)
    row.height_rule = WD_ROW_HEIGHT_RULE.EXACTLY if exact else WD_ROW_HEIGHT_RULE.AT_LEAST


def shrink_trailing_paragraph(container):
    """Word needs a paragraph after a table inside a cell; make it as small as possible."""
    if hasattr(container, "_tc") and container.paragraphs:
        p = container.paragraphs[-1]
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = Pt(2)


def stacked_bar(container, segments, width_in, track=TRACK, height_in=0.07):
    """Horizontal bar of consecutive (pct, colour) segments on a track, built from a one-row table."""
    widths, colours, used = [], [], 0.0
    for pct, colour in segments:
        w = round(width_in * max(0.0, min(100.0, float(pct))) / 100, 3)
        if w > 0.01:
            widths.append(w)
            colours.append(colour)
            used += w
    if width_in - used > 0.01:
        widths.append(round(width_in - used, 3))
        colours.append(track)
    t = fixed_table(container, 1, widths)
    row_height(t.rows[0], height_in)
    for cell, colour in zip(t.rows[0].cells, colours):
        shade(cell, colour)
        cell_margins(cell, 0, 0, 0, 0)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = Pt(1)
    shrink_trailing_paragraph(container)
    return t


def bar(container, pct, width_in, fill=ACCENT, track=TRACK, height_in=0.07):
    """A thin horizontal progress bar."""
    return stacked_bar(container, [(pct, fill)], width_in, track, height_in)


def segmented_gauge(container, score, width_in=CONTENT_WIDTH_IN, segments=40, height_in=0.16):
    """Navigator-style segmented gauge: segments light up in the score band colour."""
    score = max(0, min(100, int(score)))
    colour = BAND_HIGH if score >= 75 else BAND_MID if score >= 50 else BAND_LOW if score > 0 else MUTED
    lit = round(segments * score / 100)
    seg_w = width_in / segments
    t = fixed_table(container, 1, [seg_w] * segments)
    row_height(t.rows[0], height_in)
    for i, cell in enumerate(t.rows[0].cells):
        shade(cell, colour if i < lit else PANEL_2)
        cell_borders(cell, left=(PANEL, 16), right=(PANEL, 16))
        cell_margins(cell, 0, 0, 0, 0)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = Pt(1)
    return t


def bottom_rule(p, colour=LINE, size=6, space=4):
    ppr = p._element.get_or_add_pPr()
    bdr = OxmlElement("w:pBdr")
    b = OxmlElement("w:bottom")
    b.set(qn("w:val"), "single")
    b.set(qn("w:sz"), str(size))
    b.set(qn("w:space"), str(space))
    b.set(qn("w:color"), colour)
    bdr.append(b)
    ppr.append(bdr)


def field(paragraph, instr, size=8, colour=MUTED):
    run = paragraph.add_run()
    set_run(run, size, colour, font=SANS)
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    text = OxmlElement("w:instrText")
    text.set(qn("xml:space"), "preserve")
    text.text = instr
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._element.append(begin)
    run._element.append(text)
    run._element.append(end)


def page_break(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


# ---------------------------------------------------------------- document furniture
def setup_document(logo_path: str | None, region: str, generated: str):
    doc = Document()

    normal = doc.styles["Normal"]
    normal.font.name = SANS
    normal.font.size = Pt(10)
    normal.font.color.rgb = rgb(TEXT)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), SANS)

    section = doc.sections[0]
    section.orientation = WD_ORIENT.PORTRAIT
    section.page_width, section.page_height = Inches(8.27), Inches(11.69)   # A4
    for side in ("left_margin", "right_margin"):
        setattr(section, side, Inches(0.6))
    section.top_margin, section.bottom_margin = Inches(0.75), Inches(0.6)
    section.header_distance, section.footer_distance = Inches(0.3), Inches(0.3)

    # Header: Exabeam mark + report identity
    hdr = section.header
    hp = hdr.paragraphs[0]
    hp.paragraph_format.space_after = Pt(0)
    if logo_path and os.path.exists(logo_path):
        pic = hp.add_run().add_picture(logo_path, height=Inches(0.16))
        hp.add_run("  ")
    set_run(hp.add_run("EXABEAM"), 8.5, WHITE, True, SANS_BOLD, spacing=1.2)
    set_run(hp.add_run("   |   MITRE ATT&CK Coverage Briefing"), 8.5, MUTED, False, SANS)
    set_run(hp.add_run(f"   |   {region.upper()}  ·  {generated[:10]}"), 8, MUTED, False, SANS)
    bottom_rule(hp, LINE, 4, 6)

    # Footer: classification + page number
    fp = section.footer.paragraphs[0]
    set_run(fp.add_run("Confidential  ·  Internal security use  ·  Page "), 7.5, MUTED)
    field(fp, "PAGE", 7.5, MUTED)

    doc.core_properties.title = "MITRE ATT&CK Coverage - Executive Briefing"
    doc.core_properties.subject = "Exabeam detection coverage"
    doc.core_properties.author = "Exabeam MITRE Coverage Report"
    return doc


def section_heading(doc, number: str, title: str, kicker: str = ""):
    p = para(doc, before=16, after=2)
    p.paragraph_format.keep_with_next = True
    set_run(p.add_run(f"{number}   "), 8, GREEN, True, SANS_BOLD, spacing=0.5)
    set_run(p.add_run(title.upper()), 8, MUTED, True, SANS_BOLD, spacing=1)
    h = para(doc, kicker or title, 15, WHITE, False, SANS_BOLD, after=8)
    h.paragraph_format.keep_with_next = True
    bottom_rule(h, LINE, 4, 6)
    return h


def kpi_tiles(doc, tiles):
    """tiles: list of (label, value, sub, accent hex, pct-or-None)."""
    n = len(tiles)
    gap = 0.12
    w = (CONTENT_WIDTH_IN - gap * (n - 1)) / n
    widths = []
    for i in range(n):
        widths.append(w)
        if i < n - 1:
            widths.append(gap)
    t = fixed_table(doc, 1, widths)
    cells = [c for i, c in enumerate(t.rows[0].cells) if i % 2 == 0]
    for cell, (label, value, sub, accent, pct) in zip(cells, tiles):
        shade(cell, PANEL)
        cell_borders(cell, top=(accent, 12))
        cell_margins(cell, 140, 120, 160, 140)
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
        clear_cell(cell)
        para(cell, label.upper(), 7, MUTED, True, SANS_BOLD, after=4, spacing=0.6)
        para(cell, str(value), 20, WHITE, False, SANS_BOLD, after=2, line=1.0)
        if pct is not None:
            bar(cell, pct, w - 0.32, fill=accent if accent != LINE else ACCENT)
        para(cell, sub, 7.5, MUTED, after=0, before=4, line=1.15)
    para(doc, after=4)


def data_table(doc, headers, rows, widths, mono_cols=(), colour_cols=None, zebra=True):
    """Dark table. colour_cols: {col index: function(value) -> hex colour}."""
    colour_cols = colour_cols or {}
    t = fixed_table(doc, len(rows) + 1, widths)
    # Repeat the header row on each page, and never leave it alone at the bottom of one
    trpr = t.rows[0]._tr.get_or_add_trPr()
    trpr.append(OxmlElement("w:tblHeader"))
    for row in t.rows:
        row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        shade(c, PANEL_2)
        cell_borders(c, bottom=(LINE, 8))
        cell_margins(c, 70, 70, 100, 100)
        clear_cell(c)
        para(c, h.upper(), 7, MUTED, True, SANS_BOLD, after=0, spacing=0.5).paragraph_format.keep_with_next = True
    for r, row in enumerate(rows, start=1):
        for i, val in enumerate(row):
            c = t.rows[r].cells[i]
            shade(c, BG if (r % 2 or not zebra) else "F9FAFB")
            cell_borders(c, bottom=(LINE, 4))
            cell_margins(c, 60, 60, 100, 100)
            clear_cell(c)
            colour = colour_cols[i](val) if i in colour_cols else TEXT
            para(c, str(val), 8, colour, i in colour_cols, MONO if i in mono_cols else SANS, after=0, line=1.15)
    para(doc, after=6)
    return t


def callout(doc, label, text, accent=GREEN):
    t = fixed_table(doc, 1, [CONTENT_WIDTH_IN])
    t.rows[0]._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))   # keep the box on one page
    c = t.rows[0].cells[0]
    shade(c, PANEL)
    cell_borders(c, left=(accent, 18))
    cell_margins(c, 140, 140, 220, 180)
    clear_cell(c)
    para(c, label.upper(), 7.5, accent, True, SANS_BOLD, after=4, spacing=0.8)
    para(c, text, 10, WHITE, False, SANS, after=0, line=1.35)
    para(doc, after=6)


# ---------------------------------------------------------------- analysis
def posture_rating(score: int) -> tuple[str, str]:
    if score >= 75:
        return "ADVANCED", BAND_HIGH
    if score >= 50:
        return "ESTABLISHED", BAND_MID
    if score >= 25:
        return "DEVELOPING", AMBER
    return "LIMITED", RED


def tactic_stats(matrix: list[dict]) -> list[dict]:
    out = []
    for col in matrix:
        techs = col["techs"]
        covered = sum(1 for t in techs if t["rolled"] != "none")
        validated = sum(1 for t in techs if t["rolled"] == "validated")
        out.append({"id": col["id"], "name": col["name"], "total": len(techs), "covered": covered,
                    "validated": validated,
                    "coveredPct": round(covered / len(techs) * 100, 1) if techs else 0.0,
                    "validatedPct": round(validated / len(techs) * 100, 1) if techs else 0.0})
    return out


def join_names(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def plural(n: int, word: str, plural_word: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural_word or word + 's')}"


# ---------------------------------------------------------------- report
def build_executive_report(path: str, ctx: dict) -> None:
    k = ctx["kpis"]
    stale = ctx["stale_days"]
    matrix = ctx["matrix"]
    attack = ctx.get("attack")
    sector = ctx.get("sector") or ""
    health = ctx["health_enabled"]
    rule_products = ctx.get("rule_products", {})
    rule_techniques = ctx.get("rule_techniques", {})

    parents = {t["id"]: t for col in matrix for t in col["techs"]}
    n_parents = len(parents)
    covered = sum(1 for t in parents.values() if t["rolled"] != "none")
    validated = sum(1 for t in parents.values() if t["rolled"] == "validated")
    unproven = covered - validated
    score = k["coverageScore"]
    cov_pct = round(covered / n_parents * 100, 1) if n_parents else 0
    val_pct = round(validated / n_parents * 100, 1) if n_parents else 0
    rating, rating_colour = posture_rating(score)

    groups = attack["groups"] if attack else []
    in_sector = [i for i, g in enumerate(groups) if not sector or sector in g["sectors"]]
    sector_set = set(in_sector)

    def threat_count(t):
        return sum(1 for i in t.get("grp", []) if i in sector_set)

    tactics = tactic_stats(matrix)
    sized = [t for t in tactics if t["total"] >= 5]
    strongest = sorted(sized, key=lambda t: (-t["coveredPct"], t["name"]))[:2]
    weakest = sorted(sized, key=lambda t: (t["coveredPct"], t["name"]))[:2]

    quiet = sorted([h for h in health if h["status"] == "Quiet"], key=lambda h: h["daysSinceLastTrigger"])
    never = [h for h in health if h["status"] == "NeverFired"]
    threat_gaps = sorted([t for t in parents.values() if t["rolled"] != "validated" and threat_count(t) > 0],
                         key=lambda t: (-threat_count(t), t["rolledScore"], t["name"]))

    doc = setup_document(ctx.get("logo"), ctx["region"], ctx["generated"])

    # ============================================================ COVER BLOCK
    p = para(doc, before=6, after=0)
    set_run(p.add_run("EXECUTIVE BRIEFING"), 8, GREEN, True, SANS_BOLD, spacing=1.2)
    para(doc, "MITRE ATT&CK Detection Coverage", 24, WHITE, False, SANS_BOLD, after=2, line=1.05)
    meta = rich(doc, [
        ("Region ", {"colour": MUTED, "size": 9}), (ctx["region"].upper(), {"colour": TEXT, "size": 9, "bold": True}),
        ("     Generated ", {"colour": MUTED, "size": 9}), (ctx["generated"], {"colour": TEXT, "size": 9, "bold": True}),
        ("     ATT&CK ", {"colour": MUTED, "size": 9}),
        (f"v{attack['version']}" if attack else "n/a", {"colour": TEXT, "size": 9, "bold": True}),
        ("     Sector ", {"colour": MUTED, "size": 9}),
        (sector or "All", {"colour": TEXT, "size": 9, "bold": True}),
    ], size=9, after=14)
    bottom_rule(meta, LINE, 4, 8)

    # Score block: number + rating + gauge
    t = fixed_table(doc, 1, [2.3, 4.8])
    left, right = t.rows[0].cells
    for c in (left, right):
        shade(c, PANEL)
        cell_margins(c, 160, 160, 200, 200)
        clear_cell(c)
    cell_borders(left, left=(GREEN, 18))
    para(left, "COVERAGE SCORE", 7, MUTED, True, SANS_BOLD, after=0, spacing=0.6)
    sp = para(left, after=0, line=1.0)
    set_run(sp.add_run(str(score)), 38, WHITE, False, SANS_BOLD)
    set_run(sp.add_run(" / 100"), 11, MUTED, False, SANS)
    para(right, "POSTURE", 7, MUTED, True, SANS_BOLD, after=2, spacing=0.6)
    para(right, rating.title(), 16, rating_colour, False, SANS_BOLD, after=6, line=1.0)
    segmented_gauge(right, score, width_in=4.35)
    para(right, "Average technique score across all ATT&CK techniques, the same method as the Exabeam Outcomes Navigator. "
                "Scores reward detections that are proven to fire, not just mapped.", 7.5, MUTED, after=0, before=6)
    para(doc, after=6)

    kpi_tiles(doc, [
        ("Techniques covered", f"{cov_pct}%", f"{covered}/{n_parents} parent techniques have an enabled rule", ACCENT, cov_pct),
        ("Validated", f"{val_pct}%", f"{validated} techniques have a rule that fired in the last {stale} days", GREEN, val_pct),
        ("Rules firing", f"{k['rulesActive']}/{k['enabledRules']}", f"enabled rules triggered in the last {stale} days", BLUE,
         round(k["rulesActive"] / k["enabledRules"] * 100, 1) if k["enabledRules"] else 0),
        ("Unproven coverage", unproven, "covered techniques relying only on quiet or never-fired rules", BAND_LOW, None),
    ])

    # ============================================================ 01 SITUATION
    section_heading(doc, "01", "Situation report", "Where we stand")
    rich(doc, [
        ("Exabeam correlation content maps to ", {}), (f"{covered} of {n_parents}", {"bold": True, "colour": WHITE}),
        (f" MITRE ATT&CK techniques ({cov_pct}%). Only ", {}), (f"{validated} ({val_pct}%)", {"bold": True, "colour": WHITE}),
        (f" are backed by a rule that has actually fired in the last {stale} days; the remaining ", {}),
        (f"{unproven}", {"bold": True, "colour": WHITE}),
        (" covered techniques depend on detections that are unproven or have gone quiet. The overall MITRE ATT&CK Coverage "
         "Score is ", {}), (f"{score}/100", {"bold": True, "colour": WHITE}), (", a posture of ", {}),
        (rating.lower(), {"bold": True, "colour": rating_colour}), (".", {}),
    ])
    rich(doc, [
        (f"Of {k['enabledRules']} enabled correlation rules, ", {}),
        (f"{k['rulesActive']} fired", {"bold": True, "colour": WHITE}), (f" in the last {stale} days, ", {}),
        (f"{k['rulesQuiet']} have gone quiet", {"bold": True, "colour": WHITE}), (" and ", {}),
        (f"{k['rulesNeverFired']} have never fired", {"bold": True, "colour": WHITE}),
        (". Quiet rules are the priority signal for the SOC: a detection that used to fire and has stopped usually means a "
         "log source has dropped, a parser has changed, or the rule logic has drifted away from the environment.", {}),
    ])
    if k.get("rulesAutoDisabled"):
        rich(doc, [(f"{plural(k['rulesAutoDisabled'], 'rule')} ", {"bold": True, "colour": WHITE}),
                   ("have been auto-disabled by the platform and provide no coverage until reviewed.", {})])
    if strongest and weakest:
        rich(doc, [
            ("Coverage is strongest in ", {}),
            (join_names([f"{t['name']} ({t['coveredPct']:.0f}%)" for t in strongest]), {"bold": True, "colour": WHITE}),
            (" and weakest in ", {}),
            (join_names([f"{t['name']} ({t['coveredPct']:.0f}%)" for t in weakest]), {"bold": True, "colour": WHITE}),
            (". Gaps in early-stage tactics give attackers room to establish themselves before anything alerts; gaps late in "
             "the chain mean the first signal may be the impact itself.", {}),
        ])
    if attack and threat_gaps:
        top = threat_gaps[:3]
        who = f"{len(in_sector)} threat groups MITRE associates with {sector}" if sector else f"{len(groups)} threat groups tracked by MITRE ATT&CK"
        rich(doc, [
            (f"Against the {who}, the most widely used techniques without validated coverage are ", {}),
            (join_names([f"{t['name']} ({t['id']})" for t in top]), {"bold": True, "colour": WHITE}),
            (". These are where an intrusion is most likely to go unseen.", {}),
        ])
    hygiene = []
    if k.get("noMitreTag"):
        hygiene.append(f"{plural(k['noMitreTag'], 'enabled rule')} carry no MITRE tags")
    if ctx.get("retired_rule_count"):
        hygiene.append(f"{plural(ctx['retired_rule_count'], 'rule')} reference technique IDs retired in newer ATT&CK releases "
                       f"({', '.join(ctx['retired_ids'])})")
    if hygiene:
        sentence = join_names(hygiene)
        rich(doc, [(sentence[:1].upper() + sentence[1:] + ". ", {"bold": True, "colour": WHITE}),
                   ("These detections may work, but they do not count towards coverage until they are re-mapped.", {})])
    if ctx.get("prev"):
        ch = ctx.get("changes", [])
        counts = {}
        for c in ch:
            counts[c["change"]] = counts.get(c["change"], 0) + 1
        prev_score = ctx["prev"].get("kpis", {}).get("coverageScore")
        delta = f" (score {prev_score} → {score})" if prev_score is not None else ""
        if ch:
            summary = join_names([f"{n} × {name.lower()}" for name, n in counts.items()])
            rich(doc, [(f"Since the last run on {ctx['prev'].get('generatedAt', '')}{delta}: ", {"bold": True, "colour": WHITE}),
                       (summary + ".", {})])
        else:
            rich(doc, [(f"No changes since the last run on {ctx['prev'].get('generatedAt', '')}{delta}.", {"colour": MUTED})])

    if k["rulesNeverFired"] or k["rulesQuiet"]:
        bottom_line = (f"Breadth is {cov_pct}%, proof is {val_pct}%. The fastest, cheapest gain is not new content: it is "
                       f"proving the {k['rulesNeverFired']} never-fired rules with Echo and restoring the {k['rulesQuiet']} that have "
                       f"gone quiet. That alone could lift validated coverage towards {cov_pct}%.")
    else:
        bottom_line = f"Every mapped detection is firing. The next gains come from new content for the uncovered techniques."
    callout(doc, "Bottom line", bottom_line)

    # ============================================================ 02 TACTICS
    section_heading(doc, "02", "Coverage by tactic", "Kill-chain coverage")
    widths = [0.7, 1.75, 0.75, 0.75, 3.15]
    tt = fixed_table(doc, len(tactics) + 1, widths)
    for i, h in enumerate(["ID", "Tactic", "Covered", "Valid.", "Validated (green) + unproven (blue)"]):
        c = tt.rows[0].cells[i]
        shade(c, PANEL_2)
        cell_borders(c, bottom=(LINE, 8))
        cell_margins(c, 70, 70, 100, 100)
        clear_cell(c)
        para(c, h.upper(), 7, MUTED, True, SANS_BOLD, after=0, spacing=0.5)
    for r, tac in enumerate(tactics, start=1):
        cells = tt.rows[r].cells
        for i, c in enumerate(cells):
            shade(c, BG)
            cell_borders(c, bottom=(LINE, 4))
            cell_margins(c, 60, 60, 100, 100)
            c.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            clear_cell(c)
        para(cells[0], tac["id"], 8, MUTED, font=MONO, after=0)
        para(cells[1], tac["name"], 8.5, TEXT, after=0)
        para(cells[2], f"{tac['covered']}/{tac['total']}", 8, TEXT, font=MONO, after=0)
        para(cells[3], f"{tac['validated']}", 8, BAND_HIGH, font=MONO, after=0)
        stacked_bar(cells[4], [(tac["validatedPct"], BAND_HIGH), (tac["coveredPct"] - tac["validatedPct"], ACCENT)],
                    2.9, height_in=0.09)
    para(doc, after=6)

    # ============================================================ 03 DETECTION HEALTH
    section_heading(doc, "03", "Detection health", "Are the detections alive?")
    kpi_tiles(doc, [
        ("Active", k["rulesActive"], f"fired in the last {stale} days", BAND_HIGH, None),
        ("Gone quiet", k["rulesQuiet"], "fired before, silent now - check log sources", BAND_MID, None),
        ("Never fired", k["rulesNeverFired"], "enabled but never proven", BAND_LOW, None),
        ("Auto-disabled", k["rulesAutoDisabled"], "switched off by the platform", RED if k["rulesAutoDisabled"] else LINE, None),
    ])
    if quiet:
        para(doc, "Most recently gone quiet - most likely to be a broken pipeline rather than a rare behaviour:", 9, MUTED,
             after=4).paragraph_format.keep_with_next = True
        rows = []
        for h in quiet[:10]:
            products = ", ".join(rule_products.get(h["ruleName"], [])) or "-"
            rows.append([h["ruleName"], h["lastTriggeredAt"][:10], f"{h['daysSinceLastTrigger']}d", h["timesTriggered"], products])
        data_table(doc, ["Rule", "Last fired", "Silent", "Lifetime", "Log source in rule"], rows, [3.0, 0.95, 0.6, 0.75, 1.8],
                   mono_cols=(1, 2, 3), colour_cols={2: lambda v: BAND_MID})

    # ============================================================ 04 THREAT EXPOSURE
    if attack:
        section_heading(doc, "04", "Threat exposure",
                        f"What attackers targeting {sector} use" if sector else "What attackers use most")
        intro = (f"{len(in_sector)} threat groups in MITRE ATT&CK v{attack['version']} have descriptions associating them with {sector}. "
                 if sector else f"MITRE ATT&CK v{attack['version']} documents technique use by {len(groups)} threat groups. ")
        para(doc, intro + "The techniques below are used by the most of those groups and do not yet have validated coverage.", 9.5, TEXT, after=6)
        rows = [[t["id"], t["name"], f"{threat_count(t)}/{len(in_sector)}", STATUS_LABEL[t["rolled"]], t["rolledScore"]]
                for t in threat_gaps[:12]]
        data_table(doc, ["ID", "Technique", "Groups", "Status", "Score"], rows, [0.75, 3.5, 0.8, 1.35, 0.7],
                   mono_cols=(0, 2, 4), colour_cols={3: lambda v: STATUS_COLOUR[{l: s for s, l in STATUS_LABEL.items()}[v]]})
        if sector:
            sector_groups = sorted(in_sector, key=lambda i: -len(groups[i]["techniques"]))[:8]
            para(doc, "Most active groups associated with the sector: "
                 + ", ".join(groups[i]["name"] for i in sector_groups) + ".", 8.5, MUTED, after=6)
        para(doc, "Sector association is matched from keywords in MITRE's group descriptions; MITRE does not tag groups by sector.",
             7.5, MUTED, italic=True, after=6)

    # ============================================================ 05 ECHO VALIDATION PLAN
    section_heading(doc, "05" if attack else "04", "Validation plan", "Prove it fires - with Echo")
    rich(doc, [
        ("A rule that has never fired is a hypothesis, not a detection. ", {"bold": True, "colour": WHITE}),
        ("Use ", {}), ("Echo", {"bold": True, "colour": WHITE}),
        (" to replay representative raw logs (or PCAPs) for each technique into the pipeline and confirm the full chain end to "
         "end: log source → collector → parser → correlation rule → alert. Every rule proven this way moves its "
         "techniques from unvalidated to validated, and re-running the same Echo use cases after changes gives the SOC a "
         "repeatable regression test for its detection content.", {}),
    ])
    weight = {}
    for h in never:
        techs = rule_techniques.get(h["ruleName"], [])
        weight[h["ruleName"]] = max((threat_count(parents[t]) for t in techs if t in parents), default=0)
    candidates = sorted(never, key=lambda h: (-weight.get(h["ruleName"], 0), -len(rule_techniques.get(h["ruleName"], [])), h["ruleName"]))
    if candidates:
        para(doc, "Recommended Echo replay order (never-fired rules, ranked by the threat activity of the techniques they detect):",
             9, MUTED, after=4).paragraph_format.keep_with_next = True
        rows = []
        for h in candidates[:12]:
            techs = rule_techniques.get(h["ruleName"], [])
            products = rule_products.get(h["ruleName"], [])
            if products:
                action = f"Replay {products[0]} logs"
            elif techs and techs[0] in parents:
                action = f"Emulate {techs[0]} {parents[techs[0]]['name']}"
            elif techs:
                action = f"Emulate {techs[0]}"
            else:
                action = "Build a use case for the rule logic"
            rows.append([h["ruleName"], ", ".join(techs[:3]) or "-", weight.get(h["ruleName"], 0) if attack else "-", action])
        data_table(doc, ["Rule", "Techniques", "Groups", "Echo action"], rows, [3.1, 1.25, 0.65, 2.1], mono_cols=(1, 2))
    else:
        para(doc, "Every enabled rule has fired at least once. Schedule Echo regression runs to keep it that way.", 9.5, after=6)

    # ============================================================ 06 ACTIONS
    section_heading(doc, "06" if attack else "05", "Recommended actions", "Next 30 days")
    actions = []
    if quiet:
        actions.append(("Restore quiet detections",
                        f"Investigate the {k['rulesQuiet']} rules that have stopped firing, starting with "
                        f"{join_names([q['ruleName'] for q in quiet[:3]])}. Confirm the log sources are still sending and parsing."))
    if never:
        actions.append(("Validate with Echo",
                        f"Run Echo replays for the {k['rulesNeverFired']} never-fired rules in the order above. Target: "
                        f"validated coverage from {val_pct}% towards {cov_pct}%."))
    if attack and threat_gaps:
        uncovered = [t for t in threat_gaps if t["rolled"] == "none"][:3]
        if uncovered:
            names = join_names([t["name"] + " (" + t["id"] + ")" for t in uncovered])
            target = f" - used by the most groups targeting {sector}" if sector else ""
            actions.append(("Close the highest-threat gaps", f"Build or enable content for {names}{target}."))
    if ctx.get("retired_rule_count"):
        actions.append(("Re-map retired techniques",
                        f"Update the {ctx['retired_rule_count']} rules tagged with retired IDs ({', '.join(ctx['retired_ids'])}) "
                        "to their current ATT&CK equivalents so they count towards coverage."))
    if k.get("noMitreTag"):
        actions.append(("Tag untagged rules", f"Add MITRE mappings to the {k['noMitreTag']} enabled rules that have none."))
    actions.append(("Track it", "Re-run this report on a schedule (for example weekly) so rules that stop firing are caught "
                                "within days, not discovered during an incident."))
    for i, (title, text) in enumerate(actions, start=1):
        rich(doc, [(f"{i}.  ", {"font": SANS_BOLD, "colour": GREEN, "bold": True}),
                   (title + ".  ", {"font": SANS_BOLD, "colour": WHITE, "bold": True}),
                   (text, {})], after=6)

    # ============================================================ METHODOLOGY
    section_heading(doc, "07" if attack else "06", "Methodology", "How to read this briefing")
    for text in [
        f"Technique score (0-100): Validated (a mapped rule fired in the last {stale} days) 75-100; Quiet (fired before, not "
        "recently) 50-74; Unvalidated (never fired) 20-49; Not covered 0. Each additional rule in the same state adds 5 points "
        "within its band. A parent technique takes the best score of its own and its sub-techniques' rules.",
        "Coverage Score: the average technique score across all ATT&CK techniques - the same aggregation the Exabeam Outcomes "
        "Navigator uses. It measures proven detection, so it is deliberately lower than raw mapping coverage.",
        "Sources: Exabeam correlation rules API (rules, trigger history, MITRE mappings), Exabeam MITRE technique list, and the "
        "MITRE ATT&CK Enterprise dataset for threat groups. Only enabled correlation rules are counted.",
        "The interactive HTML report produced alongside this document contains the full matrix, every rule and technique, and "
        "lets each reader tailor the view to their sector and platforms.",
    ]:
        para(doc, text, 8.5, MUTED, after=5)
    para(doc, MITRE_NOTICE, 6.5, "9AA1AC", after=0, before=10, line=1.2)

    doc.save(path)
