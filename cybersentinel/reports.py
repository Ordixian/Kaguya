"""Alert-history reports: PDF, Word (.docx) and CSV, standard library only.

`build_report()` gathers alerts for a time window and pairs each with its
plain-English explanation; the `render_*` functions turn that into bytes.
The PDF writer is deliberately tiny (core Helvetica/Courier fonts, wrapped
text, page breaks) so Kaguya keeps zero required dependencies.
"""

from __future__ import annotations

import csv
import io
import socket
import time
import zipfile
from collections import Counter
from datetime import datetime
from xml.sax.saxutils import escape as xesc

from .explain import explain_alert, health_score, quick_summary

PERIODS = {            # name -> (seconds, label)
    "hour": (3600, "Last hour"),
    "6h": (6 * 3600, "Last 6 hours"),
    "day": (86400, "Last 24 hours"),
    "week": (7 * 86400, "Last 7 days"),
    "month": (30 * 86400, "Last 30 days"),
    "quarter": (90 * 86400, "Last 90 days"),
    "year": (365 * 86400, "Last 365 days"),
    "all": (None, "All recorded history"),
}
FORMATS = {
    "pdf": ("application/pdf", "pdf"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    "csv": ("text/csv; charset=utf-8", "csv"),
}
MAX_ALERTS = 2000
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RGB = {"critical": (0.80, 0.10, 0.10), "high": (0.92, 0.40, 0.05),
           "medium": (0.85, 0.60, 0.05), "low": (0.10, 0.55, 0.80),
           "info": (0.25, 0.45, 0.85)}


def _fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def resolve_window(period, start=None, end=None, now=None):
    """Return (since, until, label). `start`/`end` are epoch seconds for custom ranges."""
    now = now or time.time()
    if start is not None or end is not None:
        s = float(start) if start is not None else 0.0
        e = float(end) if end is not None else now
        if e < s:
            s, e = e, s
        return s, e, f"{_fmt(s)} to {_fmt(e)}" if s else f"Up to {_fmt(e)}"
    if period not in PERIODS:
        raise ValueError(f"unknown period '{period}'")
    secs, label = PERIODS[period]
    return (now - secs if secs else 0.0), now, label


def build_report(storage, period="day", start=None, end=None, host=None):
    since, until, label = resolve_window(period, start, end)
    alerts = storage.alerts_between(since, until, limit=MAX_ALERTS + 1)
    truncated = len(alerts) > MAX_ALERTS
    alerts = alerts[:MAX_ALERTS]
    items = []
    for a in alerts:
        d = {"id": a.id, "ts": a.ts, "rule": a.rule, "title": a.title,
             "severity": a.severity.label, "description": a.description,
             "host": a.host, "status": a.status, "data": a.data}
        d["explain"] = explain_alert(d)
        items.append(d)
    issues = []
    for a in storage.distinct_open_alerts():
        issues.append({"rule": a.rule, "title": a.title, "severity": a.severity.label, "data": a.data})
    open_by_sev = storage.distinct_open_by_severity()
    health = health_score(open_by_sev)
    return {
        "health": health, "open_by_severity": open_by_sev,
        "quick": quick_summary(issues, health), "open_issues": len(issues),
        "label": label, "since": since, "until": until, "truncated": truncated,
        "generated": time.time(), "host": host or socket.gethostname(),
        "total": len(items),
        "by_severity": dict(Counter(i["severity"] for i in items)),
        "by_status": dict(Counter(i["status"] for i in items)),
        "by_rule": Counter(i["rule"] for i in items).most_common(),
        "alerts": items,
    }


def summary_text(rep, open_by_severity=None):
    """Short plain-text digest for chat / email bodies."""
    q = rep["quick"]
    lines = [q["vibe"], f"Host {rep['host']} - {rep['label']}", ""]
    if rep["total"]:
        sev = ", ".join(f"{s} {rep['by_severity'][s]}" for s in SEV_ORDER if s in rep["by_severity"])
        lines.append(f"{rep['total']} alert(s) in this period: {sev}.")
    else:
        lines.append("No new alerts in this period.")
    lines += ["", "Recommended action rn:"] + [f"- {x}" for x in q["actions"]]
    lines += ["", "Full breakdown (causes + fix steps) is in the attached PDF."]
    return "\n".join(lines)


def filename(rep, ext):
    stamp = datetime.fromtimestamp(rep["generated"]).strftime("%Y%m%d-%H%M")
    return f"kaguya-alert-report-{stamp}.{ext}"


# --- shared layout model ---------------------------------------------------
# A document is a flat list of blocks:
#   ("title", text) ("h1", text) ("h2", text) ("p", text) ("bullet", text)
#   ("code", text)  ("sev", severity, text)  ("gap",)

def _blocks(rep):
    b = [("title", "Kaguya - Alert History Report"),
         ("p", f"Period: {rep['label']}"),
         ("p", f"Host: {rep['host']}    Generated: {_fmt(rep['generated'])}"),
         ("gap",),
         ("h1", "Summary"),
         ("p", f"{rep['total']} alert(s) in this period." +
               (f" (Showing the newest {MAX_ALERTS}; narrow the date range to see the rest.)"
                if rep["truncated"] else ""))]
    if rep["total"]:
        sev = [f"{s}: {rep['by_severity'][s]}" for s in SEV_ORDER if s in rep["by_severity"]]
        b.append(("bullet", "By severity - " + ", ".join(sev)))
        b.append(("bullet", "By status - " + ", ".join(f"{k}: {v}" for k, v in sorted(rep["by_status"].items()))))
        b.append(("bullet", "Most common causes - " + ", ".join(f"{r} ({n})" for r, n in rep["by_rule"][:5])))
    else:
        b.append(("p", "No new alerts were raised in this period. (Older issues that are still open are covered in the quick summary below.)"))
    b.append(("gap",))
    q = rep["quick"]
    b.append(("h1", "Quick summary: what to do rn"))
    b.append(("p", f"{q['vibe']} (Health: {rep['health']['title']}, {rep['health']['score']}/100)"))
    b.extend(("bullet", x) for x in q["actions"])
    b.append(("gap",))
    if rep["total"]:
        b.append(("h1", "Alerts (newest first)"))
    for i, a in enumerate(rep["alerts"], 1):
        ex = a["explain"]
        b.append(("sev", a["severity"], f"{i}. [{a['severity'].upper()}] {a['title']}"))
        b.append(("p", f"{_fmt(a['ts'])}  |  status: {a['status']}  |  rule: {a['rule']}  |  host: {a['host']}"))
        b.append(("h2", "What this means"))
        b.append(("p", ex["what"]))
        b.append(("h2", "What probably caused it"))
        b.extend(("bullet", c) for c in ex["cause"])
        b.append(("h2", "How worried should I be?"))
        b.append(("p", ex["risk"] + f" It is probably fine if {ex['safe_if']}"))
        b.append(("h2", "How to fix it"))
        for n, step in enumerate(ex["fix"], 1):
            b.append(("bullet", f"Step {n}: {step['text']}"))
            if step.get("cmd"):
                b.append(("code", step["cmd"]))
        b.append(("gap",))
    return b


# --- CSV -------------------------------------------------------------------

def render_csv(rep):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "severity", "status", "rule", "title", "host",
                "what_it_means", "likely_cause", "how_to_fix"])
    for a in rep["alerts"]:
        ex = a["explain"]
        w.writerow([_fmt(a["ts"]), a["severity"], a["status"], a["rule"], _csv_safe(a["title"]),
                    a["host"], _csv_safe(ex["what"]), _csv_safe(" / ".join(ex["cause"])),
                    _csv_safe(" | ".join(s["text"] + (f" [{s['cmd']}]" if s.get("cmd") else "")
                                         for s in ex["fix"]))])
    return out.getvalue().encode("utf-8-sig")


def _csv_safe(v):
    """Neutralise spreadsheet formula injection (titles can carry attacker text)."""
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


# --- DOCX ------------------------------------------------------------------

def _run(text, bold=False, size=22, color=None, mono=False):
    rpr = ""
    if mono:
        rpr += '<w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/>'
    if bold:
        rpr += "<w:b/>"
    if color:
        rpr += f'<w:color w:val="{color}"/>'
    rpr += f'<w:sz w:val="{size}"/>'
    return f'<w:r><w:rPr>{rpr}</w:rPr><w:t xml:space="preserve">{xesc(_xml_clean(text))}</w:t></w:r>'


def _xml_clean(s):
    """Drop characters that are illegal in XML 1.0."""
    return "".join(ch for ch in s if ch in "\t\n\r" or ord(ch) >= 0x20 and ord(ch) not in (0xFFFE, 0xFFFF)
                   and not 0xD800 <= ord(ch) <= 0xDFFF)


def _para(runs, before=0, after=80, indent=0, shade=None):
    ppr = f'<w:spacing w:before="{before}" w:after="{after}"/>'
    if indent:
        ppr += f'<w:ind w:left="{indent}"/>'
    if shade:
        ppr += f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>'
    return f"<w:p><w:pPr>{ppr}</w:pPr>{runs}</w:p>"


def render_docx(rep):
    body = []
    for blk in _blocks(rep):
        kind = blk[0]
        if kind == "title":
            body.append(_para(_run(blk[1], True, 40, "3B2F8F"), after=120))
        elif kind == "h1":
            body.append(_para(_run(blk[1], True, 30, "3B2F8F"), before=200, after=100))
        elif kind == "h2":
            body.append(_para(_run(blk[1], True, 22, "555555"), before=100, after=40))
        elif kind == "sev":
            rgb = "".join(f"{int(c * 255):02X}" for c in SEV_RGB.get(blk[1], (0, 0, 0)))
            body.append(_para(_run(blk[2], True, 26, rgb), before=240, after=60))
        elif kind == "p":
            body.append(_para(_run(blk[1])))
        elif kind == "bullet":
            body.append(_para(_run("•  " + blk[1]), indent=360, after=40))
        elif kind == "code":
            body.append(_para(_run(blk[1], size=19, mono=True), indent=720, after=60, shade="F1F1F6"))
        else:
            body.append(_para("", after=60))
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                '<w:body>' + "".join(body) +
                '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
                '<w:pgMar w:top="1000" w:right="1000" w:bottom="1000" w:left="1000" '
                'w:header="500" w:footer="500" w:gutter="0"/></w:sectPr></w:body></w:document>')
    content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                     '<Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
                     'officedocument.wordprocessingml.document.main+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="word/document.xml"/></Relationships>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document)
    return buf.getvalue()


# --- PDF -------------------------------------------------------------------
# Helvetica advance widths for ASCII 32..126 (per 1000 em)
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
         556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
         1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
         333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
         556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]

_PAGE_W, _PAGE_H, _MARGIN = 595, 842, 48


def _pdf_text(s):
    """Latin-1-safe text (core PDF fonts); anything else becomes '?'."""
    return "".join(ch if 32 <= ord(ch) < 127 or 160 <= ord(ch) < 256 else
                   ("?" if ord(ch) >= 127 else " ") for ch in s.replace("\t", "    "))


def _width(s, size, mono=False, bold=False):
    if mono:
        return len(s) * 600 * size / 1000
    w = sum(_HELV[ord(c) - 32] if 32 <= ord(c) < 127 else 556 for c in s)
    return w * size / 1000 * (1.07 if bold else 1)


def _wrap(text, size, max_w, mono=False, bold=False):
    out = []
    for para in text.split("\n"):
        if mono:                                      # break anywhere
            per = max(1, int(max_w / (600 * size / 1000)))
            out.extend([para[i:i + per] for i in range(0, len(para), per)] or [""])
            continue
        line = ""
        for word in para.split(" "):
            while _width(word, size, bold=bold) > max_w:   # very long token
                cut = max(1, int(len(word) * max_w / _width(word, size, bold=bold)))
                if line:
                    out.append(line); line = ""
                out.append(word[:cut]); word = word[cut:]
            trial = f"{line} {word}" if line else word
            if _width(trial, size, bold=bold) <= max_w:
                line = trial
            else:
                out.append(line); line = word
        out.append(line)
    return out


def _esc_pdf(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf(rep):
    pages, cur = [], []
    y = [_PAGE_H - _MARGIN]
    text_w = _PAGE_W - 2 * _MARGIN

    def new_page():
        nonlocal cur
        pages.append(cur)
        cur = []
        y[0] = _PAGE_H - _MARGIN

    def put(lines, size, font, indent=0, color=(0, 0, 0), lead=1.3, shade=None):
        for ln in lines:
            h = size * lead
            if y[0] - h < _MARGIN:
                new_page()
            y[0] -= h
            if shade:
                cur.append(f"{shade[0]} {shade[1]} {shade[2]} rg "
                           f"{_MARGIN + indent - 3} {y[0] - 2.5:.1f} {text_w - indent + 6} {h:.1f} re f")
            cur.append(f"BT /{font} {size} Tf {color[0]} {color[1]} {color[2]} rg "
                       f"{_MARGIN + indent:.1f} {y[0]:.1f} Td ({_esc_pdf(_pdf_text(ln))}) Tj ET")

    for blk in _blocks(rep):
        k = blk[0]
        if k == "title":
            put(_wrap(blk[1], 22, text_w, bold=True), 22, "F2", color=(0.23, 0.18, 0.56)); y[0] -= 4
        elif k == "h1":
            if y[0] < _MARGIN + 80: new_page()
            y[0] -= 8; put(_wrap(blk[1], 15, text_w, bold=True), 15, "F2", color=(0.23, 0.18, 0.56))
        elif k == "h2":
            if y[0] < _MARGIN + 50: new_page()
            y[0] -= 3; put(_wrap(blk[1], 9.5, text_w, bold=True), 9.5, "F2", color=(0.35, 0.35, 0.4))
        elif k == "sev":
            if y[0] < _MARGIN + 110: new_page()
            y[0] -= 8
            rgb = SEV_RGB.get(blk[1], (0, 0, 0))
            cur.append(f"{rgb[0]} {rgb[1]} {rgb[2]} rg {_MARGIN} {y[0] - 14:.1f} 4 14 re f")
            put(_wrap(blk[2], 11.5, text_w - 12, bold=True), 11.5, "F2", indent=10, color=rgb)
        elif k == "p":
            put(_wrap(blk[1], 10, text_w), 10, "F1")
        elif k == "bullet":
            lines = _wrap(blk[1], 10, text_w - 16)
            put(["- " + lines[0]] + ["  " + l for l in lines[1:]], 10, "F1", indent=8)
        elif k == "code":
            put(_wrap(blk[1], 8.5, text_w - 40, mono=True), 8.5, "F3", indent=24,
                color=(0.1, 0.1, 0.2), lead=1.45, shade=(0.94, 0.94, 0.97))
        else:
            y[0] -= 8
    pages.append(cur)

    objs = []                                    # 1-indexed object bodies (bytes)

    def add(body):
        objs.append(body if isinstance(body, bytes) else body.encode("latin-1"))
        return len(objs)

    add("<< /Type /Catalog /Pages 2 0 R >>")      # 1
    add("")                                        # 2 (patched below)
    for name, base in (("F1", "Helvetica"), ("F2", "Helvetica-Bold"), ("F3", "Courier")):
        add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>")  # 3,4,5
    kids = []
    total = len(pages)
    for n, ops in enumerate(pages, 1):
        footer = (f"BT /F1 8 Tf 0.5 0.5 0.55 rg {_MARGIN} 28 Td "
                  f"(Kaguya alert report - page {n} of {total}) Tj ET")
        stream = ("\n".join(ops) + "\n" + footer).encode("latin-1", "replace")
        c = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        p = add(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {c} 0 R >>")
        kids.append(p)
    objs[1] = (f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>").encode()
    info = add("<< /Title (Kaguya Alert History Report) /Producer (Kaguya) >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += (b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objs) + 1, info, xref))
    return bytes(out)


def render(rep, fmt):
    if fmt == "pdf":
        return render_pdf(rep)
    if fmt == "docx":
        return render_docx(rep)
    if fmt == "csv":
        return render_csv(rep)
    raise ValueError(f"unknown format '{fmt}'")
