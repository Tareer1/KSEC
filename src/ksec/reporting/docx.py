"""Minimal zero-dependency DOCX writer (report export).

Produces a valid Office Open XML ``.docx`` from plain markdown-ish text using
only the Python standard library (``zipfile``). Headings (``#``/``##``),
bullets (``-``) and ``**bold**`` spans are mapped to Word styles; everything
else becomes body paragraphs. Good enough for editable executive reports
without pulling in a library.
"""
from __future__ import annotations

import re
import zipfile
from io import BytesIO

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _runs(text: str) -> str:
    """Convert markdown-ish inline spans into Word run XML."""
    text = _escape(text)
    parts: list[str] = []

    def append(fragment: str, bold: bool = False) -> None:
        fragment = _INLINE_CODE_RE.sub(
            lambda m: (
                f'<w:r><w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/>'
                f"</w:rPr><w:t>{m.group(1)}</w:t></w:r>"
            ),
            fragment,
        )
        if bold:
            parts.append(f"<w:r><w:rPr><w:b/></w:rPr><w:t>{fragment}</w:t></w:r>")
        else:
            parts.append(f"<w:r><w:t xml:space=\"preserve\">{fragment}</w:t></w:r>")

    pos = 0
    for match in _BOLD_RE.finditer(text):
        append(text[pos : match.start()])
        append(match.group(1), bold=True)
        pos = match.end()
    append(text[pos:])
    return "".join(parts)


def _paragraph(text: str, style: str | None = None) -> str:
    style_xml = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f"<w:p>{style_xml}{_runs(text)}</w:p>"


def _render_body(markdown_text: str) -> str:
    paragraphs: list[str] = []
    for raw in markdown_text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.startswith("### "):
            paragraphs.append(_paragraph(line[4:], "Heading3"))
        elif line.startswith("## "):
            paragraphs.append(_paragraph(line[3:], "Heading2"))
        elif line.startswith("# "):
            paragraphs.append(_paragraph(line[2:], "Heading1"))
        elif line.startswith("- "):
            paragraphs.append(_paragraph(line[2:], "ListBullet"))
        else:
            paragraphs.append(_paragraph(line))
    return "".join(paragraphs)


_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:spacing w:before="200" w:after="100"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:pPr><w:spacing w:before="160" w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:pPr><w:ind w:left="360"/></w:pPr></w:style>
</w:styles>"""


def render_docx(markdown_text: str, title: str = "KSEC Report") -> bytes:
    """Render ``markdown_text`` into a minimal valid .docx (pure stdlib)."""
    title_xml = _paragraph(_escape(title or "KSEC Report"), "Heading1")
    body = _render_body(markdown_text)
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{title_xml}{body}</w:body></w:document>"
    )

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES)
        archive.writestr("_rels/.rels", _RELS)
        archive.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        archive.writestr("word/document.xml", document)
        archive.writestr("word/styles.xml", _STYLES)
    return buffer.getvalue()