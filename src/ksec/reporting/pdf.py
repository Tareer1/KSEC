"""Minimal zero-dependency PDF writer (report PDF export).

KSEC has no third-party dependencies, so PDF export is produced by a tiny
hand-rolled writer: Helvetica text on A4 pages, latin-1 safe, multi-page.
Enough for printable executive reports without pulling in a library.
"""
from __future__ import annotations

import zlib

_PAGE_WIDTH = 595  # A4 portrait (points)
_PAGE_HEIGHT = 842
_MARGIN = 50
_FONT_SIZE = 10
_LINE_HEIGHT = 14
_MAX_COLS = 100


def _sanitize(text: str) -> str:
    """Coerce text to latin-1-representable ASCII-ish output for PDF."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\t":
            out.append(" " * 4)
        elif 32 <= code < 127 or code in (0x0A, 0x0D):
            out.append(char)
        elif char in ("–", "—", "•", "·", "’", "‘", "“", "”", "…", "°"):
            out.append({"–": "-", "—": "-", "•": "-", "·": "-", "’": "'",
                        "‘": "'", "“": '"', "”": '"', "…": "...", "°": "deg"}[char])
        else:
            out.append("?")
    return "".join(out)


def _wrap(line: str, width: int = _MAX_COLS) -> list[str]:
    if len(line) <= width:
        return [line]
    out: list[str] = []
    while len(line) > width:
        cut = line.rfind(" ", 0, width + 1)
        if cut <= 0:
            cut = width
        out.append(line[:cut])
        line = line[cut:].lstrip()
    if line:
        out.append(line)
    return out


def _escape_pdf_text(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _layout_lines(text: str, max_cols: int = _MAX_COLS) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        if not raw.strip():
            lines.append("")
            continue
        for wrapped in _wrap(raw.rstrip(), max_cols):
            lines.append(wrapped)
    return lines


def render_pdf(text: str, title: str = "KSEC Report") -> bytes:
    """Render ``text`` into a valid multi-page A4 PDF (pure stdlib)."""
    title_line = _sanitize(title or "KSEC Report")
    lines = [title_line, "=" * min(len(title_line), _MAX_COLS), ""] + _layout_lines(
        _sanitize(text)
    )
    lines_per_page = (_PAGE_HEIGHT - 2 * _MARGIN) // _LINE_HEIGHT
    pages: list[list[str]] = []
    for start in range(0, len(lines), lines_per_page):
        pages.append(lines[start : start + lines_per_page])

    # Build objects: 1 catalog, 2 pages root, then per page:
    #   page obj, content obj; one shared font obj.
    objects: list[bytes] = []
    page_refs: list[tuple[int, int]] = []  # (page_obj_num, content_obj_num)
    content_streams: list[bytes] = []

    for page_lines in pages:
        stream_lines = ["BT", f"/F1 {_FONT_SIZE} Tf", f"{_MARGIN} {_PAGE_HEIGHT - 40} Td"]
        y = 0
        for line in page_lines:
            if not line:
                y += _LINE_HEIGHT
                continue
            if y + _LINE_HEIGHT > _PAGE_HEIGHT - 2 * _MARGIN:
                break
            stream_lines.append(f"0 -{_LINE_HEIGHT} Td")
            stream_lines.append(f"({_escape_pdf_text(line)}) Tj")
            y += _LINE_HEIGHT
        stream_lines.append("ET")
        content = "\n".join(stream_lines).encode("latin-1", "replace")
        content_streams.append(content)

    # object numbering: 1=catalog, 2=pages, 3=font, then pairs
    font_num = 3
    next_num = 4
    for content in content_streams:
        page_refs.append((next_num, next_num + 1))
        next_num += 2
    total_objects = next_num  # next free object number

    buf: list[bytes] = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
    offsets: list[int] = []

    def add_object(num: int, body: bytes) -> None:
        offsets.append((num, _tell()))
        buf.append(f"{num} 0 obj\n".encode())
        buf.append(body)
        buf.append(b"\nendobj\n")

    def _tell() -> int:
        return sum(len(part) for part in buf)

    add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{p} 0 R" for p, _ in page_refs)
    add_object(2, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_refs)} >>".encode())
    add_object(font_num, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for (page_num, content_num), stream in zip(page_refs, content_streams):
        add_object(
            page_num,
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_WIDTH} {_PAGE_HEIGHT}]"
                f" /Resources << /Font << /F1 {font_num} 0 R >> >>"
                f" /Contents {content_num} 0 R >>"
            ).encode(),
        )
        compressed = zlib.compress(stream)
        add_object(
            content_num,
            (
                f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n"
            ).encode()
            + compressed
            + b"\nendstream",
        )

    xref_pos = _tell()
    buf.append(b"xref\n")
    buf.append(f"0 {total_objects}\n".encode())
    buf.append(b"0000000000 65535 f \n")
    offset_map = dict(offsets)
    for num in range(1, total_objects):
        buf.append(f"{offset_map.get(num, 0):010d} 00000 n \n".encode())
    buf.append(
        (
            f"trailer\n<< /Size {total_objects} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode()
    )
    return b"".join(buf)
