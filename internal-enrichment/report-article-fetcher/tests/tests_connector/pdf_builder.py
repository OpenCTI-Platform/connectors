"""Build small text PDFs for the tests, without a PDF writer dependency."""


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(pages: list[list[str]]) -> bytes:
    """A PDF with one page per list, one text line per string (cp1252)."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        None,  # the page tree, written once the pages are numbered
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica"
        b" /Encoding /WinAnsiEncoding >>",
    ]
    kids = []
    for lines in pages:
        stream = "BT /F1 10 Tf 14 TL 50 780 Td\n"
        stream += "".join(f"({_escape(line)}) Tj T*\n" for line in lines)
        stream += "ET"
        content = stream.encode("cp1252")
        objects.append(
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"
        )
        content_ref = len(objects)
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]"
            b" /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>" % content_ref
        )
        kids.append(len(objects))
    objects[1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
        b" ".join(b"%d 0 R" % kid for kid in kids),
        len(kids),
    )
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)
