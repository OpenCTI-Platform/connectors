import hashlib
import html
import re


def extract_passwords(
    body: str,
    prefix: str,
    suffix: str,
    strip_whitespace: bool = False,
) -> list[str]:
    """Extract passwords from email body using configurable prefix/suffix markers.

    If strip_whitespace is True, all spaces, tabs, and newlines are removed from
    the extracted password (useful when HTML rendering or email wrapping inserts
    whitespace within the password).
    """
    if not prefix or not suffix:
        return []
    # Decode HTML entities in the body first
    decoded_body = html.unescape(body)
    # Escape prefix/suffix for regex safety
    pattern = re.escape(prefix) + r"(.+?)" + re.escape(suffix)
    matches = re.findall(pattern, decoded_body, re.DOTALL)
    results = []
    for m in matches:
        pwd = m.strip()
        if strip_whitespace:
            pwd = re.sub(r"\s+", "", pwd)
        if pwd:
            results.append(pwd)
    return results


def normalize_subject(subject: str) -> str:
    """Strip RE:/FW:/FWD: prefixes and normalize whitespace for thread matching.

    Handles common localized prefixes:
      EN: RE, FW, FWD   DE: AW, WG   FR: TR   ES: RV   NL: Doorst
      IT: I, R           PT: ENC, RES  NO/SV: SV, VS
    """
    if not subject:
        return ""
    # Covers English + common localized reply/forward prefixes
    pattern = r"^(RE|FW|FWD|AW|WG|TR|RV|I|R|ENC|RES|SV|VS|Doorst)\s*:\s*"
    cleaned = re.sub(pattern, "", subject.strip(), flags=re.IGNORECASE)
    # Recursively strip in case of multiple prefixes (RE: FW: RE: ...)
    while cleaned != subject:
        subject = cleaned
        cleaned = re.sub(pattern, "", subject.strip(), flags=re.IGNORECASE)
    return cleaned.strip()


def collapse_blank_lines(text: str) -> str:
    """Collapse runs of 3+ consecutive newlines down to 2 (one blank line).

    Outlook and gateway-rewritten HTML emails often translate to plain text
    with dozens of consecutive blank lines (nested <div>/<p>/<br>). This keeps
    paragraph breaks (a single blank line) but removes the visual explosion.
    """
    if not text:
        return text
    # Normalize line endings first so \r\n and \r don't defeat the regex
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Treat whitespace-only lines as blank
    text = re.sub(r"[ \t]+\n", "\n", text)
    # 3+ newlines -> exactly 2 (one blank line between paragraphs)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def sanitize_html(html_content: str) -> str:
    """Convert HTML email body to plain text, preserving structure."""
    if not html_content:
        return ""
    # Remove style and script tags and their content
    text = re.sub(r"<style[^>]*>.*?</style>", "", html_content, flags=re.DOTALL)
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
    # Convert br and p tags to newlines
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</div>", "\n", text, flags=re.IGNORECASE)
    # Remove remaining HTML tags
    text = re.sub(r"<[^>]+>", "", text)
    # Decode HTML entities
    text = html.unescape(text)
    # Normalize whitespace (preserve newlines)
    lines = text.split("\n")
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in lines]
    # Collapse blank-line explosions from nested <div>/<br>/<p>
    return collapse_blank_lines("\n".join(lines))


def compute_file_hashes(data: bytes) -> dict[str, str]:
    """Compute MD5, SHA-1, and SHA-256 hashes for file data."""
    return {
        "MD5": hashlib.md5(data).hexdigest(),  # noqa: S324
        "SHA-1": hashlib.sha1(data).hexdigest(),  # noqa: S324
        "SHA-256": hashlib.sha256(data).hexdigest(),
    }


def matches_subject_filter(subject: str, filters: list[dict]) -> bool:
    """Check if a subject matches any of the configured filters.

    An empty filter list means "accept any subject". This is the intuitive
    reading of "no filter configured"; the alternative (empty = match nothing)
    silently drops every email and is a config footgun.
    """
    if not filters:
        return True
    for f in filters:
        filter_type = f.get("type", "")
        value = f.get("value", "")
        if filter_type == "exact" and subject == value:
            return True
        if filter_type == "contains" and value in subject:
            return True
        if filter_type == "regex":
            try:
                if re.search(value, subject):
                    return True
            except re.error:
                continue
    return False
