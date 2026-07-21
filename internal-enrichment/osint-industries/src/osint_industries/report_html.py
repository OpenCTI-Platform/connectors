# -*- coding: utf-8 -*-
"""
Builds a self-contained HTML report (cards) from the OSINT Industries
enrichment summary. The HTML is then attached to the source observable via
AssociatedFile (the SDK associated_files field), so it is visible under the
Data/Files tab of the observable in OpenCTI.

The structure and CSS are inline. Only the profile pictures are loaded from
their remote URL (falling back to an icon when unavailable), so the report is
not fully offline.
"""

from __future__ import annotations

import datetime
import html
from typing import Any

# Fields not repeated in the card body (already in the card header or not
# useful). picture_url/logo are rendered as a thumbnail, not as text.
_HIDDEN_FIELDS = {
    "registered",
    "username",
    "name",
    "full_name",
    "picture_url",
    "logo",
}

# Candidate keys for the thumbnail, by priority.
_IMAGE_KEYS = ("picture_url", "logo", "avatar", "photo", "image")


def _image_url(flat: dict) -> str | None:
    """Return the first http(s) image URL found, otherwise None."""
    for key in _IMAGE_KEYS:
        v = flat.get(key)
        if isinstance(v, str) and v.startswith("http"):
            return v
    return None


def _avatar(flat: dict) -> str:
    """Round thumbnail: <img> if a URL is found (with automatic fallback to
    the icon if the image breaks), otherwise a default SVG icon."""
    default_icon = (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" '
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        'stroke-linejoin="round"><circle cx="12" cy="8" r="4"></circle>'
        '<path d="M4 20c0-4 4-6 8-6s8 2 8 6"></path></svg>'
    )
    url = _image_url(flat)
    if url:
        # onerror: if the image fails to load (expired link / blocked
        # hotlink), hide the <img> and reveal the fallback icon behind it.
        return (
            '<span class="avatar">'
            '<img src="%s" alt="" referrerpolicy="no-referrer" '
            "onerror=\"this.style.display='none';"
            "this.nextElementSibling.style.display='flex';\">"
            '<span class="avatar-fallback" style="display:none">%s</span>'
            "</span>"
        ) % (_esc(url), default_icon)
    return (
        '<span class="avatar"><span class="avatar-fallback" '
        'style="display:flex">%s</span></span>' % default_icon
    )


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _stringify(value: Any) -> str:
    """Flatten lists/dicts for display (ssh_keys, used_services...)."""
    if isinstance(value, list):
        items = []
        for it in value:
            if isinstance(it, dict):
                items.append(", ".join("%s=%s" % (k, v) for k, v in it.items()))
            else:
                items.append(str(it))
        return " · ".join(items)
    if isinstance(value, dict):
        return ", ".join("%s=%s" % (k, v) for k, v in value.items())
    return str(value)


def _card(entry: dict) -> str:
    module = _esc(entry["module"])
    title = _esc(entry.get("shown") or entry["module"])
    flat = entry["flat"]

    rows = []
    for k, v in flat.items():
        if k in _HIDDEN_FIELDS:
            continue
        if v in (None, "", [], {}):
            continue
        rows.append(
            '<div class="row"><span class="k">%s</span>'
            '<span class="v">%s</span></div>' % (_esc(k), _esc(_stringify(v)))
        )

    body = (
        "".join(rows) if rows else '<div class="empty">Registered — no extra data</div>'
    )

    return (
        '<article class="card">'
        '<header class="card-h">'
        "%s"
        '<span class="card-id">'
        '<span class="module">%s</span>'
        '<span class="title">%s</span>'
        "</span>"
        "</header>"
        '<div class="card-b">%s</div>'
        "</article>"
    ) % (_avatar(flat), module, title, body)


def build_report_html(selector: str, summary: list[dict]) -> str:
    """Build the full HTML. summary = list of entries
    {module, shown, flat, ...} (already filtered of breach modules)."""
    generated = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    cards = "".join(_card(e) for e in sorted(summary, key=lambda x: x["module"]))
    count = len(summary)

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Industries report — %(selector)s</title>
<style>
  :root{--bg:#0f1115;--card:#1a1d24;--line:#2a2e37;--txt:#e6e8ec;
        --muted:#8b909a;--accent:#4f8cff;--chip:#222732;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
  h1{font-size:20px;margin:0 0 4px}
  .sub{color:var(--muted);font-size:13px;margin-bottom:24px}
  .sel{color:var(--accent);font-weight:600}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
        gap:16px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;
        overflow:hidden}
  .card-h{display:flex;align-items:center;gap:12px;padding:12px 14px;
          border-bottom:1px solid var(--line);background:#171a21}
  .avatar{width:44px;height:44px;border-radius:50%%;flex-shrink:0;
          overflow:hidden;background:var(--chip);display:flex;
          align-items:center;justify-content:center}
  .avatar img{width:100%%;height:100%%;object-fit:cover;display:block}
  .avatar-fallback{align-items:center;justify-content:center;
                   width:100%%;height:100%%;color:var(--muted)}
  .card-id{display:flex;flex-direction:column;gap:3px;min-width:0}
  .module{font-size:11px;text-transform:uppercase;letter-spacing:.06em;
           color:var(--accent);white-space:nowrap}
  .title{font-weight:600;word-break:break-all}
  .card-b{padding:10px 14px}
  .row{display:flex;gap:10px;padding:5px 0;border-bottom:1px dashed #232733}
  .row:last-child{border-bottom:0}
  .k{color:var(--muted);min-width:120px;text-transform:capitalize}
  .v{word-break:break-word}
  .empty{color:var(--muted);font-style:italic;padding:6px 0}
  footer{margin-top:28px;color:var(--muted);font-size:12px;
         border-top:1px solid var(--line);padding-top:14px}
</style></head>
<body><div class="wrap">
  <h1>OSINT Industries — digital footprint</h1>
  <div class="sub">Selector <span class="sel">%(selector)s</span> ·
       %(count)d account(s) · generated %(generated)s</div>
  <div class="grid">%(cards)s</div>
  <footer>Data provided as-is by OSINT Industries. Verify before action.
          For authorised investigation use only.</footer>
</div></body></html>""" % {
        "selector": _esc(selector),
        "count": count,
        "generated": generated,
        "cards": cards,
    }
