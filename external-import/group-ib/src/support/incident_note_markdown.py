from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from support.note_markdown import MarkdownNote


def matches_struct_to_markdown_lines(
    matches: Any,
    *,
    values_max_len: int = 500,
) -> list[str]:
    if matches is None:
        return []
    rows: list[tuple[list[str], str]] = []

    def _walk(path: list[str], obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                _walk(path + [str(k)], v)
        elif isinstance(obj, list):
            vals = []
            for item in obj:
                if item is None:
                    vals.append("")
                else:
                    vals.append(str(item).strip())
            value_cell = ", ".join(vals) if vals else ""
            if len(value_cell) > values_max_len:
                value_cell = value_cell[: values_max_len - 3] + "..."
            rows.append((path, value_cell))
        else:
            value_cell = str(obj).strip() if obj is not None else ""
            if len(value_cell) > values_max_len:
                value_cell = value_cell[: values_max_len - 3] + "..."
            rows.append((path, value_cell))

    _walk([], matches)
    if not rows:
        return []
    depth = max(len(p) for p, _ in rows)
    headers = [f"Key {i + 1}" for i in range(depth)] + ["Values"]
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    lines = ["| " + " | ".join(headers) + " |", sep]
    for path, value_cell in rows:
        padded = (path + [""] * depth)[:depth]
        escaped = [str(c).replace("|", "\\|").replace("\n", " ") for c in padded]
        lines.append(
            "| "
            + " | ".join(escaped)
            + " | "
            + str(value_cell).replace("|", "\\|").replace("\n", " ")
            + " |"
        )
    return lines


def _table_cell(c: Any) -> str:
    return "" if c is None else str(c)


def markdown_compromised_account_group(
    *,
    login: Any,
    password: Any,
    include_passwords: bool,
    service: Mapping[str, Any],
    parsed_login: Mapping[str, Any],
    date_first_seen: Any,
    date_last_seen: Any,
    date_first_compromised: Any,
    date_last_compromised: Any,
    events_table: Sequence[Any],
) -> str:
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.h2("Account").kv("Login", login or unk).kv(
        "Password",
        password if (password and include_passwords) else "<redacted>",
    )
    nb.h2("Service").kv("URL", service.get("url") or unk).kv(
        "Domain", service.get("domain") or unk
    ).kv("Host", service.get("host") or unk).kv("IP", service.get("ip") or unk)
    if parsed_login.get("domain") or parsed_login.get("ip"):
        nb.h2("Parsed login").kv("Domain", parsed_login.get("domain") or unk).kv(
            "IP", parsed_login.get("ip") or unk
        )
    nb.h2("Dates").kv("First seen", date_first_seen or unk).kv(
        "Last seen", date_last_seen or unk
    ).kv("First compromised", date_first_compromised or unk).kv(
        "Last compromised", date_last_compromised or unk
    )
    if events_table:
        rows_out: list[list[Any]] = []
        for row in events_table:
            if not isinstance(row, dict):
                continue
            rows_out.append(
                [
                    row.get("dateDetected") or "",
                    row.get("dateCompromised") or "",
                    row.get("events_ipv4_ip") or "",
                    row.get("malware") or "",
                    row.get("threatActor") or "",
                    row.get("countryCode") or "",
                    row.get("region") or "",
                    row.get("asn") or "",
                ]
            )
        if rows_out:
            nb.h2("Events").table(
                [
                    "dateDetected",
                    "dateCompromised",
                    "client_ip",
                    "malware",
                    "threatActor",
                    "country",
                    "region",
                    "asn",
                ],
                rows_out,
                cell=_table_cell,
            )
    return nb.build()


def markdown_compromised_bank_card_group(
    *,
    item_id: Any,
    card_number: Any,
    card_type: Any,
    card_category: Any,
    card_system: Any,
    card_bin: Sequence[Any] | None,
    card_issuer: Any,
    card_issuer_country: Any,
    date_first_seen: Any,
    date_last_seen: Any,
    date_first_compromised: Any,
    date_last_compromised: Any,
    raw_ta_list: Sequence[Any],
    raw_source_list: Sequence[Any],
    malware_names: Sequence[str],
    events_table: Sequence[Any],
    flatten_cell: Callable[[Any], str],
) -> str:
    nb = MarkdownNote()
    nb.h2("Card Info").kv("ID", item_id).kv("Number", card_number).kv(
        "Type", card_type
    ).kv("Category", card_category).kv("System", card_system).kv(
        "BIN", ", ".join(str(b) for b in card_bin) if card_bin else None
    ).kv(
        "Issuer", card_issuer
    ).kv(
        "Issuer country", card_issuer_country
    )
    nb.h2("Dates").kv("First seen", date_first_seen).kv("Last seen", date_last_seen).kv(
        "First compromised", date_first_compromised
    ).kv("Last compromised", date_last_compromised)
    if raw_ta_list:
        nb.h2("Threat actors")
        for ta in raw_ta_list:
            if not isinstance(ta, dict):
                continue
            name = flatten_cell(ta.get("name")) or "—"
            tid = flatten_cell(ta.get("id")) or "—"
            nb.raw(f"- **{name}** — ID: `{tid}`")
    if raw_source_list:
        nb.h2("Sources")
        for src in raw_source_list:
            if not isinstance(src, dict):
                continue
            st = flatten_cell(src.get("type")) or "—"
            sid = flatten_cell(src.get("id")) or "—"
            extra = src.get("idType")
            suf = f" — idType: `{flatten_cell(extra)}`" if extra else ""
            nb.raw(f"- **{st}** — ID: `{sid}`{suf}")
    if malware_names:
        nb.h2("Malware")
        for m in malware_names:
            nb.raw(f"- {m}")
    if events_table:
        ev_rows: list[list[Any]] = []
        for row in events_table:
            if not isinstance(row, dict):
                continue
            cnc = row.get("cnc") or row.get("cnc_domain") or row.get("cnc_url")
            ev_rows.append(
                [
                    row.get("dateDetected"),
                    row.get("dateCompromised"),
                    row.get("malware_name"),
                    row.get("threatActor_name"),
                    cnc,
                    row.get("cnc_ipv4_ip"),
                    row.get("client_ipv4_ip"),
                    row.get("price"),
                    row.get("source_type"),
                ]
            )
        if ev_rows:
            nb.h2("Compromise events").table(
                [
                    "Detected",
                    "Compromised",
                    "Malware",
                    "Threat actor",
                    "CnC",
                    "CnC IPv4",
                    "Client IP",
                    "Price",
                    "Source",
                ],
                ev_rows,
                cell=flatten_cell,
            )
    return nb.build()


def _safe_str_trunc(v: Any, max_len: int) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    return s[:max_len] + "..." if len(s) > max_len else s


def markdown_compromised_access(
    *,
    access_id: Any,
    payload: Mapping[str, Any],
    target: Mapping[str, Any],
    cnc: Mapping[str, Any],
    malware_obj: Mapping[str, Any],
    source_info: Mapping[str, Any],
    price: Mapping[str, Any],
    raw_preview: Any,
    raw_use_full: bool,
    raw_max_len: int | None,
) -> str:
    acc_nb = MarkdownNote()
    acc_nb.raw("## Compromised access").kv("ID", access_id).kv(
        "Type", payload.get("type")
    ).kv("Description", _safe_str_trunc(payload.get("description"), 500))
    acc_nb.h2("Target").kv("Host", target.get("host")).kv(
        "Domain", target.get("domain")
    ).kv("Provider", target.get("provider")).kv("Country", target.get("country")).kv(
        "Device OS", target.get("device_os")
    ).kv(
        "Browser", target.get("device_browser")
    )
    acc_nb.h2("C2").kv("CNC", cnc.get("cnc")).kv("Domain", cnc.get("domain")).kv(
        "URL", cnc.get("url")
    ).kv("Port", cnc.get("port"))
    acc_nb.h2("Malware").kv("Name", malware_obj.get("name")).kv(
        "ID", malware_obj.get("id")
    )
    acc_nb.h2("Source").kv("Name", source_info.get("name")).kv(
        "External ID", source_info.get("externalId")
    ).kv("Seller", source_info.get("seller"))
    acc_nb.h2("Price").kv("Value", price.get("value")).kv(
        "Currency", price.get("currency")
    )
    if raw_preview:
        if raw_use_full:
            acc_nb.h2("Raw data").paragraph(str(raw_preview))
        else:
            acc_nb.h2("Raw data (preview)").paragraph(
                _safe_str_trunc(raw_preview, raw_max_len or 2000)
            )
    return acc_nb.build()


def markdown_compromised_spd(
    *,
    spd_id: Any,
    payload: Mapping[str, Any],
    value_obj: Mapping[str, Any],
    ptype_str: str,
    value_str: str,
    events_list: Sequence[Any],
    malware_list: Sequence[Any],
    ta_list: Sequence[Any],
) -> str:
    spd_nb = MarkdownNote()
    spd_nb.raw("## Suspicious payment details")
    spd_nb.kv("ID", spd_id)
    spd_nb.kv("Type", payload.get("type"))
    spd_nb.kv("Service type", payload.get("service_type"))
    spd_nb.kv("Owner", payload.get("ownerName"))
    spd_nb.kv("Illegal score", payload.get("illegalScore"))
    spd_nb.kv("Countries", payload.get("country"))
    spd_nb.kv("Tags", payload.get("tags"))

    spd_nb.h2("Value")
    spd_nb.kv("Value", value_str)
    spd_nb.kv("Type", ptype_str)
    spd_nb.kv("Email", value_obj.get("email"))
    spd_nb.kv("Bank card", value_obj.get("bankCard"))
    spd_nb.kv("IBAN", value_obj.get("iban"))

    if events_list:
        ev_rows: list[list[Any]] = []
        for ev in events_list[:50]:
            if isinstance(ev, dict):
                ev_rows.append(
                    [
                        ev.get("compromisedAt"),
                        ev.get("detectedAt"),
                        ev.get("source_name"),
                        ev.get("source_type"),
                        ", ".join(str(t) for t in (ev.get("tags") or [])),
                        ev.get("illegalScore"),
                    ]
                )
        if ev_rows:
            spd_nb.h2("Events").table(
                [
                    "compromisedAt",
                    "detectedAt",
                    "source",
                    "source type",
                    "tags",
                    "illegalScore",
                ],
                ev_rows,
                cell=_table_cell,
            )

    sources = payload.get("sources")
    if isinstance(sources, list) and sources:
        src_rows = [
            [s.get("name"), s.get("type")] for s in sources if isinstance(s, dict)
        ]
        if src_rows:
            spd_nb.h2("Sources").table(["name", "type"], src_rows, cell=_table_cell)

    if malware_list:
        spd_nb.h2("Malware")
        for m in malware_list:
            if m:
                spd_nb.bullet(str(m.get("name") or m))
    if ta_list:
        spd_nb.h2("Threat actors")
        for t in ta_list:
            if t:
                spd_nb.bullet(str(t.get("name") or t))
    return spd_nb.build()


def markdown_malware_config(
    *,
    config_id: Any,
    payload: Mapping[str, Any],
    malware_obj: Mapping[str, Any],
    date_first: Any,
    date_last: Any,
    content_preview: str,
    file_list: Sequence[Any],
) -> str:
    nb = MarkdownNote()
    nb.raw("## Malware config").kv("ID", config_id).kv("Hash", payload.get("hash"))
    nb.h2("Malware").kv("Name", malware_obj.get("name")).kv("ID", malware_obj.get("id"))
    nb.h2("Dates").kv("Date first seen", date_first).kv("Date last seen", date_last)
    if payload.get("configSummary"):
        nb.h2("Config summary").paragraph(str(payload.get("configSummary"))[:1000])
    if content_preview:
        nb.h2("Content (preview)").paragraph(content_preview)
    if file_list:
        file_rows: list[list[Any]] = []
        for frow in file_list[:15]:
            if isinstance(frow, dict):
                file_rows.append(
                    [
                        frow.get("name"),
                        frow.get("sha1"),
                        frow.get("sha256"),
                        frow.get("md5"),
                        frow.get("timestamp"),
                    ]
                )
        if file_rows:
            nb.h2("Files").table(
                ["name", "sha1", "sha256", "md5", "timestamp"],
                file_rows,
            )
    return nb.build()


def markdown_osi_public_leak(
    *,
    leak_id: Any,
    leak_hash: Any,
    created_raw: Any,
    payload: Mapping[str, Any],
    link_list: Sequence[Any],
    data_full_or_preview: tuple[bool, str, str] | None,
    matches: Any,
) -> str:
    unk = "<unknown>"
    pl_nb = MarkdownNote()
    pl_nb.raw("## Public leak").kv("ID", leak_id or unk).kv(
        "Hash", leak_hash or unk
    ).kv("Created", created_raw or unk)
    if data_full_or_preview is not None:
        use_full, body_text, heading = data_full_or_preview
        if use_full:
            pl_nb.h2("Data (full)").paragraph(body_text)
        else:
            pl_nb.h2(heading).paragraph(body_text)
    if link_list:
        link_rows: list[list[Any]] = []
        for row in link_list:
            if not isinstance(row, dict):
                continue
            link_rows.append(
                [
                    row.get("author") or "",
                    row.get("hash") or "",
                    row.get("link") or "",
                    row.get("title") or "",
                    row.get("source") or "",
                    row.get("dateDetected") or "",
                    row.get("datePublished") or "",
                ]
            )
        if link_rows:
            pl_nb.h2("Link list").table(
                [
                    "author",
                    "hash",
                    "link",
                    "title",
                    "source",
                    "dateDetected",
                    "datePublished",
                ],
                link_rows,
                cell=_table_cell,
            )
    if matches:
        pl_nb.h2("Matches")
        pl_nb.extend(matches_struct_to_markdown_lines(matches))
    return pl_nb.build()


def markdown_darkweb_forums(
    *,
    post: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
    categories: Sequence[Any],
    langs: Sequence[Any],
    forum_url: Any,
) -> str:
    """Render the analyst Note for a ``darkweb/forums`` post."""
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.raw(f"## Darkweb forum post [{post.get('id') or unk}]")
    nb.kv("ID", post.get("id") or unk)
    nb.kv("Topic", post.get("title"))
    nb.kv("Forum", post.get("forum"))
    nb.kv("Author", post.get("nickname"))
    nb.kv("Thread ID", post.get("thread_id"))
    nb.kv("Categories", list(categories) if categories else None)
    nb.kv("Languages", list(langs) if langs else None)
    nb.kv("Message length", post.get("message_len"))
    nb.kv("Published", (json_date_obj or {}).get("date-published"))
    nb.kv("Created", (json_date_obj or {}).get("date-created"))
    nb.kv("Updated", (json_date_obj or {}).get("date-modified"))
    if forum_url:
        nb.kv("Original post", forum_url)

    body = post.get("description")
    if body:
        nb.h2("Body").paragraph(str(body))
    return nb.build()


def markdown_threat_report(
    *,
    obj: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.raw(f"## Threat report: {obj.get('title') or unk}")
    nb.kv("ID", obj.get("id") or unk)
    nb.kv("Report number", obj.get("report_number"))
    nb.kv("Published", (json_date_obj or {}).get("date-published"))
    nb.kv("First seen", (json_date_obj or {}).get("first-seen"))
    nb.kv("Last seen", (json_date_obj or {}).get("last-seen"))
    nb.kv("Tailored", obj.get("is_tailored"))
    nb.kv("Auto-generated", obj.get("is_autogen"))
    nb.kv("Has IOCs", obj.get("has_iocs"))

    if obj.get("expertise"):
        nb.kv("Expertise", obj.get("expertise"))

    if any(
        obj.get(k)
        for k in (
            "sectors",
            "regions",
            "targeted_companies",
            "targeted_partners",
            "related_threat_actors",
        )
    ):
        nb.h2("Targeting")
        nb.kv("Sectors", obj.get("sectors"))
        nb.kv("Regions", obj.get("regions"))
        nb.kv("Targeted companies", obj.get("targeted_companies"))
        nb.kv("Targeted partners/clients", obj.get("targeted_partners"))
        nb.kv("Related threat actors", obj.get("related_threat_actors"))

    if obj.get("sources"):
        nb.h2("Sources")
        for s in (
            obj["sources"] if isinstance(obj["sources"], list) else [obj["sources"]]
        ):
            if s:
                nb.bullet(str(s))
    return nb.build()


def markdown_threat_actor(
    *,
    obj: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    """Render the analyst Note for an ``apt/threat_actor`` / ``hi/threat_actor``
    profile — the structured statistics that would otherwise be flattened into
    labels (targeting, expertise, activity counts)."""
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.raw(f"## Threat actor: {obj.get('name') or unk}")
    nb.kv("ID", obj.get("id") or unk)
    nb.kv("Aliases", obj.get("aliases"))
    nb.kv("Country", obj.get("country"))
    nb.kv("Is APT", obj.get("is_apt"))
    nb.kv("Languages", obj.get("langs"))
    nb.kv("Spoken languages", obj.get("spoken_langs"))
    nb.kv("First seen", (json_date_obj or {}).get("first-seen"))
    nb.kv("Last seen", (json_date_obj or {}).get("last-seen"))

    if any(
        obj.get(k) is not None
        for k in (
            "indicators_count",
            "reports_count",
            "related_threat_actors_count",
        )
    ):
        nb.h2("Activity")
        nb.kv("Indicators", obj.get("indicators_count"))
        nb.kv("Reports", obj.get("reports_count"))
        nb.kv("Related threat actors", obj.get("related_threat_actors_count"))

    if any(
        obj.get(k)
        for k in (
            "sectors",
            "regions",
            "targeted_countries",
            "targeted_companies",
            "targeted_partners",
        )
    ):
        nb.h2("Targeting")
        nb.kv("Sectors", obj.get("sectors"))
        nb.kv("Regions", obj.get("regions"))
        nb.kv("Targeted countries", obj.get("targeted_countries"))
        nb.kv("Targeted companies", obj.get("targeted_companies"))
        nb.kv("Targeted partners/clients", obj.get("targeted_partners"))

    if any(obj.get(k) for k in ("expertise", "goals", "roles")):
        nb.h2("Profile")
        nb.kv("Expertise", obj.get("expertise"))
        nb.kv("Goals", obj.get("goals"))
        nb.kv("Roles", obj.get("roles"))
    return nb.build()


def markdown_attacks_ddos(
    *,
    payload: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    """Render the analyst Note for an ``attacks/ddos`` record."""
    unk = "<unknown>"
    target = payload.get("target") or {}
    cnc = payload.get("cnc") or {}
    malware = payload.get("malware") or {}
    ta = payload.get("threat_actor") or {}
    nb = MarkdownNote()
    nb.raw(f"## DDoS attack [{payload.get('id') or unk}]")
    nb.kv("ID", payload.get("id") or unk)
    nb.kv("Source", payload.get("source"))
    nb.kv("Type", payload.get("type"))
    nb.kv("Protocol", payload.get("protocol"))
    nb.kv("Duration (s)", payload.get("duration"))
    nb.kv("Detected", (json_date_obj or {}).get("detection-date"))
    nb.kv("Begin", (json_date_obj or {}).get("submission-time"))
    nb.kv("End", (json_date_obj or {}).get("takedown-time"))

    nb.h2("Target")
    nb.kv("IP", target.get("ip"))
    nb.kv("Domain", target.get("domain"))
    nb.kv("URL", target.get("url"))
    nb.kv("Port", target.get("port"))
    nb.kv("Category", target.get("category"))
    nb.kv(
        "Geo",
        f"{target.get('city') or '—'}, {target.get('region') or '—'}, "
        f"{target.get('country_name') or target.get('country_code') or '—'}",
    )
    nb.kv("ASN", target.get("asn"))
    nb.kv("Provider", target.get("provider"))

    if any(cnc.get(k) for k in ("cnc", "domain", "url", "ip")):
        nb.h2("CnC")
        nb.kv("CnC", cnc.get("cnc"))
        nb.kv("Domain", cnc.get("domain"))
        nb.kv("URL", cnc.get("url"))
        nb.kv("IP", cnc.get("ip"))
        nb.kv("Country", cnc.get("country_code"))

    if malware.get("name") or ta.get("name"):
        nb.h2("Attribution")
        if malware.get("name"):
            nb.kv(
                "Malware",
                f"{malware.get('name')} (id={malware.get('id') or '—'})",
            )
        if ta.get("name"):
            nb.kv(
                "Threat actor",
                f"{ta.get('name')} (id={ta.get('id') or '—'}, "
                f"country={ta.get('country') or '—'})",
            )

    if payload.get("message_link"):
        nb.h2("References").kv("Message link", payload.get("message_link"))
    return nb.build()


def markdown_malware(
    *,
    obj: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.raw(f"## Malware: {obj.get('name') or unk}")
    nb.kv("Aliases", obj.get("aliases"))
    nb.kv("Category", obj.get("category"))
    nb.kv("Platform", obj.get("platform"))
    nb.kv("Languages", obj.get("langs"))
    nb.kv("Threat level", obj.get("threat_level"))
    nb.kv("Published", obj.get("is_published"))
    nb.kv("Updated", (json_date_obj or {}).get("date-updated"))

    def _names(rows: Any) -> list[str]:
        out: list[str] = []
        for r in rows or []:
            if isinstance(r, dict) and r.get("name"):
                out.append(str(r["name"]))
            elif isinstance(r, str) and r.strip():
                out.append(r.strip())
        return out

    actors = _names(obj.get("ta_list")) + _names(obj.get("threat_actor_list"))
    if actors:
        nb.kv("Threat actors", actors)
    linked = _names(obj.get("linked_malware"))
    if linked:
        nb.kv("Linked malware", linked)
    if obj.get("source_countries"):
        nb.kv("Source countries", obj.get("source_countries"))
    if obj.get("geo_regions"):
        nb.kv("Geo regions", obj.get("geo_regions"))

    short = obj.get("short_description")
    if short:
        nb.h2("Summary").paragraph(str(short))
    desc = obj.get("description")
    if desc and desc != short:
        nb.h2("Description").paragraph(str(desc))
    return nb.build()


def markdown_malware_cnc(
    *,
    payload: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.raw(f"## Malware CnC [{payload.get('id') or unk}]")
    nb.kv("ID", payload.get("id") or unk)
    nb.kv("CnC", payload.get("cnc"))
    nb.kv("Domain", payload.get("domain"))
    nb.kv("URL", payload.get("url"))
    nb.kv("Platform", payload.get("platform"))
    nb.kv("First seen", (json_date_obj or {}).get("date-first-seen"))
    nb.kv("Last seen", (json_date_obj or {}).get("date-last-seen"))
    nb.kv("Detected", (json_date_obj or {}).get("date-detected"))

    malware = [
        m.get("name")
        for m in (payload.get("malware_list") or [])
        if isinstance(m, dict) and m.get("name")
    ]
    if malware:
        nb.kv("Malware", malware)
    ta = [
        t.get("name")
        for t in (payload.get("threat_actor_list") or [])
        if isinstance(t, dict) and t.get("name")
    ]
    if ta:
        nb.kv("Threat actors", ta)

    ip_rows = []
    for fld in ("ipv4_list", "ipv6_list"):
        for row in payload.get(fld) or []:
            if isinstance(row, dict) and row.get("ip"):
                ip_rows.append(
                    [
                        row.get("ip"),
                        row.get("asn"),
                        row.get("country_name") or row.get("country_code"),
                    ]
                )
    if ip_rows:
        nb.h2("Resolved IPs").table(["ip", "asn", "country"], ip_rows, cell=_table_cell)

    f = payload.get("file") or {}
    if isinstance(f, dict) and any(f.get(k) for k in ("md5", "sha1", "sha256", "name")):
        nb.h2("Associated file")
        nb.kv("Name", f.get("name"))
        nb.kv("MD5", f.get("md5"))
        nb.kv("SHA1", f.get("sha1"))
        nb.kv("SHA256", f.get("sha256"))
    return nb.build()


def markdown_attacks_deface(
    *,
    payload: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    unk = "<unknown>"
    tip = payload.get("target_ip") or {}
    ta = payload.get("threat_actor") or {}
    nb = MarkdownNote()
    nb.raw(f"## Website defacement [{payload.get('id') or unk}]")
    nb.kv("ID", payload.get("id") or unk)
    nb.kv("Source", payload.get("source"))
    nb.kv("Detected", (json_date_obj or {}).get("detection-date"))
    nb.kv("Target domain", payload.get("target_domain"))
    nb.kv("Defaced URL", payload.get("site_url") or payload.get("url"))
    nb.kv("Mirror", payload.get("mirror_link"))
    nb.kv("Source URL", payload.get("source_url"))
    nb.kv("Provider domain", payload.get("provider_domain"))

    if tip.get("ip"):
        nb.h2("Target host")
        nb.kv("IP", tip.get("ip"))
        nb.kv(
            "Geo",
            f"{tip.get('city') or '—'}, {tip.get('region') or '—'}, "
            f"{tip.get('country_name') or tip.get('country_code') or '—'}",
        )
        nb.kv("ASN", tip.get("asn"))
        nb.kv("Provider", tip.get("provider"))

    if ta.get("name"):
        nb.h2("Attribution").kv(
            "Threat actor",
            f"{ta.get('name')} (id={ta.get('id') or '—'}, "
            f"isAPT={ta.get('is_apt')})",
        )
    return nb.build()


def markdown_attacks_phishing_group(
    *,
    payload: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    unk = "<unknown>"
    ta = payload.get("threat_actor") or {}
    nb = MarkdownNote()
    nb.raw(f"## Phishing group [{payload.get('id') or unk}]")
    nb.kv("ID", payload.get("id") or unk)
    nb.kv("Impersonated brand", payload.get("brand"))
    nb.kv("Primary domain", payload.get("domain"))
    nb.kv("Page title", payload.get("domain_title"))
    nb.kv("Objective", payload.get("objective"))
    nb.kv("Phishing pages", payload.get("count_phishing"))
    nb.kv("Source", payload.get("source"))
    nb.kv("Detected", (json_date_obj or {}).get("submission-time"))
    nb.kv("Blocked", (json_date_obj or {}).get("takedown-time"))

    ip_rows = [
        [
            i.get("ip"),
            i.get("country_name") or i.get("country_code"),
            i.get("provider"),
        ]
        for i in (payload.get("ip_list") or [])
        if isinstance(i, dict) and i.get("ip")
    ]
    if ip_rows:
        nb.h2("Hosting IPs").table(
            ["ip", "country", "provider"], ip_rows, cell=_table_cell
        )

    ph_rows = [
        [p.get("url"), p.get("domain"), p.get("ip"), p.get("country_code")]
        for p in (payload.get("phishing_list") or [])
        if isinstance(p, dict) and (p.get("url") or p.get("domain"))
    ]
    if ph_rows:
        nb.h2("Phishing pages").table(
            ["url", "domain", "ip", "country"], ph_rows, cell=_table_cell
        )

    if ta.get("name"):
        nb.h2("Attribution").kv(
            "Threat actor",
            f"{ta.get('name')} (id={ta.get('id') or '—'}, "
            f"isAPT={ta.get('is_apt')})",
        )
    return nb.build()


def markdown_attacks_phishing_kit(
    *,
    payload: Mapping[str, Any],
    json_date_obj: Mapping[str, Any],
) -> str:
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.raw(f"## Phishing kit [{payload.get('id') or unk}]")
    nb.kv("ID", payload.get("id") or unk)
    nb.kv("Hash", payload.get("hash"))
    nb.kv("Uploader login", payload.get("login"))
    nb.kv("Source", payload.get("source"))
    nb.kv("Target brand", payload.get("target_brand"))
    nb.kv("Detected", (json_date_obj or {}).get("detection-date"))
    nb.kv("First seen", (json_date_obj or {}).get("first-seen"))
    nb.kv("Last seen", (json_date_obj or {}).get("last-seen"))

    emails = payload.get("emails")
    if emails:
        nb.kv("Drop emails", emails)

    dl_rows = [
        [d.get("url"), d.get("domain"), d.get("file_name"), d.get("date")]
        for d in (payload.get("downloaded_from") or [])
        if isinstance(d, dict) and (d.get("url") or d.get("domain"))
    ]
    if dl_rows:
        nb.h2("Downloaded from").table(
            ["url", "domain", "file", "date"], dl_rows, cell=_table_cell
        )

    var_rows = [
        [v.get("type"), v.get("file_path")]
        for v in (payload.get("variables") or [])
        if isinstance(v, dict) and (v.get("type") or v.get("file_path"))
    ]
    if var_rows:
        nb.h2("Kit variables").table(["type", "file path"], var_rows, cell=_table_cell)
        nb.gap().raw("_Captured credential values are intentionally omitted._")
    return nb.build()


def markdown_osi_vulnerability(
    *,
    vuln: Mapping[str, Any],
    cvss: Mapping[str, Any],
    cpe_list: Sequence[Any],
    json_date_obj: Mapping[str, Any],
    cpe_rows_max: int = 200,
) -> str:
    unk = "<unknown>"
    nb = MarkdownNote()
    nb.raw(f"## Vulnerability {vuln.get('object_id') or vuln.get('id') or unk}")
    nb.kv("ID", vuln.get("id") or vuln.get("object_id") or unk)
    nb.kv("Title", vuln.get("title"))
    nb.kv("CVSS score", (cvss or {}).get("score"))
    nb.kv("CVSS vector", (cvss or {}).get("vector"))
    nb.kv("CVSS attack vector", vuln.get("cvss_attack_vector"))
    nb.kv("EPSS score", vuln.get("epss_score"))
    nb.kv("EPSS percentile", vuln.get("epss_percentile"))
    nb.kv("Has exploit", vuln.get("has_exploit"))
    nb.kv("Exploit count", vuln.get("exploit_count"))
    nb.kv("Seen in the wild", vuln.get("seen_in_the_wild"))
    nb.kv("Reporter", vuln.get("reporter"))
    nb.kv("Provider", vuln.get("provider"))
    nb.kv("Bulletin family", vuln.get("bulletin_family"))
    nb.kv("Published", (json_date_obj or {}).get("date-published"))
    nb.kv("Modified", (json_date_obj or {}).get("date-modified"))
    nb.kv("Advisory", vuln.get("href"))
    cve_list = vuln.get("cve_list")
    if cve_list:
        nb.kv("Related CVE", cve_list)

    description = vuln.get("description")
    if description:
        nb.h2("Description").paragraph(str(description))

    refs: list[str] = []
    for raw_ref in vuln.get("references") or []:
        if isinstance(raw_ref, str):
            refs += [
                r.strip() for r in raw_ref.split(",") if r.strip().startswith("http")
            ]
    if refs:
        nb.h2("References")
        for r in refs:
            nb.bullet(r)

    # Deduplicate CPE rows (the API often returns hundreds of near-identical
    # version rows); cap the rendered table so the Note stays readable.
    seen: set[tuple[str, str, str, str]] = set()
    rows: list[list[Any]] = []
    for item in cpe_list or []:
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("vendor") or ""),
            str(item.get("product") or ""),
            str(item.get("version") or ""),
            str(item.get("type") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            [
                item.get("vendor") or "",
                item.get("product") or "",
                item.get("version") or "",
                item.get("type") or "",
                item.get("raw_string") or item.get("string") or "",
            ]
        )
    if rows:
        nb.h2(f"Affected software (CPE) — {len(rows)} unique")
        nb.table(
            ["vendor", "product", "version", "type", "cpe"],
            rows[:cpe_rows_max],
            cell=_table_cell,
        )
        if len(rows) > cpe_rows_max:
            nb.gap().raw(f"_… {len(rows) - cpe_rows_max} more CPE entries omitted._")
    return nb.build()


def markdown_osi_git_repository(
    *,
    repo_id: Any,
    name: Any,
    payload: Mapping[str, Any],
    date_detected: Any,
    date_created: Any,
    files_list: Sequence[Any],
    flatten_cell: Callable[[Any], str],
) -> str:
    unk = "<unknown>"
    git_nb = MarkdownNote()
    git_nb.raw("## Git repository leak").kv("ID", repo_id or unk).kv(
        "Name", name or unk
    ).kv("Source", payload.get("source") or unk).kv(
        "Date detected", date_detected or unk
    ).kv(
        "Date created", date_created or unk
    )
    if files_list:
        frows: list[list[Any]] = []
        for row in files_list:
            if not isinstance(row, dict):
                continue
            c = flatten_cell
            frows.append(
                [
                    c(row.get("file_name")),
                    c(row.get("hash")),
                    c(row.get("authorName")),
                    c(row.get("authorEmail")),
                    c(row.get("url")),
                    c(row.get("dataFound")),
                    c(row.get("dateCreated")),
                    c(row.get("dateDetected")),
                ]
            )
        if frows:
            git_nb.h2("Files").table(
                [
                    "file_name",
                    "hash",
                    "authorName",
                    "authorEmail",
                    "url",
                    "dataFound",
                    "dateCreated",
                    "dateDetected",
                ],
                frows,
                cell=lambda x: (
                    x if isinstance(x, str) else str(x) if x is not None else ""
                ),
            )
    return git_nb.build()


def markdown_hi_open_threats(
    *,
    open_threat_id: str,
    title: str,
    source: str,
    source_type: str,
    link: str,
    json_date_obj: Mapping[str, Any],
    raw_threat_actors: Sequence[Any],
    raw_malware: Sequence[Any],
    cve_ids: Sequence[Any],
    tag_labels: Sequence[str],
    country_codes: Sequence[str],
    domain_vals: Sequence[str],
    ip_vals: Sequence[str],
    url_vals: Sequence[str],
    valid_hashes: Sequence[str],
    include_text: bool,
    include_original: bool,
    text: str,
    original: str,
    get_text_preview: Callable[[str], str],
) -> str:
    hot_nb = MarkdownNote()
    hot_nb.raw("## Open Threat Report").kv("ID", open_threat_id or "—").kv(
        "Title", title
    ).kv("Source", source or "—").kv("Source type", source_type or "—").kv(
        "Link", link or "—"
    )
    hot_nb.h2("Dates").kv("Created", json_date_obj.get("date-created")).kv(
        "Detected", json_date_obj.get("date-detected")
    ).kv("Updated", json_date_obj.get("date-updated"))
    if raw_threat_actors:
        hot_nb.h2("Threat actors")
        for ta in raw_threat_actors:
            if isinstance(ta, dict) and ta.get("name"):
                hot_nb.bullet(ta["name"])
                hot_nb.indented(str(ta.get("id") or "—"))
    if raw_malware:
        hot_nb.h2("Malware")
        for m in raw_malware:
            if isinstance(m, dict) and m.get("name"):
                hot_nb.bullet(m["name"])
                hot_nb.indented(str(m.get("id") or "—"))
    if cve_ids:
        hot_nb.h2("CVE")
        for c in cve_ids:
            hot_nb.bullet(str(c))
    if tag_labels:
        hot_nb.h2("Tags").paragraph(", ".join(tag_labels))
    if country_codes:
        hot_nb.h2("Countries").paragraph(", ".join(country_codes))
    if domain_vals or ip_vals or url_vals or valid_hashes:
        hot_nb.h2("Observables")
        if domain_vals:
            hot_nb.kv("Domains", ", ".join(domain_vals[:20]))
        if ip_vals:
            hot_nb.kv("IPs", ", ".join(ip_vals[:20]))
        if url_vals:
            hot_nb.kv("URLs", ", ".join(url_vals[:20]))
        if valid_hashes:
            hot_nb.kv("Hashes", ", ".join(valid_hashes[:20]))
    if include_text and text:
        hot_nb.h2("Text").paragraph(get_text_preview(text))
    if include_original and original:
        hot_nb.h2("Original").paragraph(get_text_preview(original))
    return hot_nb.build()


def markdown_compromised_masked_card(
    *,
    item_id: Any,
    masked_card: Mapping[str, Any],
    card_number: Any,
    card_bins: Sequence[Any] | None,
    card_system: Any,
    card_type: Any,
    card_issuer: Any,
    card_issuer_country_name: Any,
    card_issuer_country_code: Any,
    card_info: Mapping[str, Any],
    card_cvv: Any,
    card_pin: Any,
    card_dump: Any,
    cnc_domain: Any,
    cnc_url: Any,
    cnc_ip: Any,
    cnc_ipv6: Any,
    cnc_country_code: Any,
    ioc_domain_on_red: bool,
    ioc_url_on_red: bool,
    ioc_ipv4_on_red: bool,
    eval_tlp: Any,
    mal_name: Any,
    malware_obj: Mapping[str, Any] | None,
    threat_actor_names: Sequence[str],
    source_type: Any,
    source_link: Any,
    owner_obj: Mapping[str, Any],
    date_detected: Any,
    date_compromised: Any,
) -> str:
    mnb = MarkdownNote()
    mnb.raw("## Compromised masked card").kv("ID", item_id).kv(
        "baseName", masked_card.get("baseName")
    ).kv("isMasked", masked_card.get("isMasked")).kv(
        "isDump", masked_card.get("isDump")
    ).kv(
        "isExpired", masked_card.get("isExpired")
    )
    mnb.h2("Card").kv("Number", card_number).kv(
        "BIN", ", ".join(str(b) for b in card_bins) if card_bins else None
    ).kv("System", card_system).kv("Type", card_type).kv("Issuer", card_issuer).kv(
        "Issuer country", card_issuer_country_name or card_issuer_country_code
    ).kv(
        "Valid thru",
        f"{card_info.get('validThru') or '—'} ({card_info.get('validThruDate') or '—'})",
    ).kv(
        "CVV", card_cvv
    ).kv(
        "PIN", card_pin
    ).kv(
        "Dump", card_dump
    )
    mnb.h2("CnC").kv("Domain", cnc_domain).kv("URL", cnc_url)
    if cnc_ip:
        mnb.kv("IPv4", f"{cnc_ip} (country: {cnc_country_code or '—'})")
    else:
        mnb.kv("IPv4", None)
    mnb.kv("IPv6", cnc_ipv6).kv(
        "CnC domain as IoC",
        f"{'yes' if ioc_domain_on_red else 'no'} (TLP={eval_tlp or '—'})",
    ).kv("CnC URL as IoC", "yes" if ioc_url_on_red else "no").kv(
        "CnC IPv4 as IoC", "yes" if ioc_ipv4_on_red else "no"
    )
    mnb.h2("Client").kv("client.ipv4", masked_card.get("client_ipv4_ip"))
    mnb.h2("Threat / Malware / Source").kv(
        "Malware",
        f"{mal_name or '—'} (id: {(malware_obj or {}).get('id') or '—'})",
    ).kv(
        "Threat actors",
        ", ".join(threat_actor_names) if threat_actor_names else None,
    ).kv(
        "Source type", source_type
    ).kv(
        "Source link", source_link
    )
    mnb.h2("Owner (as reported)").kv("Name", owner_obj.get("name")).kv(
        "Phone", owner_obj.get("phone")
    ).kv("Address", owner_obj.get("address")).kv("State", owner_obj.get("state")).kv(
        "ZIP", owner_obj.get("zip")
    ).kv(
        "Country", owner_obj.get("country_code")
    )
    mnb.h2("Price").kv("Value", masked_card.get("price_value")).kv(
        "Currency", masked_card.get("price_currency")
    )
    mnb.h2("Dates").kv("Detected", date_detected).kv("Compromised", date_compromised)
    return mnb.build()


def markdown_ioc_note(
    *,
    ioc_id: str,
    ioc_type: str,
    ioc_value: str,
    json_date_obj: Mapping[str, Any],
    malware_names: Iterable[str],
    threat_entries: Sequence[Mapping[str, Any]],
    risk_score: Any = None,
) -> str:
    ioc_nb = MarkdownNote()
    ioc_nb.raw("## IOC Details").kv("ID", ioc_id).kv("Type", ioc_type).kv(
        "Value", ioc_value or "—"
    )
    # ioc/primary carries a ``riskScore`` (mirrored to ``x_opencti_score`` on
    # the Indicator); when absent the caller passes ``None`` and the line is
    # skipped.
    if risk_score is not None:
        ioc_nb.kv("Risk score", risk_score)
    ioc_nb.h2("Dates").kv("First seen", json_date_obj.get("date-first-seen")).kv(
        "Last seen", json_date_obj.get("date-last-seen")
    )
    if malware_names:
        ioc_nb.h2("Malware")
        for m in malware_names:
            ioc_nb.bullet(str(m))
    if threat_entries:
        ioc_nb.h2("Threats")
        for t in threat_entries:
            ioc_nb.bullet(str(t.get("name") or "—"))
            if t.get("title"):
                ioc_nb.indented(str(t["title"]))
    return ioc_nb.build()
