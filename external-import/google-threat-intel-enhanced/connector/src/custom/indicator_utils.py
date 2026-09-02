"""Utility functions for indicator creation and scoring.

Supports two scoring modes configured via `indicator_scoring`:
- `gti_derived`: Score derived from GTI verdict + severity (from gti_assessment)
- `average_detection`: Score calculated from last_analysis_stats detection counts
"""

from typing import Any, Dict, List, Optional, Tuple


def escape_stix_pattern_value(value: str) -> str:
    """Escape special characters in a string for use in STIX patterns.

    In STIX pattern string literals, backslashes and single quotes must be escaped.

    Args:
        value: The string value to escape

    Returns:
        The escaped string safe for use in STIX patterns

    """
    # First escape backslashes, then single quotes
    return value.replace("\\", "\\\\").replace("'", "\\'")


def gti_score_and_verdict(
    gti_assessment: Optional[dict],
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Extract GTI Threat Score, Verdict, Severity from gti_assessment.

    Args:
        gti_assessment: The gti_assessment dictionary from attributes

    Returns:
        Tuple of (score, verdict, severity)

    """
    gti = gti_assessment or {}
    score = ((gti.get("threat_score") or {}).get("value"))
    verdict = ((gti.get("verdict") or {}).get("value"))
    severity = ((gti.get("severity") or {}).get("value"))
    try:
        score = int(score) if score is not None else None
    except Exception:
        score = None
    return score, verdict, severity


# ---------- GTI Derived Scoring (from verdict + severity) ----------


def compute_score_gti_derived(
    verdict: Optional[str], severity: Optional[str]
) -> int:
    """Compute score from GTI verdict and severity.

    This is the GTI-derived confidence/score based on verdict + severity mapping.

    Args:
        verdict: The verdict string (e.g., "VERDICT_MALICIOUS")
        severity: The severity string (e.g., "SEVERITY_HIGH")

    Returns:
        The computed score (0-95)

    """
    VERDICT_BASE = {
        "VERDICT_MALICIOUS": 80,
        "VERDICT_SUSPICIOUS": 60,
        "VERDICT_UNDETECTED": 20,
        "VERDICT_BENIGN": 0,
        "VERDICT_UNKNOWN": 10,
    }
    SEVERITY_BONUS = {
        "SEVERITY_LOW": 0,
        "SEVERITY_MEDIUM": 5,
        "SEVERITY_HIGH": 10,
        None: 0,
    }
    base = VERDICT_BASE.get((verdict or "").upper(), 10)
    bonus = SEVERITY_BONUS.get((severity or "").upper(), 0)
    return max(0, min(base + bonus, 95))  # cap below 100 unless corroborated


# ---------- Average Detection Scoring (from last_analysis_stats) ----------


def compute_score_average_detection(
    malicious: Optional[int],
    suspicious: Optional[int],
    harmless: Optional[int],
    undetected: Optional[int],
) -> Optional[int]:
    """Compute score from last_analysis_stats detection counts.

    Uses a weighted formula based on detection counts.

    Args:
        malicious: Number of malicious detections
        suspicious: Number of suspicious detections
        harmless: Number of harmless detections
        undetected: Number of undetected results

    Returns:
        A score from 0-100, or None if no stats available

    """
    mal = malicious or 0
    sus = suspicious or 0
    har = harmless or 0
    und = undetected or 0

    total = mal + sus + har + und
    if total == 0:
        return None

    # Weight: malicious=1.0, suspicious=0.5, harmless/undetected=0
    weighted_bad = mal + (sus * 0.5)
    score = int((weighted_bad / total) * 100)

    return max(0, min(score, 100))


# ---------- Unified Scoring Function ----------


def compute_indicator_score(
    scoring_mode: str,
    verdict: Optional[str] = None,
    severity: Optional[str] = None,
    analysis_stats: Optional[Dict[str, int]] = None,
) -> Optional[int]:
    """Compute indicator score based on the configured scoring mode.

    Args:
        scoring_mode: Either "gti_derived" or "average_detection"
        verdict: The verdict string (for gti_derived mode)
        severity: The severity string (for gti_derived mode)
        analysis_stats: Dict with malicious, suspicious, harmless, undetected counts
                       (for average_detection mode)

    Returns:
        The computed score, or None if insufficient data

    """
    if scoring_mode == "gti_derived":
        if verdict:
            return compute_score_gti_derived(verdict, severity)
        return None
    elif scoring_mode == "average_detection":
        if analysis_stats:
            return compute_score_average_detection(
                analysis_stats.get("malicious"),
                analysis_stats.get("suspicious"),
                analysis_stats.get("harmless"),
                analysis_stats.get("undetected"),
            )
        return None
    else:
        # Default to gti_derived
        if verdict:
            return compute_score_gti_derived(verdict, severity)
        return None


# ---------- Indicator Allowance Check ----------


def is_indicator_allowed(score: Optional[int], verdict: Optional[str]) -> bool:
    """Create Indicators only when:
      - verdict is MALICIOUS or SUSPICIOUS, and
      - score != 1 (suppression policy).
    """
    if score == 1:
        return False
    if verdict and verdict.upper() in ("VERDICT_MALICIOUS", "VERDICT_SUSPICIOUS"):
        return True
    return False


# ---------- Verdict Derivation from Stats ----------


def derive_verdict_from_stats(
    malicious: Optional[int],
    suspicious: Optional[int],
) -> Optional[str]:
    """Derive a verdict from analysis stats.

    Args:
        malicious: Number of malicious detections
        suspicious: Number of suspicious detections

    Returns:
        A verdict string (VERDICT_MALICIOUS or VERDICT_SUSPICIOUS) or None

    """
    mal = malicious or 0
    sus = suspicious or 0

    if mal >= 3:
        return "VERDICT_MALICIOUS"
    elif mal >= 1 or sus >= 3:
        return "VERDICT_SUSPICIOUS"
    elif sus >= 1:
        return "VERDICT_SUSPICIOUS"

    return None


# ---------- Narrative / Reasons Extraction ----------


def _first_non_empty(*values) -> Optional[str]:
    """Return the first non-empty string value."""
    for v in values:
        if not v:
            continue
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _as_text(x) -> Optional[str]:
    """Extract text from various data structures."""
    if not x:
        return None
    if isinstance(x, str):
        return x.strip() or None
    if isinstance(x, dict):
        return _first_non_empty(
            x.get("value"),
            x.get("text"),
            x.get("description"),
            x.get("message"),
            x.get("detail"),
        )
    if isinstance(x, list):
        buf: List[str] = []
        for item in x:
            t = _as_text(item)
            if t:
                buf.append(t)
        return " ".join(buf) if buf else None
    return None


def build_reasons_from_attrs(attrs: Dict) -> List[str]:
    """Build human-friendly justification bullets from known GTI/VT fields.

    Args:
        attrs: The attributes dictionary from the API response

    Returns:
        List of reason strings

    """
    reasons: List[str] = []
    gti = (attrs.get("gti_assessment") or {}) if isinstance(attrs, dict) else {}
    cf = (gti.get("contributing_factors") or {}) if isinstance(gti, dict) else {}
    thr = (attrs.get("threat_severity") or {}) if isinstance(attrs, dict) else {}
    thr_data = (thr.get("threat_severity_data") or {}) if isinstance(thr, dict) else {}
    sbx = (attrs.get("sandbox_verdicts") or {}) if isinstance(attrs, dict) else {}
    mcfg = (attrs.get("malware_config") or {}) if isinstance(attrs, dict) else {}

    # 1) Signals/contributors
    gavs = cf.get("gavs_detections")
    if isinstance(gavs, int) and gavs > 0:
        reasons.append(
            f"Detected by Google's spam and threat filtering engines (GAVS detections: {gavs})"
        )
    if cf.get("pervasive_indicator"):
        reasons.append("Considered widespread (pervasive indicator)")
    if cf.get("malicious_sandbox_verdict"):
        reasons.append(
            "Detected by sandbox analysis, indicating suspicious or malicious behavior"
        )
    if cf.get("associated_malware_configuration") or mcfg:
        reasons.append("Contains known malware configurations")

    m_conf = cf.get("mandiant_confidence_score")
    if isinstance(m_conf, int) and m_conf >= 80:
        reasons.append(
            "Mandiant's scoring pipeline identified this indicator as malicious"
        )
    else:
        gti_conf = cf.get("gti_confidence_score")
        if isinstance(gti_conf, int) and gti_conf >= 80:
            reasons.append(
                "Google Threat Intelligence scoring indicates high confidence of maliciousness"
            )

    if thr_data.get("belongs_to_bad_collection"):
        reasons.append(
            "Contained within a collection provided by Google Threat Intelligence or trusted partners"
        )

    # 2) Family names / sandbox malware names
    fam_names: List[str] = []
    if isinstance(mcfg.get("families"), list):
        for fam in mcfg["families"]:
            name = fam.get("family")
            if name:
                fam_names.append(name)
            for alt in fam.get("alt_names") or []:
                if alt:
                    fam_names.append(alt)

    if isinstance(sbx, dict):
        for _, v in sbx.items():
            if isinstance(v, dict):
                for nm in v.get("malware_names") or []:
                    if nm:
                        fam_names.append(nm)

    fam_names = list(dict.fromkeys(fam_names))  # de-dup
    if fam_names:
        reasons.append(
            "Analysis confirms configuration consistent with known malware family: "
            + ", ".join(fam_names[:8])
        )

    return reasons


def extract_gti_narrative_block(attrs: Dict) -> Tuple[Optional[str], List[str]]:
    """Extract headline text and reasons list from GTI assessment.

    Returns:
        Tuple of (headline_text, reasons_list)
        - headline_text: prefers gti_assessment.description (full prose)
        - reasons_list: synthesized bullets from contributing_factors/etc.

    """
    gti = (attrs or {}).get("gti_assessment", {}) or {}
    thr = (attrs or {}).get("threat_severity", {}) or {}

    # 1) Prefer the long prose from gti_assessment.description
    desc = _as_text(gti.get("description"))
    if desc:
        headline = desc.strip()
    else:
        # Fallback: shorter narrative sources
        headline = None
        for key in ("assessment", "explanation", "summary", "message", "details"):
            txt = _as_text(gti.get(key))
            if txt:
                headline = txt.rstrip(".")
                break
        if not headline:
            verdict_raw = ((gti.get("verdict") or {}).get("value")) or None
            sev_text = _as_text(thr.get("level_description"))
            sev_raw = ((gti.get("severity") or {}).get("value")) or None
            if verdict_raw:
                verdict = verdict_raw.replace("VERDICT_", "").replace("_", " ").lower()
                if sev_text:
                    headline = f"This indicator is {verdict} ({sev_text.rstrip('.')})"
                elif sev_raw:
                    sev = sev_raw.replace("SEVERITY_", "").replace("_", " ").lower()
                    headline = f"This indicator is {verdict} ({sev} severity)"
                else:
                    headline = f"This indicator is {verdict}"

    # 2) Build reasons
    reasons = build_reasons_from_attrs(attrs)

    return headline, reasons


def build_assessment_text(
    score: Optional[int], verdict: Optional[str], severity: Optional[str]
) -> str:
    """Build structured assessment text line.

    Args:
        score: GTI threat score
        verdict: GTI verdict
        severity: GTI severity

    Returns:
        Formatted assessment string

    """
    parts = []
    if score is not None:
        parts.append(f"GTI Threat Score: {score}")
    if verdict:
        parts.append(f"Verdict: {verdict}")
    if severity:
        parts.append(f"Severity: {severity}")
    return "; ".join(parts) if parts else "No GTI assessment available"


def build_vt_gui_url(kind: str, value: str, vt_id: Optional[str] = None) -> str:
    """Build VirusTotal GUI URL for an observable.

    Args:
        kind: Observable type (domain, ip, url, file)
        value: Observable value
        vt_id: Optional VT ID (useful for URLs)

    Returns:
        VirusTotal GUI URL

    """
    from urllib.parse import quote

    kind = kind.lower()
    if kind == "file":
        return f"https://www.virustotal.com/gui/file/{value}"
    if kind == "domain":
        return f"https://www.virustotal.com/gui/domain/{value}"
    if kind == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{value}"
    if kind == "url":
        if vt_id:
            return f"https://www.virustotal.com/gui/url/{vt_id}"
        return f"https://www.virustotal.com/gui/search/{quote(value, safe='')}"
    return f"https://www.virustotal.com/gui/search/{quote(value, safe='')}"


def build_enhanced_description(
    attrs: Dict,
    score: Optional[int],
    verdict: Optional[str],
    severity: Optional[str],
) -> str:
    """Build enhanced description with narrative, reasons, and assessment.

    Args:
        attrs: Raw attributes dict from API
        score: GTI threat score
        verdict: GTI verdict
        severity: GTI severity

    Returns:
        Full description string

    """
    headline, reasons = extract_gti_narrative_block(attrs)
    structured = build_assessment_text(score, verdict, severity)

    lines: List[str] = []
    if headline:
        if headline.endswith("."):
            lines.append(headline)
        else:
            lines.append(headline + ".")
    if reasons:
        lines.append("")
        lines.append("Reasons:")
        for r in reasons:
            r_clean = r.rstrip(".")
            lines.append(f"- {r_clean}.")
    if lines:
        lines.append("")
    lines.append(f"Assessment: {structured}")

    return "\n".join(lines)
