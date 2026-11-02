from datetime import datetime

# Source values -> OpenCTI SSVC enum values; anything else is dropped.
SSVC_EXPLOITATION_VALUES = {
    "none": "none",
    "poc": "proof_of_concept",
    "public_poc": "proof_of_concept",
    "proof_of_concept": "proof_of_concept",
    "active": "active",
}
SSVC_AUTOMATABLE_VALUES = {"yes": "yes", "no": "no"}
SSVC_TECHNICAL_IMPACT_VALUES = {"partial": "partial", "total": "total"}
SSVC_SOURCE_PREFERENCE = ["vulncheck", "cisa-adp"]


def _ssvc_value(value: str | None, allowed: dict) -> str | None:
    if not value:
        return None
    return allowed.get(value.strip().lower().replace(" ", "_").replace("-", "_"))


def _ssvc_properties(
    exploitation: str | None, automatable: str | None, technical_impact: str | None
) -> dict:
    values = {
        "x_opencti_ssvc_exploitation": _ssvc_value(
            exploitation, SSVC_EXPLOITATION_VALUES
        ),
        "x_opencti_ssvc_automatable": _ssvc_value(automatable, SSVC_AUTOMATABLE_VALUES),
        "x_opencti_ssvc_technical_impact": _ssvc_value(
            technical_impact, SSVC_TECHNICAL_IMPACT_VALUES
        ),
    }
    return {key: value for key, value in values.items() if value is not None}


def get_vulncheck_ssvc_properties(ssvc: list | None) -> dict:
    """SSVC properties from vulncheck-nvd2 `metrics.ssvc`: the VulnCheck entry, else CISA-ADP."""
    by_source = {(entry.source or "").lower(): entry for entry in ssvc or []}
    entry = next((by_source[s] for s in SSVC_SOURCE_PREFERENCE if s in by_source), None)
    if entry is None:
        return {}
    return _ssvc_properties(
        entry.exploitation, entry.automatable, entry.technical_impact
    )


def get_nvd_ssvc_properties(ssvc_v203: list | None) -> dict:
    """SSVC properties from nist-nvd2 `metrics.ssvcV203` decision options."""
    if not ssvc_v203 or ssvc_v203[0].ssvc_data is None:
        return {}
    options = ssvc_v203[0].ssvc_data.options or []

    def pick(field: str) -> str | None:
        return next((v for o in options if (v := getattr(o, field, None))), None)

    return _ssvc_properties(
        pick("exploitation"), pick("automatable"), pick("technical_impact")
    )


def check_vuln_description(descriptions: list) -> str:
    for d in descriptions:
        if d.lang == "en":
            return d.value
    return ""


def build_nvd2_query_params(config, connector_state, source_name: str, logger) -> dict:
    """Resolve the last-modified date window for an NVD2 index query.

    Start-date precedence (mirrors the canonical OpenCTI ``cve`` connector):
      1. explicit ``nvd2_last_mod_start_date`` override (manual backfill)
      2. the per-source last-run date stored in connector state (incremental)
      3. first run -> ``now - nvd2_max_date_range`` days, unless
         ``nvd2_pull_history`` is set, in which case no start filter is sent
         (full historical seed).

    The VulnCheck index API expects ``YYYY-MM-DD`` and paginates by cursor, so a
    single window covers any range (no date chunking needed).
    """
    params: dict = {}
    # explicit override (backfill) -- a datetime, formatted to the API's YYYY-MM-DD
    override = config.vulncheck.nvd2_last_mod_start_date
    start = override.strftime("%Y-%m-%d") if override else None
    origin = "override"

    if not start and connector_state:
        prev = connector_state.get(source_name)  # "%Y-%m-%d %H:%M:%S"
        if prev:
            start, origin = prev.split(" ")[0], "state"

    if (
        not start and not config.vulncheck.nvd2_pull_history
    ):  # first run, bounded window
        start = (datetime.now() - config.vulncheck.nvd2_max_date_range).strftime(
            "%Y-%m-%d"
        )
        origin = "max_date_range"

    if start:
        params["last_mod_start_date"] = start
    else:  # first run + pull_history -> no start filter
        origin = "pull_history"

    if config.vulncheck.nvd2_last_mod_end_date:
        params["last_mod_end_date"] = config.vulncheck.nvd2_last_mod_end_date.strftime(
            "%Y-%m-%d"
        )

    logger.info(
        "NVD2 query window",
        {"params": params or "full history (no filter)", "start_origin": origin},
    )
    return params
