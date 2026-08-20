from datetime import datetime


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
