"""Meta used in the whole pipeline for reports ingestion."""

import asyncio
from typing import Dict

SENTINEL = object()
PREFIX_BROKER = "reports_ingest"
REPORTS_BROKER = f"{PREFIX_BROKER}/reports"
FINAL_BROKER = f"{PREFIX_BROKER}/final"
LAST_WORK_START_DATE_STATE_KEY = "last_work_start_date"
LAST_INGESTED_REPORT_MODIFICATION_DATE_STATE_KEY = (
    "last_ingested_report_modification_date"
)
EVENT_MAP: Dict[str, asyncio.Event] = {}


MALWARE_FAMILIES_BROKER = f"{PREFIX_BROKER}/malware_families"
