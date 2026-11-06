from pathlib import Path

CONFIG_FILE_PATH = Path(__file__).parents[2].joinpath("config.yml")
MAX_AUTHORIZED = 120

# Hard resource bounds, independent of operator concurrency/history settings.
MAX_CPES_PER_CVE = 100
MAX_CPE_PAGES_PER_CVE = 10
MAX_CVES_PER_ENTITY = 100
CVES_PER_CHUNK = 5
