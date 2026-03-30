#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION="${1:?Usage: $0 <version>}"

CONNECTORS="
    external-import/alienvault
    external-import/cisa-known-exploited-vulnerabilities
    external-import/crowdstrike
    external-import/cve
    external-import/group-ib
    external-import/mitre
    external-import/opencti
    external-import/recorded-future
    external-import/servicenow
    internal-enrichment/first-epss
    internal-enrichment/google-dns
    internal-enrichment/import-external-reference
    internal-enrichment/ipinfo
    internal-enrichment/tagger
    internal-enrichment/virustotal
    internal-export-file/export-file-csv
    internal-export-file/export-file-stix
    internal-export-file/export-file-txt
    internal-export-file/export-file-yara
    internal-export-file/export-report-pdf
    internal-export-file/export-ttps-file-navigator
    internal-import-file/import-document
    internal-import-file/import-document-ai
    internal-import-file/import-file-misp
    internal-import-file/import-file-stix
    internal-import-file/import-file-yara
    internal-import-file/import-ttps-file-navigator
    stream/crowdstrike-endpoint-security
    stream/taxii-post
"

FAILED=""
for connector in ${CONNECTORS}; do
    echo "=========================================="
    echo "Building ${connector}..."
    echo "=========================================="
    if "${SCRIPT_DIR}/build_ubi9.sh" "${connector}" "${VERSION}"; then
        echo "OK: ${connector}"
    else
        echo "FAILED: ${connector}"
        FAILED="${FAILED} ${connector}"
    fi
    echo ""
done

if [ -n "${FAILED}" ]; then
    echo "=========================================="
    echo "The following builds failed:"
    for f in ${FAILED}; do
        echo "  - ${f}"
    done
    echo "=========================================="
    exit 1
fi

echo "All UBI9 builds succeeded."

