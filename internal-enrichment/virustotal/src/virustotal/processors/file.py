from typing import TYPE_CHECKING

from virustotal.processors.entity import EntityProcessor

if TYPE_CHECKING:
    from virustotal.builder import VirusTotalBuilder


class FileProcessor(EntityProcessor):
    """Enriches StixFile, Artifact, and file-type Indicators."""

    def _fetch_data(self) -> dict | None:
        hash_value = self._resolve_hash()
        json_data = self.client.get_file_info(hash_value)

        # Artifacts that VT has never seen can be uploaded for analysis.
        # This is skipped for Indicators (no file bytes available) and StixFiles.
        if (
            json_data
            and "error" in json_data
            and json_data["error"]["code"] == "NotFoundError"
            and not self.is_indicator
            and self.connector.file_upload_unseen_artifacts
            and self.opencti_entity["entity_type"] == "Artifact"
        ):
            json_data = self._upload_artifact_and_recheck(hash_value)

        return json_data

    def _enrich(self, builder: "VirusTotalBuilder", json_data: dict) -> None:
        attributes = json_data["data"]["attributes"]

        if not self.is_indicator:
            # Observable-specific updates (mutate the SCO stix entity).
            builder.update_hashes()
            if self.opencti_entity["entity_type"] == "StixFile":
                builder.update_size()
            builder.update_names(
                self.opencti_entity["entity_type"] == "StixFile"
                and not self.opencti_entity.get("name")
            )
            builder.create_indicator_based_on(
                self.connector.file_indicator_config,
                f"""[file:hashes.'SHA-256' = '{attributes["sha256"]}']""",
            )

        builder.update_labels()

        if self.connector.file_import_yara:
            for yara in attributes.get("crowdsourced_yara_results", []):
                ruleset = self.connector._retrieve_yara_ruleset(
                    yara.get("ruleset_id", "No ruleset id provided")
                )
                builder.create_yara(
                    yara,
                    ruleset,
                    attributes.get("creation_date"),
                )

        if (
            self.connector.file_create_note_full_report
            and "last_analysis_results" in attributes
        ):
            content = self._build_full_report_content(json_data["data"], builder)
            builder.create_note("VirusTotal Report", content)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_hash(self) -> str:
        """Return the best available hash for the VT file lookup.

        For indicators the hash comes from ``opencti_entity["observable_value"]``
        (already resolved by :meth:`~VirusTotalConnector._extract_observable_from_indicator`).
        For observables it is read from the SCO ``hashes`` dict, preferring
        SHA-256 over SHA-1 over MD5.
        """
        if self.is_indicator:
            return self.opencti_entity["observable_value"]

        hashes = self.stix_entity.get("hashes", {})
        for algo in ("SHA-256", "SHA-1", "MD5"):
            if algo in hashes:
                return hashes[algo]

        raise ValueError(
            "Unable to enrich the observable: it has no SHA-256, SHA-1, or MD5 hash."
        )

    def _upload_artifact_and_recheck(self, hash_value: str) -> dict | None:
        """Upload an unseen Artifact to VT and wait for analysis to complete.

        Returns ``None`` when the artifact has no associated file bytes,
        signalling the caller to skip enrichment entirely (mirrors the
        original ``return`` early-exit in ``_process_file``).
        """
        import_files = self.opencti_entity.get("importFiles", [])
        if not import_files:
            return None

        file_meta = import_files[0]
        if file_meta["size"] > 33_554_432:
            msg = (
                "The file attempting to be uploaded is greater than VirusTotal's "
                "32 MB limit."
            )
            raise ValueError(msg)

        message = (
            f"The file {hash_value} was not found in VirusTotal repositories. "
            "Beginning upload and analysis."
        )
        self.helper.api.work.to_received(self.helper.work_id, message)
        self.helper.log_debug(message)

        artifact_url = f"{self.helper.opencti_url}/storage/get/{file_meta['id']}"
        try:
            artifact = self.helper.api.fetch_opencti_file(artifact_url, binary=True)
        except Exception as err:
            raise ValueError(
                "[VirusTotal] Error fetching artifact from OpenCTI."
            ) from err

        try:
            analysis_id = self.client.upload_artifact(file_meta["name"], artifact)
            # Queuing the file info call triggers more immediate analysis.
            self.client.get_file_info(hash_value)
        except Exception as err:
            raise ValueError(
                "[VirusTotal] Error uploading artifact to VirusTotal."
            ) from err

        try:
            self.client.check_upload_status("artifact", hash_value, analysis_id)
        except Exception as err:
            raise ValueError(
                "[VirusTotal] Error waiting for VirusTotal to analyse artifact."
            ) from err

        return self.client.get_file_info(hash_value)

    @staticmethod
    def _build_full_report_content(data: dict, builder: "VirusTotalBuilder") -> str:
        """Build the markdown content for the full analysis report Note."""
        attrs = data["attributes"]
        stats = attrs["last_analysis_stats"]
        results = attrs["last_analysis_results"]

        rows = [
            (
                "| Total Analyses | Malicious | Suspicious | Undetected | Harmless"
                " | Timeout | Confirmed timeout | Failure | Unsupported |"
            ),
            (
                "|----------------|-----------|------------|------------|---------"
                "-|---------|-------------------|---------|-------------|"
            ),
            (
                f"| {len(results)} | {stats['malicious']} | {stats['suspicious']} |"
                f" {stats['undetected']} | {stats['harmless']} | {stats['timeout']} |"
                f" {stats['confirmed-timeout']} | {stats['failure']} |"
                f" {stats['type-unsupported']} |"
            ),
        ]

        engine_rows = [
            "## Last Analysis Results\n",
            "Any falsy value will be replaced by 'N/A'",
            "| Engine name | Engine version | Method | Category | Result |",
            "|-------------|----------------|--------|----------|--------|",
        ]
        for result in results.values():
            engine_rows.append(
                f"| {result.get('engine_name') or 'N/A'}"
                f" | {result.get('engine_version') or 'N/A'}"
                f" | {result.get('method') or 'N/A'}"
                f" | {result.get('category') or 'N/A'}"
                f" | {result.get('result') or 'N/A'} |"
            )

        content = "\n".join(rows) + "\n\n" + "\n".join(engine_rows)
        content += builder.create_notes_attributes_content()
        return content
