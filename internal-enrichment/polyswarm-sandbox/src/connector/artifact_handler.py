from typing import Any


class ArtifactHandler:
    def __init__(
        self, helper, max_file_size: int = 33554432, download_enabled: bool = True
    ) -> None:
        self.helper = helper
        self.max_file_size: int = max_file_size
        self.download_enabled: bool = download_enabled

    def download_artifact(
        self, entity: dict[str, Any]
    ) -> tuple[bytes | None, str | None]:
        """Download artifact from OpenCTI, enforcing max_file_size.

        Returns:
            Tuple of (file_data, error_reason).
            On success: (bytes, None)
            On failure: (None, "human-readable error string")
        """
        try:
            if not self.download_enabled:
                return (
                    None,
                    "Artifact download is disabled in connector configuration (POLYSWARM_DOWNLOAD_ARTIFACTS=false)",
                )

            import_files = entity.get("importFiles", [])
            if not import_files:
                return (
                    None,
                    "No file attached to this artifact. Upload a file to the artifact before enriching.",
                )

            file_id = import_files[0].get("id")
            if not file_id:
                return (
                    None,
                    "Artifact file entry has no ID — the file may be corrupt or incomplete.",
                )

            # Check file size before downloading
            file_size = import_files[0].get("size")
            file_name = import_files[0].get("name", "unknown")
            max_mb = round(self.max_file_size / (1024 * 1024), 1)

            if file_size is not None and int(file_size) > self.max_file_size:
                size_mb = round(int(file_size) / (1024 * 1024), 1)
                return None, (
                    f"File '{file_name}' is {size_mb} MB which exceeds the maximum allowed size "
                    f"of {max_mb} MB ({self.max_file_size} bytes). "
                    f"Contact PolySwarm to increase your file size limit."
                )

            file_uri = f"{self.helper.api.api_url.replace('/graphql', '')}/storage/get/{file_id}"
            file_data = self.helper.api.fetch_opencti_file(file_uri, True)

            # Distinguish a real download failure (``None``) from a
            # successfully-downloaded empty file (``b""``). The previous
            # ``if not file_data:`` short-circuited both cases through
            # the "Failed to download" branch and made the
            # ``len(file_data) == 0`` check below unreachable, returning
            # a misleading error for empty-file submissions.
            if file_data is None:
                return (
                    None,
                    f"Failed to download file '{file_name}' from OpenCTI storage — file may have been deleted.",
                )

            # Check actual downloaded size (metadata may be absent or wrong)
            if len(file_data) > self.max_file_size:
                size_mb = round(len(file_data) / (1024 * 1024), 1)
                return None, (
                    f"Downloaded file '{file_name}' is {size_mb} MB which exceeds the maximum allowed size "
                    f"of {max_mb} MB ({self.max_file_size} bytes). "
                    f"Contact PolySwarm to increase your file size limit."
                )

            if len(file_data) == 0:
                return (
                    None,
                    f"File '{file_name}' is empty (0 bytes). Cannot submit an empty file for analysis.",
                )

            return file_data, None

        except (OSError, KeyError) as e:
            return None, f"File download I/O error: {str(e)}"
        except Exception as e:
            return None, f"Unexpected download error: {type(e).__name__}: {str(e)}"
