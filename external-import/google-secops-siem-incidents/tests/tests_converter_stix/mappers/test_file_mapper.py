"""RED tests — File mapper.

Tests extraction of File observables (with name and SHA-256 hashes) from outcomes.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from connectors_sdk.models import File
from connectors_sdk.models.enums import HashAlgorithm
from tests_converter_stix.factories import (
    make_author,
    make_file_outcomes,
    make_tlp_marking,
)

# Valid 64-char hex SHA-256 placeholder hashes for tests.
_SHA256_A = "abc123" + "0" * 58
_SHA256_B = "def456" + "0" * 58


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _when_map_files(outcomes):
    return map_files(
        outcomes,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestFileMapper:
    def test_then_principal_file_extracted_with_hash(self):
        """Given principal path '/usr/bin/curl' + valid sha256 → File(name='curl', hashes={SHA256: ...})."""
        # _given_
        outcomes = make_file_outcomes(
            principal_path="/usr/bin/curl",
            principal_sha256=_SHA256_A,
        )

        # _when_
        result = _when_map_files(outcomes)

        # _then_
        assert len(result) >= 1
        curl_files = [f for f in result if f.name == "curl"]
        assert len(curl_files) == 1
        assert curl_files[0].hashes == {HashAlgorithm.SHA256: _SHA256_A}

    def test_then_target_file_extracted_with_hash(self):
        """Given target path '/tmp/payload.exe' + valid sha256 → File(name='payload.exe', ...)."""
        # _given_
        outcomes = make_file_outcomes(
            target_path="/tmp/payload.exe",
            target_sha256=_SHA256_B,
        )

        # _when_
        result = _when_map_files(outcomes)

        # _then_
        assert len(result) >= 1
        payload_files = [f for f in result if f.name == "payload.exe"]
        assert len(payload_files) == 1
        assert payload_files[0].hashes == {HashAlgorithm.SHA256: _SHA256_B}

    def test_then_both_principal_and_target_files(self):
        """Given principal + target file paths → 2 File objects."""
        # _given_
        outcomes = make_file_outcomes(
            principal_path="/usr/bin/curl",
            principal_sha256=_SHA256_A,
            target_path="/tmp/payload.exe",
            target_sha256=_SHA256_B,
        )

        # _when_
        result = _when_map_files(outcomes)

        # _then_
        assert len(result) == 2
        assert all(isinstance(f, File) for f in result)

    def test_then_path_present_but_hash_absent(self):
        """Given path present but hash absent → File(name=..., hashes=None)."""
        # _given_
        outcomes = make_file_outcomes(
            principal_path="/usr/bin/curl",
            principal_sha256=None,
        )

        # _when_
        result = _when_map_files(outcomes)

        # _then_
        assert len(result) == 1
        assert result[0].name == "curl"
        assert result[0].hashes is None

    def test_then_all_file_outcomes_empty_returns_empty(self):
        """Given all file outcomes empty → returns []."""
        # _given_
        outcomes = make_file_outcomes()

        # _when_
        result = _when_map_files(outcomes)

        # _then_
        assert result == []

    def test_then_empty_outcomes_list_returns_empty(self):
        """Trap guard: Given all file outcomes empty → returns []."""
        # _given_
        outcomes = []

        # _when_
        result = _when_map_files(outcomes)

        # _then_
        assert result == []
