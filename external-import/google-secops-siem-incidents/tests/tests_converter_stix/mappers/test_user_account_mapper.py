"""RED tests — UserAccount mapper.

Tests extraction and deduplication of UserAccount observables from outcomes.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from connectors_sdk.models import UserAccount

# --- import under test (will cause ImportError → RED) ---
from google_secops_siem_incidents.mappers.user_account_mapper import (  # noqa: E402
    map_user_accounts,
)
from tests_converter_stix.factories import (
    make_author,
    make_multi_user_outcomes,
    make_tlp_marking,
    make_user_outcomes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _when_map_users(outcomes):
    return map_user_accounts(
        outcomes,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestUserAccountMapper:
    def test_then_unique_user_accounts_extracted(self):
        """Given principal=['alice','bob'] + target=['bob','charlie'] → 3 unique UserAccount."""
        # _given_
        outcomes = make_user_outcomes(
            principal_users=["alice", "bob"],
            target_users=["bob", "charlie"],
        )

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert len(result) == 3
        assert all(isinstance(u, UserAccount) for u in result)
        user_ids = {u.user_id for u in result}
        assert user_ids == {"alice", "bob", "charlie"}

    def test_then_bob_appears_only_once(self):
        """Deduplication: 'bob' appears in both principal and target → only once in output."""
        # _given_
        outcomes = make_user_outcomes(
            principal_users=["alice", "bob"],
            target_users=["bob", "charlie"],
        )

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        bob_count = sum(1 for u in result if u.user_id == "bob")
        assert bob_count == 1

    def test_then_all_empty_returns_empty_list(self):
        """Given all empty → returns []."""
        # _given_
        outcomes = make_user_outcomes()

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert result == []

    def test_then_empty_outcomes_returns_empty_list(self):
        """Trap guard: Given all outcomes empty → returns []."""
        # _given_
        outcomes = []

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert result == []


class TestUserAccountFields:
    def test_then_account_login_equals_user_id(self):
        """account_login is set to the same value as user_id."""
        # _given_
        outcomes = make_user_outcomes(principal_users=["alice"])

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert result[0].account_login == result[0].user_id == "alice"

    def test_then_account_type_windows_domain_for_backslash_format(self):
        """'CORP\\\\alice' → AccountType.WINDOWS_DOMAIN."""
        # _given_
        outcomes = make_user_outcomes(principal_users=["CORP\\alice"])

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        from connectors_sdk.models.enums import AccountType

        assert result[0].account_type == AccountType.WINDOWS_DOMAIN

    def test_then_account_type_ldap_for_email_format(self):
        """'alice@corp.com' → AccountType.LDAP."""
        # _given_
        outcomes = make_user_outcomes(principal_users=["alice@corp.com"])

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        from connectors_sdk.models.enums import AccountType

        assert result[0].account_type == AccountType.LDAP

    def test_then_account_type_unix_for_plain_username(self):
        """'alice' (no backslash/at) → AccountType.UNIX."""
        # _given_
        outcomes = make_user_outcomes(principal_users=["alice"])

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        from connectors_sdk.models.enums import AccountType

        assert result[0].account_type == AccountType.UNIX

    def test_then_empty_strings_are_filtered(self):
        """Empty strings in string_vals are skipped, non-empty preserved."""
        # _given_
        outcomes = make_user_outcomes(principal_users=["", "alice", ""])

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert len(result) == 1
        assert result[0].user_id == "alice"


class TestUserAccountMapperMultiOutcome:
    def test_then_two_principal_outcomes_all_ids_collected_and_deduplicated(self):
        """Given 2 principal_user_userid outcomes → all user IDs collected + deduplicated."""
        # _given_
        outcomes = make_multi_user_outcomes(
            principal_batches=[["alice", "bob"], ["bob", "charlie"]],
        )

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert len(result) == 3
        user_ids = {u.user_id for u in result}
        assert user_ids == {"alice", "bob", "charlie"}

    def test_then_two_target_outcomes_all_ids_collected_and_deduplicated(self):
        """Given 2 target_user_userid outcomes → all user IDs collected + deduplicated."""
        # _given_
        outcomes = make_multi_user_outcomes(
            target_batches=[["dave", "eve"], ["eve", "frank"]],
        )

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert len(result) == 3
        user_ids = {u.user_id for u in result}
        assert user_ids == {"dave", "eve", "frank"}

    def test_then_mix_of_principal_and_target_batches_all_collected(self):
        """Given mix of principal + target batches → all collected and deduplicated."""
        # _given_
        outcomes = make_multi_user_outcomes(
            principal_batches=[["alice", "bob"], ["charlie"]],
            target_batches=[["bob", "dave"], ["eve"]],
        )

        # _when_
        result = _when_map_users(outcomes)

        # _then_
        assert len(result) == 5
        user_ids = {u.user_id for u in result}
        assert user_ids == {"alice", "bob", "charlie", "dave", "eve"}
