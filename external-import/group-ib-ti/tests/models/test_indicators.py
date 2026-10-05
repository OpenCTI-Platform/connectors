from __future__ import annotations

from datetime import datetime, timezone

import pytest
from models.indicators import (
    URL,
    BankAccount,
    Domain,
    Email,
    FileHash,
    Indicator,
    IPAddress,
    PaymentCard,
    UserAccount,
)

# Shared helper: stix2.Indicator rejects ``valid_until == valid_from``.
# ``BaseEntity.__init__`` sets ``valid_until = datetime.now(UTC)`` and
# ``valid_from = None``, which stix2 normalises to "now" — colliding with
# valid_until. We pre-seed an earlier valid_from on every IOC test.
_VALID_FROM = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _arm_indicator(wrapper):
    wrapper.set_valid_from(_VALID_FROM)
    return wrapper


# --- Indicator (YARA / Suricata) ---------------------------------------------


class TestIndicator:
    def test_yara_pattern_uses_context(self):
        ind = Indicator(
            name="Rule_X",
            c_type="yara",
            context="rule Rule_X { condition: true }",
        )
        ind.is_ioc = True
        _arm_indicator(ind)
        ind.generate_stix_objects()
        assert ind.stix_main_object.pattern_type == "yara"
        assert "condition" in ind.stix_main_object.pattern

    def test_suricata_pattern_uses_context(self):
        ind = Indicator(
            name="suricata-rule",
            c_type="suricata",
            context="alert tcp any any -> any 80",
        )
        ind.is_ioc = True
        _arm_indicator(ind)
        ind.generate_stix_objects()
        assert ind.stix_main_object.pattern_type == "suricata"
        assert "alert tcp" in ind.stix_main_object.pattern

    def test_invalid_pattern_type_raises(self):
        ind = Indicator(name="x", c_type="not-supported", context="anything")
        ind.is_ioc = True
        _arm_indicator(ind)
        with pytest.raises(ValueError, match="not a valid"):
            ind.generate_stix_objects()

    def test_score_propagates(self):
        ind = Indicator(
            name="rule",
            c_type="yara",
            context="rule x {}",
            risk_score=80,
        )
        ind.is_ioc = True
        _arm_indicator(ind)
        ind.generate_stix_objects()
        assert ind.stix_main_object["x_opencti_score"] == 80


# --- FileHash ----------------------------------------------------------------


class TestFileHash:
    MD5 = "d41d8cd98f00b204e9800998ecf8427e"
    SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_observable_carries_all_hashes(self):
        fh = FileHash(name=[self.MD5, self.SHA1, self.SHA256], c_type="file")
        fh.generate_stix_objects()
        obs = fh.stix_observable
        assert obs.hashes["MD5"] == self.MD5
        assert obs.hashes["SHA-1"] == self.SHA1
        assert obs.hashes["SHA-256"] == self.SHA256

    def test_observable_skips_blank_hashes(self):
        fh = FileHash(name=[self.MD5, "", None], c_type="file")
        fh.generate_stix_objects()
        # Only the valid MD5 ends up on the observable.
        assert list(fh.stix_observable.hashes.keys()) == ["MD5"]

    def test_indicator_one_per_hash(self):
        fh = FileHash(name=[self.MD5, self.SHA256], c_type="file")
        fh.is_ioc = True
        _arm_indicator(fh)
        fh.generate_stix_objects()
        # ``_generate_indicator`` returns a list — one Indicator per hash.
        assert isinstance(fh.stix_indicator, list)
        assert len(fh.stix_indicator) == 2
        for ind in fh.stix_indicator:
            assert "file:hashes" in ind.pattern


# --- IPAddress ---------------------------------------------------------------


class TestIPAddress:
    def test_ipv4_observable(self):
        ip = IPAddress(name="192.0.2.1", c_type="ipv4-addr")
        ip.generate_stix_objects()
        # stix2.IPv4Address has type "ipv4-addr".
        assert ip.stix_observable.type == "ipv4-addr"
        assert ip.stix_observable.value == "192.0.2.1"

    def test_ipv6_observable(self):
        ip = IPAddress(name="::1", c_type="ipv6-addr")
        ip.generate_stix_objects()
        assert ip.stix_observable.type == "ipv6-addr"

    def test_ipv4_pattern(self):
        ip = IPAddress(name="192.0.2.1", c_type="ipv4-addr")
        ip.is_ioc = True
        _arm_indicator(ip)
        ip.generate_stix_objects()
        assert ip.stix_indicator.pattern == "[ipv4-addr:value = '192.0.2.1']"

    def test_ipv6_pattern(self):
        ip = IPAddress(name="::1", c_type="ipv6-addr")
        ip.is_ioc = True
        _arm_indicator(ip)
        ip.generate_stix_objects()
        assert "ipv6-addr:value" in ip.stix_indicator.pattern

    def test_invalid_ip_pattern_raises(self):
        ip = IPAddress(name="not-an-ip", c_type="ipv4-addr")
        ip.is_ioc = True
        _arm_indicator(ip)
        with pytest.raises(ValueError, match="not a valid IP"):
            ip.generate_stix_objects()

    def test_description_carried_in_observable(self):
        ip = IPAddress(name="192.0.2.1", c_type="ipv4-addr")
        ip.set_description("DDoS source")
        ip.generate_stix_objects()
        assert ip.stix_observable["x_opencti_description"] == "DDoS source"


# --- URL ---------------------------------------------------------------------


class TestURL:
    def test_observable(self):
        u = URL(name="https://example.com/x", c_type="url")
        u.generate_stix_objects()
        assert u.stix_observable.type == "url"
        assert u.stix_observable.value == "https://example.com/x"

    def test_pattern_escapes_single_quote(self):
        # ``stix_escape`` doubles backslashes and escapes single quotes.
        u = URL(name="https://example.com/q?a='1'", c_type="url")
        u.is_ioc = True
        _arm_indicator(u)
        u.generate_stix_objects()
        # Single quotes inside the value must be escaped in the STIX pattern.
        assert "\\'" in u.stix_indicator.pattern


# --- Domain ------------------------------------------------------------------


class TestDomain:
    def test_observable(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.generate_stix_objects()
        assert d.stix_observable.type == "domain-name"
        assert d.stix_observable.value == "example.com"

    def test_pattern(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.is_ioc = True
        _arm_indicator(d)
        d.generate_stix_objects()
        assert d.stix_indicator.pattern == "[domain-name:value = 'example.com']"

    def test_description_carried(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.set_description("phishing host")
        d.generate_stix_objects()
        assert d.stix_observable["x_opencti_description"] == "phishing host"


# --- Email -------------------------------------------------------------------


class TestEmail:
    def test_observable(self):
        e = Email(name="alice@example.com", c_type="email-addr")
        e.generate_stix_objects()
        assert e.stix_observable.type == "email-addr"
        assert e.stix_observable.value == "alice@example.com"
        # display_name mirrors the value.
        assert e.stix_observable.display_name == "alice@example.com"

    def test_pattern(self):
        e = Email(name="a@example.com", c_type="email-addr")
        e.is_ioc = True
        _arm_indicator(e)
        e.generate_stix_objects()
        assert e.stix_indicator.pattern == "[email-addr:value = 'a@example.com']"


# --- UserAccount -------------------------------------------------------------


class TestUserAccount:
    def test_observable(self):
        ua = UserAccount(
            name="alice",
            c_type="user-account",
            account_login="alice",
            account_type="email",
            display_name="Alice",
        )
        ua.generate_stix_objects()
        obs = ua.stix_observable
        assert obs.type == "user-account"
        assert obs.account_login == "alice"
        assert obs.account_type == "email"
        assert obs.display_name == "Alice"

    def test_no_indicator_path(self):
        # UserAccount inherits from BaseEntity (no _BaseIndicator); even
        # with is_ioc=True it should not produce an Indicator SDO.
        ua = UserAccount(name="alice", c_type="user-account")
        ua.is_ioc = True
        ua.generate_stix_objects()
        assert ua.stix_indicator is None


# --- PaymentCard -------------------------------------------------------------


class TestPaymentCard:
    def test_minimal(self):
        pc = PaymentCard(name="4111111111111111")
        pc.generate_stix_objects()
        # ``pycti.CustomObservablePaymentCard`` exposes value/card_number.
        assert pc.stix_main_object["card_number"] == "4111111111111111"

    def test_with_full_metadata(self):
        pc = PaymentCard(
            name="4111111111111111",
            cvv="123",
            holder_name="Alice",
            expiration_date="2025-12-31T23:59:59Z",
        )
        pc.generate_stix_objects()
        obs = pc.stix_main_object
        assert obs["cvv"] == "123"
        assert obs["holder_name"] == "Alice"
        assert obs["expiration_date"].endswith("Z")

    def test_invalid_expiration_dropped(self):
        pc = PaymentCard(
            name="4111111111111111",
            expiration_date="not-a-date",
        )
        pc.generate_stix_objects()
        # Bad-date input is silently dropped (the SCO stays clean).
        assert "expiration_date" not in pc.stix_main_object

    def test_blank_expiration_dropped(self):
        pc = PaymentCard(name="x", expiration_date="   ")
        pc.generate_stix_objects()
        assert "expiration_date" not in pc.stix_main_object

    def test_coerce_expiration_static_helper(self):
        out = PaymentCard._coerce_expiration("2025-01-01T00:00:00Z")
        assert out == "2025-01-01T00:00:00Z"
        # Naive ISO string is parsed then stamped UTC ("Z").
        out = PaymentCard._coerce_expiration("2025-01-01T00:00:00")
        assert out is not None and out.endswith("Z")

    def test_coerce_expiration_none(self):
        assert PaymentCard._coerce_expiration(None) is None
        assert PaymentCard._coerce_expiration("") is None


# --- BankAccount -------------------------------------------------------------


class TestBankAccount:
    def test_minimal(self):
        ba = BankAccount(name="GB82WEST12345698765432")
        ba.generate_stix_objects()
        assert ba.stix_main_object["iban"] == "GB82WEST12345698765432"

    def test_with_bic_and_account_number(self):
        ba = BankAccount(
            name="GB82WEST12345698765432",
            bic="WESTGB22",
            account_number="98765432",
        )
        ba.generate_stix_objects()
        obs = ba.stix_main_object
        assert obs["bic"] == "WESTGB22"
        assert obs["account_number"] == "98765432"

    def test_description_propagates(self):
        ba = BankAccount(name="GB82WEST12345698765432")
        ba.set_description("Mule account")
        ba.generate_stix_objects()
        assert ba.stix_main_object["x_opencti_description"] == "Mule account"


# --- _BaseIndicator (models/_common.py) -------------------------------------


class TestBaseIndicatorBasePattern:
    def test_base_create_pattern_returns_none(self):
        # ``_BaseIndicator._create_pattern`` is a fallback returning None
        # for callers that don't override it. Subclasses (URL/Domain/IP/
        # FileHash/Email) all override; the base shows up only when a
        # bare ``_BaseIndicator`` is constructed directly.
        from models._common import _BaseIndicator

        ind = _BaseIndicator(
            name="x",
            c_type="other",
            tlp_color="amber",
            labels=None,
            risk_score=None,
        )
        assert ind._create_pattern("anything") is None


class TestEmailDescriptionPropagation:
    def test_email_description_carries_into_observable(self):
        # When ``description`` is set on the wrapper, it lands on
        # ``x_opencti_description`` of the resulting Email-Addr SCO.
        e = Email(name="alice@example.com", c_type="email-addr")
        e.set_description("phishing target")
        e.generate_stix_objects()
        assert e.stix_observable["x_opencti_description"] == "phishing target"


class TestPaymentCardDescriptionPropagation:
    def test_payment_card_description_carries_into_observable(self):
        # Same description branch on the Payment-Card SCO.
        pc = PaymentCard(name="4111111111111111")
        pc.set_description("Stolen card")
        pc.generate_stix_objects()
        assert pc.stix_main_object["x_opencti_description"] == "Stolen card"
