from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pycti
import stix2
from models._common import BaseEntity, _BaseIndicator


class Indicator(_BaseIndicator):
    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        context=None,
        created=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.context = context
        self.created = created

    def _create_pattern(self, pattern_name: str) -> Any:
        if pattern_name == "yara":
            return self.context
        elif pattern_name == "suricata":
            return self.context
        else:
            msg = f"This pattern value {pattern_name} is not a valid."
            raise ValueError(msg)

    def _generate_indicator(self) -> Any:
        self.stix_main_object = stix2.Indicator(
            id=pycti.Indicator.generate_id(self.name),
            name=self.name,
            description=self.description,
            pattern=self._create_pattern(self.c_type),
            pattern_type=self.c_type,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            created=self.created,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_main_observable_type": self._generate_main_observable_type(
                    self.c_type
                ),
                **self._labels_kv(),
            },
        )
        return self.stix_main_object


class FileHash(_BaseIndicator):
    def __init__(
        self,
        name: list[str],
        c_type: str,
        tlp_color: str = "white",
        labels: list[str] | None = None,
        risk_score: str | None = None,
    ) -> None:
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name: str) -> Any:
        return f"[file:hashes.'{self.determine_hash_algorithm_by_length(pattern_name)}' = '{pattern_name}']"

    def _generate_observable(self) -> Any:
        self.stix_main_object = stix2.File(
            hashes={
                self.determine_hash_algorithm_by_length(_name): _name
                for _name in self.name
                if _name
            },
            object_marking_refs=self.get_markings(),
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                **self._labels_kv(),
                "x_opencti_created_by_ref": self.author.id,
            },
        )
        return self.stix_main_object

    def _generate_indicator(self) -> Any:
        return [
            stix2.Indicator(
                id=pycti.Indicator.generate_id(_name),
                name=_name,
                description=self.description,
                pattern_type="stix",
                valid_from=self.valid_from,
                valid_until=self.valid_until,
                pattern=self._create_pattern(_name),
                created_by_ref=self.author.id,
                object_marking_refs=self.get_markings(),
                custom_properties={
                    "x_opencti_score": self.risk_score or None,
                    "x_opencti_main_observable_type": self._generate_main_observable_type(
                        self.c_type
                    ),
                    **self._labels_kv(),
                },
            )
            for _name in self.name
            if _name
        ]


class IPAddress(_BaseIndicator):
    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name: str) -> Any:
        if self.is_ipv4(pattern_name):
            return f"[ipv4-addr:value = '{pattern_name}']"
        elif self.is_ipv6(pattern_name):
            return f"[ipv6-addr:value = '{pattern_name}']"
        else:
            msg = f"This pattern value {pattern_name} is not a valid IP address."
            raise ValueError(msg)

    def _generate_observable(self) -> Any:
        custom = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_external_references": self.external_references,
        }
        if getattr(self, "description", None):
            custom["x_opencti_description"] = self.description
        ip_cls = stix2.IPv6Address if self.c_type == "ipv6-addr" else stix2.IPv4Address
        self.stix_main_object = ip_cls(
            value=self.name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
        )
        return self.stix_main_object


class URL(_BaseIndicator):
    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name: str) -> Any:
        pattern = f"[url:value = '{self.stix_escape(pattern_name)}']"
        return pattern

    def _generate_observable(self) -> Any:
        custom = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
            "x_opencti_created_by_ref": self.author.id,
        }
        self.stix_main_object = stix2.URL(
            value=self.name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
        )
        return self.stix_main_object


class Domain(_BaseIndicator):
    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name: str) -> Any:
        return f"[domain-name:value = '{pattern_name}']"

    def _generate_observable(self) -> Any:
        custom = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_external_references": self.external_references,
        }
        if getattr(self, "description", None):
            custom["x_opencti_description"] = self.description
        self.stix_main_object = stix2.DomainName(
            value=self.name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
        )
        return self.stix_main_object


class Email(_BaseIndicator):
    def __init__(self, name, c_type, tlp_color="white", labels=None, risk_score=None):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

    def _create_pattern(self, pattern_name: str) -> Any:
        return f"[email-addr:value = '{pattern_name}']"

    def _generate_observable(self) -> Any:
        custom = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_created_by_ref": self.author.id,
        }
        if getattr(self, "description", None):
            custom["x_opencti_description"] = self.description
        self.stix_main_object = stix2.EmailAddress(
            value=self.name,
            display_name=self.name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
        )
        return self.stix_main_object


class UserAccount(BaseEntity):
    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        account_login=None,
        account_type=None,
        display_name=None,
    ):
        super().__init__(name, c_type, tlp_color)
        self.labels = labels or []
        self.account_login = account_login
        self.account_type = account_type
        self.display_name = display_name

    def _generate_observable(self) -> Any:
        custom = {
            **self._labels_kv(),
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_external_references": self.external_references,
        }
        self.stix_main_object = stix2.UserAccount(
            account_login=self.account_login,
            account_type=self.account_type,
            display_name=self.display_name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
        )
        return self.stix_main_object


class PaymentCard(BaseEntity):
    """OpenCTI ``Payment-Card`` cyber observable (native financial SCO).

    The STIX id is derived deterministically from ``card_number`` by pycti's
    ``CustomObservablePaymentCard`` (id-contributing property), so re-ingesting
    the same card updates the same observable instead of duplicating it.
    """

    def __init__(
        self,
        name,
        c_type="payment-card",
        tlp_color="white",
        labels=None,
        expiration_date=None,
        cvv=None,
        holder_name=None,
    ):
        super().__init__(name, c_type, tlp_color)
        self.labels = labels or []
        self.expiration_date = expiration_date
        self.cvv = cvv
        self.holder_name = holder_name

    @staticmethod
    def _coerce_expiration(value: Any) -> str | None:
        if not value:
            return None
        s = str(value).strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _generate_observable(self) -> Any:
        custom = {
            **self._labels_kv(),
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_external_references": self.external_references,
        }
        if getattr(self, "description", None):
            custom["x_opencti_description"] = self.description
        optional = {}
        exp = self._coerce_expiration(self.expiration_date)
        if exp:
            optional["expiration_date"] = exp
        if self.cvv:
            optional["cvv"] = str(self.cvv)
        if self.holder_name:
            optional["holder_name"] = str(self.holder_name)
        self.stix_main_object = pycti.CustomObservablePaymentCard(
            value=self.name,
            card_number=self.name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
            **optional,
        )
        return self.stix_main_object


class BankAccount(BaseEntity):
    """OpenCTI ``Bank-Account`` cyber observable (native financial SCO).

    The STIX id is derived deterministically from ``iban`` by pycti's
    ``CustomObservableBankAccount`` (id-contributing property).
    """

    def __init__(
        self,
        name,
        c_type="bank-account",
        tlp_color="white",
        labels=None,
        bic=None,
        account_number=None,
    ):
        super().__init__(name, c_type, tlp_color)
        self.labels = labels or []
        self.bic = bic
        self.account_number = account_number

    def _generate_observable(self) -> Any:
        custom = {
            **self._labels_kv(),
            "x_opencti_created_by_ref": self.author.id,
            "x_opencti_external_references": self.external_references,
        }
        if getattr(self, "description", None):
            custom["x_opencti_description"] = self.description
        optional = {}
        if self.bic:
            optional["bic"] = str(self.bic)
        if self.account_number:
            optional["account_number"] = str(self.account_number)
        self.stix_main_object = pycti.CustomObservableBankAccount(
            value=self.name,
            iban=self.name,
            object_marking_refs=self.get_markings(),
            custom_properties=custom,
            **optional,
        )
        return self.stix_main_object
