from .base import FilterAwareVerity471Stream


class Verity471CredentialsStream(FilterAwareVerity471Stream):
    """
    Leaked-credentials stream (`/credentials/stream`, Verity471 only).

    Each credential is mapped by the verity471 SDK's `CredentialMapper` into a
    `UserAccount` (plus an `EmailAddress` for email logins, affected `DomainName`s and
    the harvesting infostealer `Malware`, wired with `related-to`). Whether the cleartext
    password is stored in the `UserAccount` `credential` field is governed by the
    `enable_credentials_plain_password` connector setting, threaded into the SDK's
    `STIXMapperSettings` by the core stream base.

    The stream can be narrowed to one or more affiliation groups through the
    `affiliation_group` connector setting. As with the alerts stream, a Verity471 cursor
    is only valid for the filter set it was issued against, so changing the affiliation
    group makes the connector discard the stored cursor and re-anchor the from-date.
    """

    label = "credentials"
    group_label = "credentials"
    api_payload_objects_key = "credentials"
    api_class_name = "CredentialsApi"
    api_method_name = "get_credentials_stream"
    size = 100
    _timestamp_field = "last_updated_ts"

    def _filters_fingerprint(self) -> str:
        affiliation_group = getattr(self.connector_config, "affiliation_group", None)
        return ",".join(sorted(affiliation_group)) if affiliation_group else ""

    def _filter_kwargs(self) -> dict:
        affiliation_group = getattr(self.connector_config, "affiliation_group", None)
        if affiliation_group:
            return {"affiliation_group": ",".join(affiliation_group)}
        return {}
