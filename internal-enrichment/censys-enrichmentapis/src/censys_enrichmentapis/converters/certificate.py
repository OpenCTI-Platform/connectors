from censys_enrichmentapis.converters.base import CensysConverter, ObservableLike
from censys_platform import Certificate


class CertificateConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> list[Certificate]:
        # An X509 observable may carry no ``hashes`` at all; let the client
        # raise ``EntityHasNoUsableHashError`` rather than failing on a KeyError.
        return list(
            self._require_client().fetch_certs(hashes=observable.get("hashes") or {})
        )

    def _convert(self, observable: ObservableLike, data: list[Certificate]) -> None:
        self.builder.add_author_and_marking()
        for cert in data:
            self.builder.certificates.add_certificate(cert=cert)
