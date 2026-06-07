from censys_enrichment.converters.base import CensysConverter, ObservableLike
from censys_platform import Certificate


class CertificateConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> list[Certificate]:
        return list(self._require_client().fetch_certs(hashes=observable["hashes"]))

    def _convert(self, observable: ObservableLike, data: list[Certificate]) -> None:
        self.builder.add_author_and_marking()
        for cert in data:
            self.builder.add_certificate(cert=cert)
