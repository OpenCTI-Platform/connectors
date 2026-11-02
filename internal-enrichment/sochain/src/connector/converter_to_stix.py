"""STIX shaping for the SoChain enrichment connector.

The enriched Cryptocurrency-Wallet observable is updated in place by the
connector via ``OpenCTIStix2.put_attribute_in_extension``. This module only
mints the extra objects: the author Identity and the address-poisoning Note.
Every object carries a deterministic STIX id.
"""

import stix2
from pycti import Identity, Note


class ConverterToStix:
    def __init__(self, author: stix2.Identity) -> None:
        self.author = author

    @staticmethod
    def make_author() -> stix2.Identity:
        return stix2.Identity(
            id=Identity.generate_id(name="SoChain", identity_class="organization"),
            name="SoChain",
            identity_class="organization",
            description=(
                "Blockchain explorer and API for Bitcoin, Litecoin, Dogecoin "
                "and Zcash."
            ),
            external_references=[
                stix2.ExternalReference(
                    source_name="SoChain",
                    url="https://sochain.com",
                )
            ],
        )

    def poisoning_note(
        self,
        network: str,
        address: str,
        content: str,
        count: int,
        observable_id: str,
        markings: list,
    ) -> stix2.Note:
        # Stable per-address id: a later enrichment updates this note instead
        # of adding another. Keyed on the address, not on the content, which
        # changes as new findings come in.
        return stix2.Note(
            id=Note.generate_id(
                None, f"SoChain address poisoning of {network} {address}"
            ),
            abstract=(
                f"Address poisoning: {count} look-alike address"
                f"{'' if count == 1 else 'es'} sent this address dust"
            ),
            content=content,
            created_by_ref=self.author["id"],
            object_refs=[observable_id],
            object_marking_refs=markings,
            custom_properties={"note_types": ["external"]},
        )
