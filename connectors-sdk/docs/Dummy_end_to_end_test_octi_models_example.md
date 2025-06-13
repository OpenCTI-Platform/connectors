# Dummy End to End Octi Models Test Examples

Here is a minimal example of how to test the end-to-end functionality of the `connectors_sdk.models.octi` package and see the results in the Octi UI.

```python
"""Minimal exemple of OpenCTI connector using connectors-sdk octi model objects."""

import sys
import traceback
from typing import TYPE_CHECKING

import pycti  # type: ignore[import-untyped] # pycti does not provide stubs
from connectors_sdk.models.octi import (
    ExternalReference,
    Indicator,
    IPV4Address,
    Organization,
    OrganizationAuthor,
    TLPMarking,
    based_on,
    related_to,
)

if TYPE_CHECKING:
    from connectors_sdk.models.octi import BaseEntity


class ConnectorExample:
    """Example OpenCTI connector using connectors-sdk."""

    def __init__(self) -> None:
        """Initialize the connector."""
        self.helper = pycti.OpenCTIConnectorHelper(
            config={
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "ChangeMe",
                },
                "connector": {
                    "id": "example",
                    "type": "EXTERNAL_IMPORT",
                    "name": "Example",
                    "scope": "example",
                    "log_level": "debug",
                },
            }
        )

    def work(self) -> None:
        """Define the connector work."""
        try:
            octi_models: list[BaseEntity] = []  # results holder

            # TLP Marking
            tlp_marking = TLPMarking(level="amber+strict")
            octi_models.append(tlp_marking)
            # Author
            author = OrganizationAuthor(
                name="Example Author",
            )
            octi_models.append(author)
            # Indicator
            indicator = Indicator(
                name="my_indicator",
                author=author,
                markings=[tlp_marking],
                pattern="[url:value = 'https://example.com']",
                pattern_type="stix",
            )
            octi_models.append(indicator)
            # Organization
            organization = Organization(
                name="Example Corp",
                author=author,
                markings=[tlp_marking],
                external_references=[
                    ExternalReference(
                        source_name="Example Source",
                        url="https://example.com/reference",
                    )
                ],
            )
            octi_models.append(organization)
            # IPV4Address
            observable = IPV4Address(
                value="127.0.0.1", author=author, markings=[tlp_marking]
            )
            octi_models.append(observable)
            # Related-to
            rel_related_to = observable | related_to | organization  # type: ignore[operator]
            octi_models.append(rel_related_to)
            # Based-on
            rel_based_on = indicator | based_on | observable  # type: ignore[operator]
            octi_models.append(rel_based_on)
            # Indicator with conversion
            indicator_with_obs = Indicator(
                name="my_indicator_with_obs",
                pattern="[domain-name:value = 'example.com']",
                pattern_type="stix",
                author=author,
                markings=[tlp_marking],
                create_observables=True,
            )
            octi_models.append(indicator_with_obs)
            # Observable with conversion
            observable_with_ind = IPV4Address(
                value="127.0.0.2",
                author=author,
                markings=[tlp_marking],
                create_indicator=True,
            )
            octi_models.append(observable_with_ind)

            stix_objects = [m.to_stix2_object() for m in octi_models]

            if len(stix_objects):
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, self.helper.connect_name
                )
                _ = self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(stix_objects),
                    work_id=work_id,
                )
                self.helper.api.work.to_processed(work_id, "Done")

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Run the connector."""
        self.helper.schedule_iso(
            message_callback=self.work,
            duration_period="PT0M",  # zero => run and terminate
        )


if __name__ == "__main__":
    try:
        connector = ConnectorExample()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
```

## Results

OCTI UI Data Entities:

![OCTI UI Indicators](Dummy_end_to_end_test_octi_models_example_data\Indicators.png)
![OCTI UI Observables](Dummy_end_to_end_test_octi_models_example_data\Observables.png)
![OCTI UI Relationships](Dummy_end_to_end_test_octi_models_example_data\Relationships.png)
![OCTI UI Organization](Dummy_end_to_end_test_octi_models_example_data\Organization_with_external_ref.png)
