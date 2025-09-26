import pycti
import stix2
import stix2.exceptions
from api_client.models import GalaxyItem

from .common import ConverterConfig, ConverterError
from .utils import is_uuid


class GalaxyConverterError(ConverterError):
    """Custom exception for event's galaxies conversion errors."""


class GalaxyConverter:
    def __init__(self, config: ConverterConfig):
        self.config = config

    def create_intrusion_set(
        self,
        galaxy_entity,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.IntrusionSet | None:
        if " - G" in galaxy_entity["value"]:
            name = galaxy_entity["value"].split(" - G")[0]
        elif "APT " in galaxy_entity["value"]:
            name = galaxy_entity["value"].replace("APT ", "APT")
        else:
            name = galaxy_entity["value"]
        if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
            aliases = galaxy_entity["meta"]["synonyms"]
        else:
            aliases = [name]
        if not is_uuid(name):
            return stix2.IntrusionSet(
                id=pycti.IntrusionSet.generate_id(name=name),
                name=name,
                labels=["intrusion-set"],
                description=galaxy_entity["description"],
                created_by_ref=author["id"],
                object_marking_refs=markings,
                custom_properties={"x_opencti_aliases": aliases},
            )

    def create_tool(
        self,
        galaxy_entity,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.Tool:
        if " - S" in galaxy_entity["value"]:
            name = galaxy_entity["value"].split(" - S")[0]
        else:
            name = galaxy_entity["value"]
        if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
            aliases = galaxy_entity["meta"]["synonyms"]
        else:
            aliases = [name]
        return stix2.Tool(
            id=pycti.Tool.generate_id(name=name),
            name=name,
            labels=["tool"],
            description=galaxy_entity["description"],
            created_by_ref=author["id"],
            object_marking_refs=markings,
            custom_properties={"x_opencti_aliases": aliases},
            allow_custom=True,
        )

    def create_malware(
        self,
        galaxy_entity,
        labels: list[str],
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.Malware:
        if " - S" in galaxy_entity["value"]:
            name = galaxy_entity["value"].split(" - S")[0]
        else:
            name = galaxy_entity["value"]
        if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
            aliases = galaxy_entity["meta"]["synonyms"]
        else:
            aliases = [name]
        return stix2.Malware(
            id=pycti.Malware.generate_id(name=name),
            name=name,
            is_family=True,
            aliases=aliases,
            labels=labels,
            description=galaxy_entity["description"],
            created_by_ref=author["id"],
            object_marking_refs=markings,
            allow_custom=True,
        )

    def create_attack_pattern(
        self,
        galaxy_entity,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.AttackPattern:
        if " - T" in galaxy_entity["value"]:
            name = galaxy_entity["value"].split(" - T")[0]
        else:
            name = galaxy_entity["value"]
        if "meta" in galaxy_entity and "synonyms" in galaxy_entity["meta"]:
            aliases = galaxy_entity["meta"]["synonyms"]
        else:
            aliases = [name]
        x_mitre_id = None
        if "external_id" in galaxy_entity["meta"]:
            if len(galaxy_entity["meta"]["external_id"]) > 0:
                x_mitre_id = galaxy_entity["meta"]["external_id"][0]
        return stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(name=name, x_mitre_id=x_mitre_id),
            name=name,
            description=galaxy_entity["description"],
            created_by_ref=author["id"],
            object_marking_refs=markings,
            custom_properties={
                "x_mitre_id": x_mitre_id,
                "x_opencti_aliases": aliases,
            },
            allow_custom=True,
        )

    def create_sector(
        self,
        galaxy_entity,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.Identity:
        name = galaxy_entity["value"]
        return stix2.Identity(
            id=pycti.Identity.generate_id(name=name, identity_class="class"),
            name=name,
            identity_class="class",
            description=galaxy_entity["description"],
            created_by_ref=author["id"],
            object_marking_refs=markings,
            allow_custom=True,
        )

    def create_country(
        self,
        galaxy_entity,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.Identity:
        name = galaxy_entity["description"]
        return stix2.Location(
            id=pycti.Location.generate_id(name=name, x_opencti_location_type="Country"),
            name=name,
            country=galaxy_entity["meta"]["ISO"],
            description="Imported from MISP tag",
            created_by_ref=author["id"],
            object_marking_refs=markings,
            custom_properties={"x_opencti_location_type": "Country"},
        )

    def create_region(
        self,
        galaxy_entity,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.Identity:
        name = galaxy_entity["value"].split(" - ")[1]
        return stix2.Location(
            id=pycti.Location.generate_id(name=name, x_opencti_location_type="Region"),
            name=name,
            region=name,
            created_by_ref=author["id"],
            object_marking_refs=markings,
            custom_properties={"x_opencti_location_type": "Region"},
        )

    def process(
        self,
        galaxy: GalaxyItem,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> list[stix2.v21._STIXBase21]:
        stix_objects = []

        try:
            # Get the linked intrusion sets
            if (
                galaxy.namespace == "mitre-attack" and galaxy.name == "Intrusion Set"
            ) or (
                galaxy.namespace == "misp"
                and galaxy.name
                in [
                    "Threat Actor",
                    "Microsoft Activity Group actor",
                    "ESET Threat Actor",
                ]
            ):
                for galaxy_entity in galaxy.GalaxyCluster or []:
                    intrusion_set = self.create_intrusion_set(
                        galaxy_entity, author=author, markings=markings
                    )
                    if intrusion_set:
                        stix_objects.append(intrusion_set)

            # Get the linked tools
            if galaxy.namespace == "mitre-attack" and galaxy.name == "Tool":
                for galaxy_entity in galaxy.GalaxyCluster or []:
                    tool = self.create_tool(
                        galaxy_entity, author=author, markings=markings
                    )
                    if tool:
                        stix_objects.append(tool)

            # Get the linked malwares
            if (galaxy.namespace == "mitre-attack" and galaxy.name == "Malware") or (
                galaxy.namespace == "misp"
                and galaxy.name in ["Tool", "Ransomware", "Android", "Malpedia"]
            ):
                for galaxy_entity in galaxy.GalaxyCluster or []:
                    malware = self.create_malware(
                        galaxy_entity,
                        labels=[galaxy.name],
                        author=author,
                        markings=markings,
                    )
                    if malware:
                        stix_objects.append(malware)

            # Get the linked attack_patterns
            if galaxy.namespace == "mitre-attack" and galaxy.name == "Attack Pattern":
                for galaxy_entity in galaxy.GalaxyCluster or []:
                    attack_pattern = self.create_attack_pattern(
                        galaxy_entity, author=author, markings=markings
                    )
                    if attack_pattern:
                        stix_objects.append(attack_pattern)

            # Get the linked sectors
            if galaxy.namespace == "misp" and galaxy.name == "Sector":
                for galaxy_entity in galaxy.GalaxyCluster or []:
                    sector = self.create_sector(
                        galaxy_entity, author=author, markings=markings
                    )
                    if sector:
                        stix_objects.append(sector)

            # Get the linked countries
            if galaxy.namespace == "misp" and galaxy.name == "Country":
                for galaxy_entity in galaxy.GalaxyCluster or []:
                    country = self.create_country(
                        galaxy_entity, author=author, markings=markings
                    )
                    if country:
                        stix_objects.append(country)

            # Get the linked regions
            if (
                galaxy.namespace == "misp"
                and galaxy.type == "region"
                and galaxy.name == "Regions UN M49"
            ):
                for galaxy_entity in galaxy.GalaxyCluster or []:
                    region = self.create_region(
                        galaxy_entity, author=author, markings=markings
                    )
                    if region:
                        stix_objects.append(region)

        except stix2.exceptions.STIXError as err:
            raise GalaxyConverterError("Error while converting event's galaxy") from err

        return stix_objects
