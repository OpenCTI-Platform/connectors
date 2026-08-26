import json
import time

import iso3166
import stix2

CONFIG_OPENCTI_LABELS = ["popularity"]


class StixMaker:
    def __init__(
        self, helper, feedtype, max_bundle_entries=10000
    ) -> None:
        self.helper = helper
        self.max_bundle_entries = max_bundle_entries
        self.feedtype = feedtype

        # This allows us to not re-create the STIX objects which we had created before
        self.cached_object_ids = {}

        # Every object we create goes here as it need to be prepend to each final bundle
        self.bundles_created_objects = []

        # Output STIX bundle storage - everything but created objects
        self.bundles_output = []

        self.creator_identity = self.findOrCreateCacheableObject(
            "identity",
            {
                "name": "Bitdefender",
                "description": "Bitdefender offers cybersecurity solutions, services and threat intelligence.",
                "contact_information": "https://www.bitdefender.com",
                "identity_class": "organization",
                "custom_properties": {
                    "x_opencti_reliability": "A - Completely reliable",
                    "x_opencti_organization_type": "vendor",
                },
                "external_references": [
                    {
                        "source_name": "Bitdefender Threat Intelligence",
                        "url": "https://www.bitdefender.com/en-us/business/products/operational-threat-intelligence",
                        "description": "Bitdefender Threat Intelligence",
                    }
                ],
            },
        )

        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, f"importing {feedtype} feed"
        )

    def fromEntry(self, entry: str) -> bool:
        data = json.loads(entry)

        maker = StixMakerPrivate(self)

        if self.feedtype == "file":
            self.bundles_output.extend(maker.fromFileEntry(data))
        elif self.feedtype == "ip":
            self.bundles_output.extend(maker.fromIpEntry(data))
        elif self.feedtype == "web":
            self.bundles_output.extend(maker.fromWebEntry(data))
        else:
            raise Exception(f"invalid entry type {self.feedtype}")

        if len(self.bundles_output) > self.max_bundle_entries:
            self._sendStixBundle()

    def _sendStixBundle(self):

        if len(self.bundles_output) == 0:
            return

        self.helper.log_info(
            f"{self.helper.connect_name} sending stix bundle of {len(self.bundles_output)} entries"
        )

        outbundle = stix2.Bundle(
            self.bundles_created_objects + self.bundles_output, allow_custom=True
        ).serialize()

        self.helper.send_stix2_bundle(
            bundle=outbundle,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
            update=True,
        )

        self.bundles_output.clear()
        self.bundles_created_objects.clear()

    def sendFinal(self):
        self._sendStixBundle()
        self.helper.api.work.to_processed(self.work_id, "done")

    def findOrCreateCacheableObject(self, objtype: str, values: dict) -> str:
        """
        This method creates the STIX object in the database if first time called,
        and stores its ID. The subsequent calls it just returns the stored ID.
        """
        if objtype == "attack_pattern":
            api = self.helper.api.attack_pattern
            cache_entry = f'p{values["name"]}'
            filters = [{"key": "name", "values": [values["name"]]}]
            creator_class = stix2.AttackPattern

        elif objtype == "location":
            api = self.helper.api.location
            cache_entry = f'l{values["name"]}'
            filters = [{"key": "name", "values": [values["name"]]}]
            creator_class = stix2.Location

        elif objtype == "identity":
            api = self.helper.api.identity
            cache_entry = f'i{values["identity_class"]}-{values["name"]}'
            filters = [
                {"key": "name", "values": [values["name"]]},
                {"key": "identity_class", "values": [values["identity_class"]]},
            ]
            creator_class = stix2.Identity

        elif objtype == "threat_actor":
            api = self.helper.api.threat_actor
            cache_entry = f't{values["name"]}'
            filters = [{"key": "name", "values": [values["name"]]}]
            creator_class = stix2.ThreatActor

        elif objtype == "vulnerability":
            api = self.helper.api.vulnerability
            cache_entry = f'v{values["name"]}'
            filters = [{"key": "name", "values": [values["name"]]}]
            creator_class = stix2.Vulnerability

        elif objtype == "malware_family":
            api = self.helper.api.malware
            cache_entry = f'f{values["name"]}'
            filters = [
                {"key": "name", "values": [values["name"]]},
                {"key": "is_family", "values": [True]},
            ]
            creator_class = stix2.Malware

        else:
            raise Exception(f"Unknown lookup type {objtype}")

        # If we created or found it before just return the ID (to be linked as ref)
        if cache_entry in self.cached_object_ids:
            return self.cached_object_ids[cache_entry]

        # The object may have been created by others who do not necessarily follow standard ID struct,
        # thus we look it up by what is relevant so we can just use its ID for references
        found = api.read(
            filters={
                "mode": "and",
                "filters": filters,
                "filterGroups": [],
            }
        )

        if found is not None:
            self.cached_object_ids[cache_entry] = found["standard_id"]
            return found["standard_id"]

        # Create a Stix object
        values["id"] = api.generate_id_from_data(values)
        self.cached_object_ids[cache_entry] = values["id"]

        # We add it into created objects so we would then prepend this to each bundle
        # (this adds some overhead but allows to process bundles independently, which is what OpenCTI does)
        self.bundles_created_objects.append(creator_class(**values))
        return values["id"]


# Private class
class StixMakerPrivate:

    def __init__(self, maker) -> None:
        self.maker = maker
        self.stixdata = dict()

    def _getValue(self, name: str):
        if not name in self.data:
            return None

        val = self.data[name]
        del self.data[name]
        return val

    def _unix_to_rfc3339(self, ts: int) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ts)))

    # Parses the common values of the entry
    def _parseCommon(self, entry: str):
        self.data = entry

        timestamp = self._getValue("timestamp")
        labels = []
        customprops = {"x_opencti_detection": True}

        self.timestamp = self._unix_to_rfc3339(timestamp)
        self.first_seen = self._unix_to_rfc3339(self._getValue("first_seen"))
        self.confidence = self._getValue("confidence")
        self.severity = self._getValue("severity")

        # Severity is added as custom score but also as a label
        if self.severity is not None and isinstance(self.severity, int):
            customprops["x_opencti_score"] = self.severity

            if self.severity >= 80:
                labels.append("severity:critical")
            elif self.severity >= 60:
                labels.append("severity:high")
            elif self.severity >= 40:
                labels.append("severity:medium")
            else:
                labels.append("severity:low")

        # Create as custom labels
        for l in CONFIG_OPENCTI_LABELS:
            val = self._getValue(l)
            if val is not None:
                customprops[f"x_opencti_{l}"] = val

        self.indicator_params = {
            "pattern_type": "stix",
            "valid_from": self.first_seen,
            "created": self.timestamp,
            "confidence": self.confidence,
            "labels": labels,
            "revoked": False,
            "indicator_types": ["malicious-activity"],
            "custom_properties": customprops,
            "created_by_ref": self.maker.creator_identity,
        }

        if "revoked" in self.data:
            self.indicator_params["revoked"] = True
            self._getValue("revoked")

        if "tags" in self.data:
            self.tags = self._getValue("tags")
            self.indicator_params["description"] = ",".join(self.tags)
            self.indicator_params["labels"].extend(self.tags)
        else:
            self.tags = None

        if "TTL" in self.data:
            self.indicator_params["valid_until"] = self._unix_to_rfc3339(
                timestamp + self._getValue("TTL")
            )

        # At this moment we're not importing this'
        if "suspicious_entry" in self.data:
            self._getValue("suspicious_entry")

    def _parseRelatedIndicator(self, indicator, source_id):

        RELATIONSHIP_MAP = {
            "file_is_modified_by_file": ("related-to", False),
            "file_is_downloaded_by_file": ("related-to", True),
            "file_is_read_by_file": ("related-to", False),
            "file_is_executed_by_file": ("related-to", False),
            "file_modifies_file": ("related-to", True),
            "file_executes_file": ("related-to", True),
            "file_reads_file": ("related-to", True),
            "url_contains_ip": ("related-to", True),
            "file_connects_to_domain": ("communicates-with", True),
            "file_connects_to_ip": ("communicates-with", True),
            "ip_is_connected_to_by_file": ("communicates-with", False),
            "file_downloads_file": ("downloads", True),
            "file_connects_to_url": ("communicates-with", True),
            "ip_is_resolved_from_domain": ("resolves-to", False),
            "ip_is_contained_by_url": ("related-to", False),
            "url_resolves_to_ip": ("resolves-to", True),
            "domain_resolves_to_ip": ("resolves-to", True),
            "url_host_resolves_to_ip": ("related-to", True),
            "domain_relates_to_domain": ("related-to", True),
            "url_hosted_on_domain": ("related-to", True),
            "domain_hosts_url": ("related-to", False),
            "domain_is_connected_to_by_file": ("related-to", True),
        }

        # Skip unknown indicators as new may be added
        if indicator["relationship"] not in RELATIONSHIP_MAP:
            self.maker.helper.log_warning(
                f'Unknown relationship type {indicator["relationship"]}'
            )
            return []

        # Some upstream examples overload the "type" field but provide a type-specific key
        # matching the relationship semantics.
        if indicator["relationship"] == "file_connects_to_url" and "url" in indicator:
            indicator_type = "url"
        else:
            indicator_type = indicator["type"]

        # What type is it
        if indicator_type == "file":
            filedata = {"hashes": {}}

            if "sha256" in indicator:
                filedata["hashes"]["SHA-256"] = indicator["sha256"]
                filedata["name"] = indicator["sha256"]

            if "sha1" in indicator:
                filedata["hashes"]["SHA-1"] = indicator["sha1"]
                filedata["name"] = indicator["sha1"]

            if "md5" in indicator:
                filedata["hashes"]["MD5"] = indicator["md5"]
                filedata["name"] = indicator["md5"]

            if "name" in indicator:
                filedata["name"] = indicator["name"]

            stix_obj = stix2.File(**filedata)

        elif indicator_type == "domain":
            if "domain" not in indicator:
                self.maker.helper.log_warning(
                    f"Domain related indicator missing domain value: {indicator}"
                )
                return []

            stix_obj = stix2.DomainName(value=indicator["domain"])

        elif indicator_type == "ipv4":
            if "ipv4" not in indicator:
                self.maker.helper.log_warning(
                    f"IPv4 related indicator missing ipv4 value: {indicator}"
                )
                return []

            stix_obj = stix2.IPv4Address(value=indicator["ipv4"])

        elif indicator_type == "ipv6":

            if "ipv6" not in indicator:
                self.maker.helper.log_warning(
                    f"IPv6 related indicator missing ipv4 value: {indicator}"
                )
                return []

            addr = indicator["ipv6"]
            if addr.startswith("[") and addr.endswith(
                "]"
            ):  # Bitdefender feed has IPv6 as [2534:11:22:33]
                addr = addr[1 : len(addr) - 1]

            stix_obj = stix2.IPv6Address(value=addr)

        elif indicator_type == "url":
            stix_obj = stix2.URL(value=indicator["url"])

        else:
            self.maker.helper.log_warning(
                f"Unknown indicator type {indicator_type}: {indicator}"
            )
            return []

        reldata = RELATIONSHIP_MAP[indicator["relationship"]]

        if reldata[1]:
            stix_rel = stix2.Relationship(
                relationship_type=reldata[0],
                source_ref=source_id,
                target_ref=stix_obj.id,
                description=indicator["relationship"],
                created_by_ref=self.maker.creator_identity,
            )
        else:
            stix_rel = stix2.Relationship(
                relationship_type=reldata[0],
                source_ref=stix_obj.id,
                target_ref=source_id,
                description=indicator["relationship"],
                created_by_ref=self.maker.creator_identity,
            )

        return [stix_obj, stix_rel]

    def _validateRemaining(self) -> None:
        if self.data:
            raise Exception(f"Entry left data unconsumed: {self.data}")

    # Parse additional data which is present in all feeds
    def _parseAdditional(self, source_id, source_type):

        additional_bundle = []

        # Collect country and industry refs to also link to threat actor if present
        country_refs = []
        industry_refs = []

        #
        # Affected countries handler
        #
        if "affected_countries" in self.data:
            for entry in self._getValue("affected_countries"):
                iso2 = entry["country"]
                percent = entry["percentage"]

                if iso2.upper() == "OTHERS":
                    continue

                country = iso3166.countries.get(iso2.upper())

                ref_id = self.maker.findOrCreateCacheableObject(
                    "location",
                    {
                        "name": country.name,
                        "country": iso2,
                        "created_by_ref": self.maker.creator_identity,
                        "custom_properties": {"x_opencti_location_type": "Country"},
                    },
                )

                country_refs.append((ref_id, percent))
                additional_bundle.append(
                    stix2.Relationship(
                        relationship_type=(
                            "targets" if source_type == "malware" else "related-to"
                        ),
                        source_ref=source_id,
                        target_ref=ref_id,
                        created_by_ref=self.maker.creator_identity,
                        custom_properties={"x_opencti_impact_percentage": percent},
                        allow_custom=True
                    )
                )

        #
        # Affected industries
        #
        if "affected_industries" in self.data:
            for entry in self._getValue("affected_industries"):

                sector_name = entry["industry"]
                percent = entry["percentage"]

                ref_id = self.maker.findOrCreateCacheableObject(
                    "identity",
                    {
                        "name": sector_name.strip(),
                        "identity_class": "class",
                        "created_by_ref": self.maker.creator_identity,
                        "custom_properties": {"x_opencti_type": "Sector"},
                    },
                )

                industry_refs.append((ref_id, percent))
                additional_bundle.append(
                    stix2.Relationship(
                        relationship_type=(
                            "targets" if source_type == "malware" else "related-to"
                        ),
                        source_ref=source_id,
                        target_ref=ref_id,
                        created_by_ref=self.maker.creator_identity,
                        custom_properties={"x_opencti_impact_percentage": percent},
                        allow_custom=True
                    )
                )

        #
        # Threat actor?
        #
        if "actor_name" in self.data:

            threatactordata = {"name": self._getValue("actor_name")}

            ref_id = self.maker.findOrCreateCacheableObject(
                "threat_actor", threatactordata
            )
            additional_bundle.append(
                stix2.Relationship(
                    relationship_type=(
                        "uses" if source_type == "malware" else "related-to"
                    ),
                    source_ref=ref_id,
                    target_ref=source_id,
                    created_by_ref=self.maker.creator_identity,
                )
            )

            # Link threat actor to countries (targets relationship)
            for country_id, percent in country_refs:
                additional_bundle.append(
                    stix2.Relationship(
                        relationship_type="targets",
                        source_ref=ref_id,
                        target_ref=country_id,
                        created_by_ref=self.maker.creator_identity,
                        custom_properties={"x_opencti_impact_percentage": percent},
                        allow_custom=True
                    )
                )

            # Link threat actor to industries (targets relationship)
            for industry_id, percent in industry_refs:
                additional_bundle.append(
                    stix2.Relationship(
                        relationship_type="targets",
                        source_ref=ref_id,
                        target_ref=industry_id,
                        created_by_ref=self.maker.creator_identity,
                        custom_properties={"x_opencti_impact_percentage": percent},
                        allow_custom=True
                    )
                )

        #
        # Exploited vulnerabilities?
        #
        if "exploited_vulnerabilities" in self.data:
            for v in self._getValue("exploited_vulnerabilities"):

                vulndata = {
                    "name": v["cve_id"],
                    "created_by_ref": self.maker.creator_identity,
                    "custom_properties": {},
                }

                if "cvss_score" in v:
                    if "v2" in v["cvss_score"]:
                        vulndata["custom_properties"]["x_opencti_cvss_base_score"] = (
                            vulndata["custom_properties"]["x_opencti_cvss_v2"]
                        ) = v["cvss_score"]["v2"]

                    if "v3" in v["cvss_score"]:
                        vulndata["custom_properties"]["x_opencti_cvss_base_score"] = (
                            vulndata["custom_properties"]["x_opencti_cvss_v3"]
                        ) = v["cvss_score"]["v3"]

                ref_id = self.maker.findOrCreateCacheableObject(
                    "vulnerability", vulndata
                )
                additional_bundle.append(
                    stix2.Relationship(
                        relationship_type=(
                            "exploits" if source_type == "malware" else "related-to"
                        ),
                        source_ref=source_id,
                        target_ref=ref_id,
                        created_by_ref=self.maker.creator_identity,
                    )
                )

        #
        # MITRE attack patterns?
        #
        if "mitre_attack" in self.data:
            for tid in self._getValue("mitre_attack"):

                attackpatterndata = {
                    "name": tid,
                    "created_by_ref": self.maker.creator_identity,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tid,
                            "url": "https://attack.mitre.org/techniques/" + tid,
                        }
                    ],
                }

                ref_id = self.maker.findOrCreateCacheableObject(
                    "attack_pattern", attackpatterndata
                )
                additional_bundle.append(
                    stix2.Relationship(
                        relationship_type=(
                            "uses" if source_type == "malware" else "related-to"
                        ),
                        source_ref=source_id,
                        target_ref=ref_id,
                        created_by_ref=self.maker.creator_identity,
                    )
                )

        return additional_bundle

    def fromFileEntry(self, entry: str):

        self._parseCommon(entry)

        # Everything goes here
        stix_bundle = []

        threat_label = self._getValue("threat_label")

        #
        # File STIX object data
        #
        hash_sha256 = self._getValue("sha256")
        hash_md5 = self._getValue("md5")
        hash_sha1 = self._getValue("sha1")

        filedata = {"hashes": {}}

        if hash_sha256:
            filedata["hashes"]["SHA-256"] = hash_sha256

        if hash_sha1:
            filedata["hashes"]["SHA-1"] = hash_sha1

        if hash_md5:
            filedata["hashes"]["MD5"] = hash_md5

        firsthash = hash_sha256 or hash_md5 or hash_sha1
        is_revoked = self.indicator_params["revoked"]

        # May or may not be there
        file_names = self._getValue("file_names")

        if file_names is not None:
            filedata["name"] = file_names[0]

        file_size = self._getValue("file_size")

        if file_size is not None:
            filedata["size"] = file_size

        # not needed
        self._getValue("type")

        if "file_format" in self.data:
            filedata["custom_properties"] = {"format": self._getValue("file_format")}

        # FIXME: currently ignored
        self._getValue("similar_files")

        stix_file = stix2.File(**filedata)
        stix_bundle.append(stix_file)

        #
        # Indicator STIX object data
        #
        indicator_pattern_array = []

        for h in filedata["hashes"]:
            indicator_pattern_array.append(
                f"file:hashes.'{h}' = '{filedata['hashes'][h]}'"
            )

        indicatordata = self.indicator_params
        indicatordata["name"] = firsthash
        indicatordata["pattern"] = "[" + " OR ".join(indicator_pattern_array) + "]"
        indicatordata["custom_properties"]["x_opencti_main_observable_type"] = "File"

        if "threat_type" in self.data:
            ttype = self._getValue("threat_type")
            if ttype not in indicatordata["labels"]:
                indicatordata["labels"].append(ttype)
        else:
            ttype = None

        indicatordata["id"] = self.maker.helper.api.indicator.generate_id_from_data(
            indicatordata
        )
        stix_indicator = stix2.Indicator(**indicatordata, allow_custom=True)
        stix_bundle.append(stix_indicator)

        # Link file to indicator
        stix_bundle.append(
            stix2.Relationship(
                relationship_type="based-on",
                source_ref=stix_indicator.id,
                target_ref=stix_file.id,
                created_by_ref=self.maker.creator_identity,
            )
        )

        #
        # Malware object data - malware itself
        #
        if not is_revoked and threat_label:
            malwaredata = {
                "name": threat_label,
                "is_family": False,
                "first_seen": self.first_seen,
                "created": self.timestamp,
                "confidence": self.confidence,
                "created_by_ref": self.maker.creator_identity,
            }

            if ttype is not None:
                malwaredata["malware_types"] = [ttype]

            if self.tags is not None:
                malwaredata["labels"] = self.tags

            malwaredata["id"] = self.maker.helper.api.malware.generate_id_from_data(
                malwaredata
            )
            stix_malware = stix2.Malware(**malwaredata)
            stix_bundle.append(stix_malware)

            # Link indicator to malware
            stix_bundle.append(
                stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=stix_indicator.id,
                    target_ref=stix_malware.id,
                    created_by_ref=self.maker.creator_identity,
                )
            )
        else:
            stix_malware = None

        # If we have malware family, link it to the malware
        if stix_malware is not None and "threat_family" in self.data:
            family = self._getValue("threat_family")
            family = (
                family[:1].upper() + family[1:]
            )  # capitalize first letter but do not touch the rest

            malware_family_data = {
                "name": family,
                "is_family": True,
                "first_seen": self.first_seen,
                "created": self.timestamp,
                "confidence": self.confidence,
                "created_by_ref": self.maker.creator_identity,
            }

            ref_id = self.maker.findOrCreateCacheableObject(
                "malware_family", malware_family_data
            )
            stix_bundle.append(
                stix2.Relationship(
                    relationship_type="variant-of",
                    source_ref=stix_malware.id,
                    target_ref=ref_id,
                    created_by_ref=self.maker.creator_identity,
                )
            )

        # Parse additional objects
        if stix_malware is not None:
            stix_bundle.extend(self._parseAdditional(stix_malware.id, "malware"))
        else:
            stix_bundle.extend(self._parseAdditional(stix_indicator.id, "indicator"))

        #
        # Related indicators
        #
        if "related_indicators" in self.data and stix_malware is not None:

            for i in self._getValue("related_indicators"):
                stix_bundle.extend(self._parseRelatedIndicator(i, stix_malware.id))

        self._validateRemaining()
        return stix_bundle

    def fromIpEntry(self, entry: str):

        self._parseCommon(entry)

        # Everything goes here
        stix_bundle = []

        self._getValue("type")
        # "type":"IP"

        # We keep location as indicator custom label since it is temporary and valid only in the context
        # of time. I.e. next year this IP maybe on a different location and in different CIDR block
        indicator_custom_properties = [
            "flags",
            "cidr",
            "ip_country",
            "geo_region",
            "geo_city",
            "geo_latitude",
            "geo_longitude",
            "ports",
            "protocols",
        ]

        #
        # IP address
        #
        ipaddress = self._getValue("ip")
        ip_params = {"value": ipaddress}

        # Create an indicator
        indicatordata = self.indicator_params
        indicatordata["name"] = ipaddress
        indicatordata["description"] = (",").join(self.indicator_params["labels"])

        # ASN info
        if "asn" in self.data:
            asn_number = self._getValue("asn")
            asn_data = {"number": asn_number}

            for v in ["as_owner", "asn_owner"]:
                if v in self.data:
                    asn_data["name"] = self._getValue(v)
                    break

            stix_asn = stix2.AutonomousSystem(**asn_data)
            stix_bundle.append(stix_asn)
            ip_params["belongs_to_refs"] = [stix_asn.id]

        # Create IP CRO
        if self._getValue("format") == "IPv4":
            indicator_pattern = "ipv4-addr:value"
            indicatordata["custom_properties"][
                "x_opencti_main_observable_type"
            ] = "IPv4-Addr"
            stix_ip = stix2.IPv4Address(**ip_params)

        else:
            indicator_pattern = "ipv6-addr:value"
            indicatordata["custom_properties"][
                "x_opencti_main_observable_type"
            ] = "IPv6-Addr"
            stix_ip = stix2.IPv6Address(**ip_params)

        stix_bundle.append(stix_ip)

        indicatordata["pattern"] = f"[{indicator_pattern} = '{ipaddress}']"

        # FIXME: indicator_types

        # Add more data into custom properties
        for p in indicator_custom_properties:
            if p in self.data:
                indicatordata["custom_properties"][f"x_opencti_{p}"] = self._getValue(p)

        stix_indicator = stix2.Indicator(**indicatordata, allow_custom=True)
        stix_bundle.append(stix_indicator)

        stix_bundle.append(
            stix2.Relationship(
                relationship_type="related-to",
                source_ref=stix_indicator.id,
                target_ref=stix_ip.id,
                created_by_ref=self.maker.creator_identity,
                start_time=indicatordata["valid_from"],
            )
        )

        # Parse additional objects
        stix_bundle.extend(self._parseAdditional(stix_indicator.id, "indicator"))

        # Related indicators
        if "related_indicators" in self.data:
            for i in self._getValue("related_indicators"):
                stix_bundle.extend(self._parseRelatedIndicator(i, stix_ip.id))

        self._validateRemaining()
        return stix_bundle

    def fromWebEntry(self, entry: str):

        self._parseCommon(entry)

        # Everything goes here
        stix_bundle = []

        domainurl = self._getValue("url")

        if self._getValue("type") == "domain":
            stix_obj = stix2.DomainName(value=domainurl)
            indicator_pattern = f"[domain-name:value = '{domainurl}']"

        else:  # url
            stix_obj = stix2.URL(value=domainurl)
            indicator_pattern = f"[url:value = '{domainurl}']"

        indicatordata = self.indicator_params
        indicatordata["name"] = domainurl
        indicatordata["pattern"] = indicator_pattern

        if "threat_types" in self.data:
            for t in self._getValue("threat_types"):
                if isinstance(t, str) and t not in indicatordata["labels"]:
                    indicatordata["labels"].append(t)

        indicator_custom_properties = ["flags"]

        # Add more data into custom properties
        for p in indicator_custom_properties:
            if p in self.data:
                indicatordata["custom_properties"][f"x_opencti_{p}"] = self._getValue(p)

        stix_indicator = stix2.Indicator(**indicatordata, allow_custom=True)

        stix_bundle.append(stix_obj)
        stix_bundle.append(stix_indicator)
        stix_bundle.append(
            stix2.Relationship(
                relationship_type="based-on",
                source_ref=stix_indicator.id,
                target_ref=stix_obj.id,
                created_by_ref=self.maker.creator_identity,
                start_time=indicatordata["valid_from"],
            )
        )

        # Parse additional objects
        stix_bundle.extend(self._parseAdditional(stix_indicator.id, "indicator"))

        #
        # Related indicators
        #
        if "related_indicators" in self.data:
            for i in self._getValue("related_indicators"):
                stix_bundle.extend(self._parseRelatedIndicator(i, stix_obj.id))

        self._getValue("web_content_categories")
        self._validateRemaining()

        return stix_bundle
