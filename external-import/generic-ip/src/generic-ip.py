import os
import re
import ssl
import time
import urllib.request
from datetime import datetime

import stix2
import yaml
from pycti import (
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class GenericCSVIPImport:
    def __init__(self):
        # Chargement de la configuration depuis config.yml s'il existe
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.yml"
        )
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Priorité aux variables d'environnement sinon utilisation de la config
        self.csv_url = os.getenv("TARGET_URL") or get_config_variable(
            "GENERIC_CSV_URL", ["genericcsvipimport", "csv_url"], config
        )
        score_value = os.getenv("SCORE") or get_config_variable(
            "GENERIC_CSV_SCORE", ["genericcsvipimport", "score"], config, True
        )
        self.score = int(score_value)

        interval_value = os.getenv("INTERVAL") or get_config_variable(
            "GENERIC_CSV_INTERVAL", ["genericcsvipimport", "interval"], config, True
        )
        self.interval = int(interval_value)

        self.score = int(score_value)
        self.update_existing_data = (
            True  # os.getenv("CONNECTOR_UPDATE_EXISTING_DATA") or True
        )
        org_name = os.getenv("ORG_NAME")

        if not self.csv_url:
            raise Exception("An URL must be set")

        # Récupérer l'identité existante ou la créer si nécessaire
        connector_identity_name = (
            os.getenv("CONNECTOR_IDENTITY_NAME") or "NOT_CONFIGURED_IN_CONNECTOR"
        )
        connector_identity_description = (
            os.getenv("CONNECTOR_IDENTITY_DESCRIPTION") or "NOT_CONFIGURED_IN_CONNECTOR"
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name=connector_identity_name,
            description=connector_identity_description,
        )
        if (
            not self.identity
            or "standard_id" not in self.identity
            or not self.identity["standard_id"]
        ):
            raise Exception(
                "Failed to retrieve or create a valid identity (missin standard_id)."
            )

    def get_interval(self):
        """Renvoie l'intervalle en secondes."""
        return int(self.interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info(
            "Démarrage du connecteur Generic IP Import, one by line..."
        )
        while True:
            try:
                # Récupération du timestamp actuel et de l'état précédent
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Dernière exécution : "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Le connecteur n'a jamais été exécuté")

                # Exécution si l'intervalle est écoulé
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Exécution du connecteur!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = (
                        "Generic IP Import, one by line run @ "
                        + now.strftime("%Y-%m-%d %H:%M:%S")
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        # Récupération du flux CSV depuis l'URL indiquée
                        self.helper.log_info(
                            "Récupération du flux CSV depuis : " + self.csv_url
                        )
                        req = urllib.request.Request(self.csv_url)
                        req.method = "GET"
                        ssl_context = ssl._create_unverified_context()
                        response = urllib.request.urlopen(req, context=ssl_context)
                        content = response.read().decode("utf-8")
                        ip_list = content.splitlines()

                        # Préparation de la référence externe associée à ce flux
                        external_reference = stix2.ExternalReference(
                            source_name="Generic IP Import, one by line",
                            url=self.csv_url,
                            description="Flux CSV contenant des adresses IP",
                        )

                        bundle_objects = []
                        ipv4_validator = re.compile(
                            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                        )

                        for ip in ip_list:
                            ip = ip.strip()
                            if not ip:
                                continue

                            if ipv4_validator.match(ip):
                                pattern = "[ipv4-addr:value = '" + ip + "']"
                                stix_indicator = stix2.Indicator(
                                    id=Indicator.generate_id(pattern),
                                    name=ip,
                                    description="Adresse IPv4 importée depuis le flux CSV",
                                    created_by_ref=self.identity["standard_id"],
                                    confidence=self.helper.connect_confidence_level,
                                    pattern_type="stix",
                                    pattern=pattern,
                                    external_references=[external_reference],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_score": self.score,
                                        "x_opencti_main_observable_type": "IPv4-Addr",
                                    },
                                )
                                stix_observable = stix2.IPv4Address(
                                    type="ipv4-addr",
                                    spec_version="2.1",
                                    value=ip,
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_description": "Adresse IPv4 importée depuis le flux CSV",
                                        "x_opencti_score": self.score,
                                        "created_by_ref": self.identity["standard_id"],
                                        "external_references": [external_reference],
                                    },
                                )
                            else:
                                pattern = "[ipv6-addr:value = '" + ip + "']"
                                stix_indicator = stix2.Indicator(
                                    id=Indicator.generate_id(pattern),
                                    name=ip,
                                    description="Adresse IPv6 importée depuis le flux CSV",
                                    created_by_ref=self.identity["standard_id"],
                                    confidence=self.helper.connect_confidence_level,
                                    pattern_type="stix",
                                    pattern=pattern,
                                    external_references=[external_reference],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_score": self.score,
                                        "x_opencti_main_observable_type": "IPv6-Addr",
                                    },
                                )
                                stix_observable = stix2.IPv6Address(
                                    type="ipv6-addr",
                                    spec_version="2.1",
                                    value=ip,
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_description": "Adresse IPv6 importée depuis le flux CSV",
                                        "x_opencti_score": self.score,
                                        "created_by_ref": self.identity["standard_id"],
                                        "external_references": [external_reference],
                                    },
                                )

                            stix_relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "based-on", stix_indicator.id, stix_observable.id
                                ),
                                relationship_type="based-on",
                                source_ref=stix_indicator.id,
                                target_ref=stix_observable.id,
                                object_marking_refs=[stix2.TLP_WHITE],
                            )

                            bundle_objects.extend(
                                [stix_indicator, stix_observable, stix_relationship]
                            )

                        bundle = self.helper.stix2_create_bundle(bundle_objects)
                        self.helper.send_stix2_bundle(bundle, work_id=work_id)
                    except Exception as e:
                        self.helper.log_error(
                            "Erreur lors du traitement du CSV : " + str(e)
                        )

                    message = "Exécution réussie, enregistrement de last_run : " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Dernière exécution enregistrée, prochaine exécution dans : "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " jours"
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Prochaine exécution dans : "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " jours"
                    )
                    time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Arrêt du connecteur")
                exit(0)
            except Exception as e:
                self.helper.log_error("Erreur : " + str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        connector = GenericCSVIPImport()
        connector.run()
    except Exception as e:
        print("Erreur lors de l'exécution du connecteur : " + str(e))
        time.sleep(10)
        exit(0)
