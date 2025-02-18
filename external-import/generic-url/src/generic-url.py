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


class GenericCSVUrlImport:
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
            "GENERIC_CSV_URL", ["genericcsvurlimport", "csv_url"], config
        )
        score_value = os.getenv("SCORE") or get_config_variable(
            "GENERIC_CSV_SCORE", ["genericcsvurlimport", "score"], config, True
        )
        self.score = int(score_value)

        interval_value = os.getenv("INTERVAL") or get_config_variable(
            "GENERIC_CSV_INTERVAL", ["genericcsvurlimport", "interval"], config, True
        )
        self.interval = int(interval_value)

        self.update_existing_data = True  # ou configuration selon vos besoins
        # Optionnel : récupérer l'organization name si nécessaire

        if not self.csv_url:
            raise Exception("Une URL doit être spécifiée pour le flux CSV.")

        # Récupérer l'identité du connecteur ou la créer si nécessaire
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
                "Impossible de récupérer ou créer une identité valide (standard_id manquant)."
            )

    def get_interval(self):
        """Renvoie l'intervalle en secondes."""
        return int(self.interval) * 60 * 60 * 24

    def run(self):
        self.helper.log_info("Démarrage du connecteur Generic CSV URL Import...")
        # Définir une regex pour vérifier qu'une ligne commence par http:// ou https://
        url_validator = re.compile(r"^https?://.+", re.IGNORECASE)

        while True:
            try:
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

                # Exécuter si l'intervalle est écoulé
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Exécution du connecteur!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Generic CSV URL Import run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        self.helper.log_info(
                            "Récupération du flux CSV depuis : " + self.csv_url
                        )
                        req = urllib.request.Request(self.csv_url)
                        req.method = "GET"
                        ssl_context = ssl._create_unverified_context()
                        response = urllib.request.urlopen(req, context=ssl_context)
                        content = response.read().decode("utf-8")
                        # Chaque ligne doit contenir une URL
                        url_list = content.splitlines()

                        # Préparation de la référence externe associée à ce flux
                        external_reference = stix2.ExternalReference(
                            source_name="Generic CSV URL Import",
                            url=self.csv_url,
                            description="Flux CSV contenant des URL",
                        )

                        bundle_objects = []

                        for url_value in url_list:
                            url_value = url_value.strip()
                            if not url_value:
                                continue

                            if url_validator.match(url_value):
                                # Création du pattern pour l'indicateur
                                pattern = "[url:value = '" + url_value + "']"
                                # Création de l'indicateur STIX
                                stix_indicator = stix2.Indicator(
                                    id=Indicator.generate_id(pattern),
                                    name=url_value,
                                    description="URL importée depuis le flux CSV",
                                    created_by_ref=self.identity["standard_id"],
                                    confidence=self.helper.connect_confidence_level,
                                    pattern_type="stix",
                                    pattern=pattern,
                                    external_references=[external_reference],
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_score": self.score,
                                        "x_opencti_main_observable_type": "URL",
                                    },
                                )
                                # Création de l'observable de type URL
                                stix_url = stix2.URL(
                                    type="url",
                                    spec_version="2.1",
                                    value=url_value,
                                    object_marking_refs=[stix2.TLP_WHITE],
                                    custom_properties={
                                        "x_opencti_description": "URL importée depuis le flux CSV",
                                        "x_opencti_score": self.score,
                                        "created_by_ref": self.identity["standard_id"],
                                        "external_references": [external_reference],
                                    },
                                )
                            else:
                                self.helper.log_error(
                                    "La valeur n'est pas une URL valide : " + url_value
                                )
                                continue

                            # Création de la relation "based-on" entre l'indicateur et l'observable
                            stix_relationship = stix2.Relationship(
                                id=StixCoreRelationship.generate_id(
                                    "based-on", stix_indicator.id, stix_url.id
                                ),
                                relationship_type="based-on",
                                source_ref=stix_indicator.id,
                                target_ref=stix_url.id,
                                object_marking_refs=[stix2.TLP_WHITE],
                            )

                            bundle_objects.extend(
                                [stix_indicator, stix_url, stix_relationship]
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
        connector = GenericCSVUrlImport()
        connector.run()
    except Exception as e:
        print("Erreur lors de l'exécution du connecteur : " + str(e))
        time.sleep(10)
        exit(0)
