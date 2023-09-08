import os, yaml, threading, time, json, re
from typing import Dict
from cron_converter import Cron
from dataexport import DataExport
from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIApiClient
from stix2 import Relationship, Bundle, Note
from urllib.parse import urljoin

# Import attribution_tools parser:
# https://github.com/WithSecureLabs/opencti-attribution-tools
from attribution_tools import parsers

# Import attributionToolsModel
from attribution_tools.attribution_model import AttributionToolsModel
from attribution_tools.train_attribution_model import TrainingAttributionToolsModel

TRAINING_DATA_PATH = os.path.dirname(os.path.abspath(__file__)) + "/data/training_data"
N_MAX_DATASET_FILES = 3
class AttributionTools:
    def __init__(self) -> None:
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.attribution_model = None

        # getting settings from config yml
        ## training schedule
        self.cron = Cron(get_config_variable(
           "ATTRIBUTIONTOOLS_MODEL_TRAINING_CRON_UTC",
           ["attributiontools", "model_training_cron_utc"],
           config,
        ))
        ## n_threads for training data querying
        self.n_query_threads = get_config_variable(
           "ATTRIBUTIONTOOLS_N_TRAINING_QUERY_THREADS",
           ["attributiontools", "n_training_query_threads"],
           config,
           isNumber=True,
        )
        if self.n_query_threads < 1:
            raise ValueError(f"ATTRIBUTIONTOOLS_N_TRAINING_QUERY_THREADS invalid number: {self.n_query_threads}. Should be > 0.")
        ## default confidence for created relations
        self.default_relation_confidence = float(get_config_variable(
           "ATTRIBUTIONTOOLS_DEFAULT_RELATION_CONFIDENCE",
           ["attributiontools", "default_relation_confidence"],
           config,
        ))
        if self.default_relation_confidence < 0 or self.default_relation_confidence > 100:
            raise ValueError(f"ATTRIBUTIONTOOLS_DEFAULT_RELATION_CONFIDENCE invalid number: {self.default_relation_confidence}. Should be 0-100.")
        self.automatic_relation_creation: bool = get_config_variable(
           "ATTRIBUTIONTOOLS_AUTOMATIC_RELATION_CREATION",
           ["attributiontools", "automatic_relation_creation"],
           config,
        )
        if not isinstance(self.automatic_relation_creation, bool):
            raise ValueError(f"ATTRIBUTIONTOOLS_RELATION_CREATION_PROBABILITY_TRESHOLD is not a boolean: {self.automatic_relation_creation}")
        ## threshold of prediction probablity to create a relation
        self.relation_creation_probability_treshold = float(get_config_variable(
           "ATTRIBUTIONTOOLS_RELATION_CREATION_PROBABILITY_TRESHOLD",
           ["attributiontools", "relation_creation_probability_treshold"],
           config,
        ))
        if self.relation_creation_probability_treshold < 0 or self.relation_creation_probability_treshold > 1:
            raise ValueError(f"ATTRIBUTIONTOOLS_RELATION_CREATION_PROBABILITY_TRESHOLD invalid number: {self.relation_creation_probability_treshold}. Should be 0-1.")
        ## Stix ID of relation creator organization (WithSecure)
        self.identity_id = get_config_variable(
           "ATTRIBUTIONTOOLS_CREATOR_ORG_IDENTITY_ID",
           ["attributiontools", "creator_org_identity_id"],
           config,
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.client = OpenCTIApiClient(
            url=self.helper.get_opencti_url(), token=self.helper.get_opencti_token()
        )

        self.dataexport = DataExport(self.client)

        self.helper.log_info(f"Model retraining schedule set to {self.cron}")

    def _process_message(self, data) -> None:
        # get standard_id for the incident where user triggered the attribution tool
        incident_standard_id = self.helper.api.stix_domain_object.read(
            id=data["entity_id"],
            types=["Incident"],
            customAttributes="standard_id"
        )["standard_id"]

        # get the incident entity and all first neighbours as bundle
        bundle: Dict = self.dataexport.export_entity(
            mode="full",
            entity_type="Incident",
            entity_id=incident_standard_id,
        )

        # Parse incident json from OpenCTI to str consumable by the model
        incident_str = parsers.incident_json_to_str(bundle)

        # Call prediction with the incident
        prediction = self.attribution_model.predict(incident_str)
        self.helper.log_info(prediction)

        # Parse stix id from prediction label
        def parse_stix_id(label):
            split_label = label.split("_")
            if len(split_label) < 2:
                raise ValueError(f"Prediction label has unexpected format, should contain an underscore: {label}")
            return split_label[-1]
        predicted_standard_ids = list(map(parse_stix_id, prediction["label"]["labels"]))

        bundle_objects = []

        # Create relation objects from predictions
        if self.automatic_relation_creation:
            for i in range(len(predicted_standard_ids)):
                prediction_probability = prediction["label"]["probas"][i]
                if prediction_probability < self.relation_creation_probability_treshold:
                    break
                # Create a relationship between the incident and predicted intrusion set
                relationship = Relationship(
                    created_by_ref=self.identity_id,
                    relationship_type="attributed-to",
                    description=(
                        "[AUTOMATIC ENRICHMENT] Relationship created automatically by the attribution-tools connector by WithSecure."
                        f"\n\nConfidence: {prediction_probability}"
                        f"\n\nPrediction rank: {i+1}."
                    ),
                    source_ref=incident_standard_id,
                    target_ref=predicted_standard_ids[i],
                    confidence=self.default_relation_confidence,
                )
                bundle_objects.append(relationship)
        
        # Create a note from the prediction results
        timestamp_str = f"{datetime.utcnow().isoformat(timespec='seconds')}Z"
        note_contents = (
            f"Attribution-tools enrichment performed on {timestamp_str}."
            f"\n\nModel version: {self.attribution_model.db_version}"
            "\n\nMost probable intrusion sets:"
            "\n|rank|name|probability|standard_id|link|"
            "\n|:-|:-|:-|:-|:-|"
        )
        ## Build table rows to note
        for i in range(len(predicted_standard_ids)):
            predicted_stix_object = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
                stix_id=predicted_standard_ids[i],
            )
            rank = i+1
            name = predicted_stix_object['name']
            probability = prediction['label']['probas'][i]
            standard_id = predicted_standard_ids[i]
            # Assume the object is an intrusion-set
            link = urljoin(
                self.helper.get_opencti_url(),
                f"/dashboard/threats/intrusion_sets/{predicted_stix_object['id']}"
            )
            note_contents += f"\n|{rank}|{name}|{probability}|{standard_id}|{link}|"
        note = Note(
            type="note",
            abstract=f"Attribution-tools connector enrichment {timestamp_str}",
            content=note_contents,
            created_by_ref=self.identity_id,
            object_refs=[incident_standard_id],
            confidence=0,
            custom_properties= {
                "note_types": ["assessment"]
            },
        )
        bundle_objects.append(note)

        # Upload created objects
        bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(
            bundle,
        )
        self.helper.log_info("Enrichment bundles sent!")

    def train_model(self, training_data, db_version):
        self.helper.log_info("Starting model training...")
        trained_values = TrainingAttributionToolsModel(training_data, db_version)
        model, f1_score, incremented_database_version = trained_values.retrain_model()
        self.attribution_model = AttributionToolsModel(model, incremented_database_version)
        self.helper.log_info(f"Model training successfully finished. F1 score: {f1_score}, new database version: {incremented_database_version}")

    def get_dataset_files(self) -> list:
        """Find and return existing training datasets that are present in TRAINING_DATA_PATH.

        :return: Returns a list of objects that contain the path, file_name, and timestamp 
        of the training datasets.
        """
        # Check if the directory exists
        if not os.path.exists(TRAINING_DATA_PATH):
            # Create the directory if it doesn't exist
            os.makedirs(TRAINING_DATA_PATH)
            # Training data does not exist, return empty list
            return []

        pattern = r'intrusionsets_(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\.json'
        files = []
        for file_name in os.listdir(TRAINING_DATA_PATH):
            match = re.match(pattern, file_name)
            if match:
                timestamp_str = match.group(1)
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%SZ')
                files.append({
                    "path": os.path.join(TRAINING_DATA_PATH, file_name),
                    "file_name": file_name,
                    "timestamp": timestamp
                })
        files.sort(key=lambda x: x['timestamp'], reverse=True)
        return files

    def load_saved_data_and_train_model(self) -> bool:
        files = self.get_dataset_files()
        for file in files:
            try:
                with open(file["path"]) as f:
                    training_data_object = json.load(f)
                # TODO: db version gets incremented here even though it shouldn't.
                # Requires changes in attribution_tools package or ugly workarounds.
                self.train_model(training_data_object["training_data"], training_data_object["db_version"])
                return True
            except KeyError:
                # Try to load older files
                continue
        return False

    def fetch_data_and_train_model(self):
        self.helper.log_info("Starting data fetch for model training...")
        # Announce upcoming training work
        now = datetime.utcnow()
        friendly_name = f"Model training @ {now.isoformat(timespec='seconds')}Z"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            friendly_name,
        )

        # Fetch training data
        training_data = self.dataexport.export_list(
            entity_type="Intrusion-Set",
            n_threads=self.n_query_threads,
        )

        # Train and set new model
        db_version = "(0, 0, 0)" if self.attribution_model is None else self.attribution_model.db_version
        self.train_model(training_data, db_version)
        finished_time = datetime.utcnow()
        timestamp_str = f"{finished_time.isoformat(timespec='seconds')}Z"

        # Save most recent training data
        training_data_object = {
            "created_time": timestamp_str,
            "db_version": self.attribution_model.db_version,
            "training_data": training_data,
        }
        with open(f"{TRAINING_DATA_PATH}/intrusionsets_{timestamp_str}.json", "w") as f:
            json.dump(training_data_object, f)
        self.helper.log_info("Training data saved.")

        # Delete old dataset files
        files = self.get_dataset_files()
        files_to_be_removed = files[N_MAX_DATASET_FILES:]
        for file in files_to_be_removed:
            os.remove(file["path"])

        # Announce that training is finished
        message = f"Model training completed at {timestamp_str}. Training took {finished_time - now}."
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_info("Model training successfully finished.")

    def scheduled_model_training_loop(self):
        # Create a retraining schedule based on provided cron expression
        schedule = self.cron.schedule(datetime.utcnow())
        while True:
            # Find next time matching schedule and wait
            next_datetime = schedule.next()
            time_difference = (next_datetime - datetime.utcnow())
            while time_difference.total_seconds() < 0:
                next_datetime = schedule.next()
                time_difference = (next_datetime - datetime.utcnow())
            self.helper.log_info(f"Next model training will happen in {time_difference} at {next_datetime.isoformat()}Z")
            time.sleep(time_difference.total_seconds())

            # Start model training
            self.fetch_data_and_train_model()

    def start(self):
        # Train model from saved data or fetch and train
        if not self.load_saved_data_and_train_model():
            self.fetch_data_and_train_model()
        scheduled_training_thread = threading.Thread(target=self.scheduled_model_training_loop, daemon=True)
        scheduled_training_thread.start()
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    attribution_tools = AttributionTools()
    attribution_tools.start()
