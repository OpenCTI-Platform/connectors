import os
import yaml
import stix2
import json
import datetime
from pycti import OpenCTIConnectorHelper, Note, get_config_variable
from .prompter import GptClient
from .blog_fetcher import BlogFetcher
from .regex_extract import RegexExtractor
from threading import Lock

class GptEnrichmentConnector:
    def __init__(self):
        self._SOURCE_NAME = "GPT Enrichment Connector"
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.temperature = get_config_variable(
            "GPT_ENRICHMENT_TEMPERATURE", ["gpt_enrichment", "temperature"], config, False, 0.0
        )
        self.model = get_config_variable(
            "GPT_ENRICHMENT_MODEL", ["gpt_enrichment", "model"], config, False, "gpt-3.5-turbo-16k"
        )
        self.apikey = get_config_variable(
            "GPT_ENRICHMENT_APIKEY", ["gpt_enrichment", "apikey"], config, False, ""
        )

        self.author = self.helper.api.identity.create(type="Organization", name=self._SOURCE_NAME, description="GPT-Enrichment Connector", confidence=self.helper.connect_confidence_level)

        self.prompt_version = get_config_variable(
            "GPT_ENRICHMENT_PROMPT_VERSION", ["gpt_enrichment", "prompt_version"], config, False, "v0.0.1"
        )
        self.lock = Lock()

    def run(self):
        # Start the main loop of the connector
        self.helper.listen(self.start_enrichment)
        
    def start_enrichment(self, data):
        entity_id = data["entity_id"]
        report = self.helper.api.report.read(id=entity_id)
        if report is None:
            raise ValueError("Report not found")
        self.lock.acquire()
        try:
            for external_reference in report["externalReferences"]:
                if external_reference["url"].startswith("https://otx.alienvault"):
                    continue
                blog_html = BlogFetcher.get_html(self.helper, external_reference["url"])


                blog = BlogFetcher.extract_all(self.helper, blog_html)
                context = GptClient.prompt(self.helper, blog, self.apikey, self.model, self.temperature, self.prompt_version)
                note_body = f"Temperature: {self.temperature}\nModel: {self.model}\nPrompt: {self.prompt_version}\n```\n" + json.dumps(eval(context), indent=2) + "\n```"
                self.helper.api.note.create(
                            id=Note.generate_id(datetime.datetime.now().isoformat(), note_body),
                            abstract="GPT-Enrichment Result",
                            content=note_body,
                            created_by_ref=self.author,
                            objects=[entity_id],
                        )
                self.helper.log_info("Created a gpt enrichment note for external reference: " + external_reference["url"])

                blog_only_p = BlogFetcher.extract_p_text(blog_html)
                regex_extract = RegexExtractor.extract_all(blog_only_p)

                note_body_regex = f"```Regex Extractor: \n" + json.dumps(regex_extract, indent=2) + "\n```"

                self.helper.api.note.create(
                            id=Note.generate_id(datetime.datetime.now().isoformat(), note_body_regex),
                            abstract="Regex Extractor Result",
                            content=note_body_regex,
                            created_by_ref=self.author,
                            objects=[entity_id],
                        )
                self.helper.log_info("Created a regex extractor note for external reference: " + external_reference["url"])
            self.lock.release()
        except Exception as e:
            self.lock.release()
            raise ValueError("Error during enrichment: " + str(e))

    


    