from abc import ABC, abstractmethod
from datetime import datetime
from re import T

TEAMT5_API_BASE_URL = "https://api.threatvision.org"
FOUND_STIX_ITEMS = set() 

class BaseHandler(ABC):
    
    #The name of the handler, for use in logging.
    name = None
    #The API endpoint for retrieving objects of the corresponding type
    url_suffix = None
    #The key required to look up the objects in the response, as per the TeamT5 API
    response_key = None



    def __init__(self, client, helper, config, author, tlp_ref):
        """
        Initialize the BaseHandler: an abstract base class implementing the Template Method
        design pattern to allow for customisations for different object types to the otherwise
        consistent retrieval and posting processes. 

        Subclasses implement the map_bundle_reference and create_additional_objects methods, allowing them
        to create additional STIX objects or otherwise alter the ways in which the retrieved data is handled.
        """
        self.client = client
        self.helper = helper
        self.config = config
        self.author = author
        self.tlp_ref = tlp_ref


    @abstractmethod
    def map_bundle_reference(self, raw_bundle_ref: dict) -> dict:       
        """
        Maps a bundle reference from the TeamT5 API based on the specifications delegated
        to subclasses. 

        :param raw_bundle_ref: A dictionary of the raw bundle reference from the API before mapping.
        :return: A dictionary of the mapped bundle reference.
        """
        pass
    

    @abstractmethod
    def create_additional_objects(self, stix_content: list, bundle_ref: dict) -> list:
        """
        Creates any additional objects required to be alongside the STIX bundle retrieved from
        the TeamT5 API. Based on the specifications delegated to subclasses. For example: a Report
        for the Report Handler.

        :param stix_content: A list of all stix objects in the bundle corresponding to the bundle reference.
        :param bundle_ref: A dictionary of the current bundle reference containing bundle information. 
        :return: A list containing the previous STIX content as well as any new objects.
        """
        pass



    def retrieve_bundle_references(self, last_run_timestamp: int) -> list:
        """
        Retrieves all bundle references from the TeamT5 API after the desired timestamp, of the type 
        corresponding to the calling Handler. 
        
        Bundle references are structures defined by the API that provide information about their
        contents as well as an endpoint URL to download their corresponding STIX bundle, for example,
        an IndicatorBundle reference.

        :param last_run_timestamp: The timestamp from which bundle references should be retrieved. 
        :return: A list containing all bundle references published to the API since the last run timestamp.
        """

        url = f"{str(TEAMT5_API_BASE_URL).rstrip('/')}{self.url_suffix}"
        retrieved_bundle_refs = []

        while True:

                params = {
                    "offset": len(retrieved_bundle_refs), 
                    "date[from]": last_run_timestamp
                }

                data = self.client._request_data(url, params)
                if not data or not data.get("success"):
                    self.helper.connector_logger.warning(
                        f"Unable to retrieve {self.name}: response from server was unsuccessful"
                    )
                    continue

                # Using template method, map each bundle reference based on the retrieved data.
                bundle_refs = [self.map_bundle_reference(raw_ref) for raw_ref in data[self.response_key]]

                self.helper.connector_logger.debug(
                    f"Found {len(bundle_refs)} {self.name} references."
                )
                retrieved_bundle_refs.extend(bundle_refs)
                if len(bundle_refs) == 0:
                    break

        return retrieved_bundle_refs


    def push_objects(self, work_id: str, bundle_refs: list) -> int:
        """
        Retrieves the bundle of STIX objects corresponding to each bundle reference
        and pushes them to OpenCTI.

        :param work_id: The id to be used in pushing said bundles.
        :param bundle_refs: A list of bundle references corresponding to the type of the Handler.
        :return: The number of bundles successfully pushed to OpenCTI.
        """

        num_bundles_pushed = 0
        
        for bundle_ref in bundle_refs:

            self.helper.connector_logger.debug(
                f"Processing {self.name} from: {datetime.fromtimestamp(bundle_ref.get('created_at')).strftime('%H:%M %d/%m/%Y')}"
            )

            bundle_url = bundle_ref.get("stix_url")
            if bundle_url is None:
                self.helper.connector_logger.warning(
                    f"Failed to push {self.name}: {self.name} has no STIX url from which it can be retrieved."
                )
                continue

            # Retrieve the STIX Bundle corresponding to the bundle reference
            stix_bundle = self.client._request_data(bundle_url)
            if stix_bundle is None:
                continue
            
            stix_content = stix_bundle.get("objects")
            if stix_content is None or len(stix_content) == 0:
                self.helper.connector_logger.info(
                    f"API Returned bundle with no items."
                )
                continue

            #Append author and TLP Marking to objects in the bundle
            stix_content = [self._append_author_and_tlp(obj) for obj in stix_content]

            #Create additional STIX Objects for required Handlers (e.g Report object for Report Handler)
            stix_content = self.create_additional_objects(stix_content, bundle_ref)

            stix_content.extend([self.author, self.tlp_ref])

            # Push the bundle to the platform
            bundle = self.helper.stix2_create_bundle(stix_content)
            self.helper.send_stix2_bundle(
                bundle, work_id=work_id, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(
                f"{self.name} with {len(stix_content)} objects pushed to OpenCTI successfully."
            )
            num_bundles_pushed += 1

        return num_bundles_pushed


    def _append_author_and_tlp(self, stix_object: dict) -> dict: 
        """
        Appends an author and TLP Marking to a pre-existing STIX object in dictionary form. 
        NB: Of the object types processed by the connector, domain-name and ipv4-addr are the only ones
        which cannot receive an author attribute. 

        :param stix_object: A STIX object in dictionary form.
        :return: The same STIX object in dictionary form, with the desired TLP Marking and author (where applicable).
        """

        objects_without_author = {"ipv4-addr", "domain-name"}

        #Append author where applicable
        obj_type = stix_object.get("type")
        if obj_type not in objects_without_author:
            stix_object["created_by_ref"] = self.author["id"]

        #Append TLP Marking
        stix_object["object_marking_refs"] = stix_object.get("object_marking_refs",[]) + [self.tlp_ref["id"]]


        #TODO: remove
        FOUND_STIX_ITEMS.add(obj_type)
        self.helper.connector_logger.info(FOUND_STIX_ITEMS)

        return stix_object


        