
PRODUCT_NAME = "OpenCTI"
VENDOR_NAME = "Filigran"


class UDMEntity:
    """
    Represent a Google UDM entity
    """

    def __init__(
        self,
        helper: any = None,
        data: dict = None,
    ):
        self.data = data
        self.helper = helper

    def convert(self):
        print("je suis dans convert")
        test = self.helper.get_attribute_in_extension("observable_values", self.data)
        print(self.data)
        print(test)
        for observable in self.helper.get_attribute_in_extension("observable_values", self.data):
            print(f"going to parse observable: {observable}")

            metadata = {
                "vendor_name": VENDOR_NAME,
                "product_name": PRODUCT_NAME,
                "collected_timestamp": self.data["created_at"],
                "product_entity_id": self.data["id"],
                "description": self.data["description"],
                "interval": {
                    "start_time": self.data["valid_from"],
                    "end_time": self.data["valid_until"],
                },
                "threat": {
                    "confidence_details": int(self.data["confidence"]),
                    "risk_score": int(self.helper.get_attribute_in_extension("score", self.data))
                }
            }

            if self.data.get("labels"):
                metadata["threat"]["category_details"] = ", ".join(self.data.get("labels"))

            entity = {}
            match observable.get("type"):
                case "Domain-Name":
                    entity['hostname'] = self.data.get("name") #TODO: to change
                    metadata['entity_type'] = 'DOMAIN_NAME'
                case "IPV4-Address":
                    entity['ip'] = self.data.get("name") #TODO: to change
                    metadata['entity_type'] = 'IP_ADDRESS'
                case "IPV6-Address":
                    entity['ip'] = self.data.get("name") #TODO: to change
                    metadata['entity_type'] = 'IP_ADDRESS'
                case "URL":
                    # remove the http or https protocol from URL if your log source doesn't record this
                    # sanitized_url = fix_url(indicator['value'],"^http(s)?://")
                    # entity['url'] = sanitized_url
                    entity['url'] = self.data.get("name") #TODO: to change
                    metadata['entity_type'] = 'URL'
                case "File":
                    file = {}
                    file['md5'] = self.data.get("name") #TODO: to change
                    metadata['entity_type'] = 'FILE'
                    entity['file'] = file
                case "sha1":
                    file = {}
                    file['sha1'] = self.data.get("name") #TODO: to change
                    metadata['entity_type'] = 'FILE'
                    entity['file'] = file
                case "sha256":
                    file = {}
                    file['sha256'] = self.data.get("name") #TODO: to change
                    metadata['entity_type'] = 'FILE'
                    entity['file'] = file
