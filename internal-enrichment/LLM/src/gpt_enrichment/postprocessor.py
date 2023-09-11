import re
import json
from pycti import OpenCTIConnectorHelper
class Postprocessor:
    def __init__(self,helper: OpenCTIConnectorHelper):
        super().__init__() #this is not used for now. Idea is to create a TextProcessor class and have Preprocessor and Postprocessor inherit from it.
        self.emptyish=[
            "None",
            "none",
            "N/A",
            "n/a",
            "NA",
            "na",
            "N/a",
            "N\A",
            "Unknown",
            "unknown",
            "null",
            "Null",
            "NULL",

        ]
        emptyish_list_no_quote=["[{}]".format(emptyish) for emptyish in self.emptyish]
        emptyish_list_double_quote=["[\"{}\"]".format(emptyish) for emptyish in self.emptyish]
        emptyish_list_single_quote=["['{}']".format(emptyish) for emptyish in self.emptyish]
        self.emptyish+=emptyish_list_no_quote+emptyish_list_double_quote+emptyish_list_single_quote
        self.helper=helper
        self.prompt_to_stix={
            "CVE":"vulnerabilities",
            "TTP":"attack_patterns",
            "IoC":"indicators",
            "victim_location":"locations",
            "threat_actor":"intrusion_sets"
            }
        
        self.file_extensions=[
            "exe",
            "dll",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",
            "pdf",
            "txt",
            "zip",
            "rar",
            "7z",
            "gz",
            "tar",
            "iso",
            "elf",
            "bin",

        ]


    def map_prompt_field_to_stix_field(self, field : str) -> str:
        return self.prompt_to_stix[field] if field in self.prompt_to_stix.keys() else field

    def postprocess(self, blog : str) -> dict:
        #TODO: add filtering here to get rid of filenames ".exe,.dll etc."
        #TODO: add object speficic postprocessing here
        try:
            try:
                blog=json.loads(blog)
            except json.decoder.JSONDecodeError as e:
                self.helper.log_error(f"Error while decoding JSON: {e}")
                raise self.InvalidLLMResponseException(blog)
            
            output={}
            self.helper.log_debug(f"DEBUG DEBUG: Blog before postprocessing: \n\n {blog} \n\n")

            for field in blog.keys():
                if type(blog[field])==str:
                    output[self.map_prompt_field_to_stix_field(field)]=self.postprocess_str_field(blog[field])
                elif type(blog[field])==list:
                    output[self.map_prompt_field_to_stix_field(field)]=self.postprocess_list_field(blog[field])
                else:
                    self.helper.log_error(f"Unknown type {type(blog[field])} for field {field}")
                    output[field]=str(f"Unknown type {type(blog[field])} for field {field}") 
                    #TODO: the list should be checked against all valid STIX types.
                    #Ones matching should be logged as WARNING. Others should be logged as ERROR.

            output=self.lowercase_keys(output)
            return output
        except Exception as e:
            raise self.PostProcessingException(f"Error while postprocessing: {e}")

    def postprocess_str_field(self, field : str) -> str:
        return [] if self.convert_empty_str_to_list(field)==[] else self.convert_str_to_list(field)

    def convert_str_to_list(self, string : str) -> list:
        self.helper.log_debug(f"DEBUG DEBUG: Converting string \n\n {string} \n\nto list")
        return [item.strip() for item in string.split(",")]
    
    def convert_empty_str_to_list(self, string : str) -> list:
        return [] if string in self.emptyish else string
    
    def postprocess_list_field(self, field_value : list) -> list:
        stringified=[self.postprocess_dict_field(item) if type(item)==dict else str(item)for item in field_value] #TODO: use the postprocess_dict_field function here
        stripped=[item.strip() for item in stringified]
        return [item for item in stripped if item not in self.emptyish]
    
    def lowercase_keys(self, blog : dict) -> dict:
        return {key.lower():blog[key] for key in blog.keys()}
    
    def postprocess_dict_field(self, field_value : dict) -> dict: #TODO: This will be fully rewritten later.
        values_list=list(field_value.values())
        if len(values_list)==0:
            return {}
        if type(values_list[0])==list:
            values_list=values_list[0]
        elif type(values_list[0])==str:
            values_list=self.convert_str_to_list(values_list[0])
        else:
            pass #TODO add more types here, raise error if type is not supported.
        return str(values_list[0]) if len(values_list)==1 else "{}:{}".format(values_list[0],values_list[1]) #TODO: rework this to handle more names and types.
    

    class InvalidLLMResponseException(Exception): #TODO: move this to a separate file along with the other exceptions
        def __init__(self, invalid_response : str):
            super().__init__("LLM returned the following invalid response: {}".format(invalid_response))
    
    class PostProcessingException(Exception):
        def __init__(self, message):
            super().__init__(message)
    

    
    

