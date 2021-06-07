import logging
import os
from typing import Dict, List, Pattern, IO

from pdfminer.high_level import extract_pages
from pdfminer.layout import LTTextContainer
from pycti import OpenCTIConnectorHelper
from reportimporter.constants import (
    OBSERVABLE_CLASS,
    ENTITY_CLASS,
    RESULT_FORMAT_MATCH,
    RESULT_FORMAT_TYPE,
    RESULT_FORMAT_CATEGORY,
    MIME_PDF,
    MIME_TXT,
    OBSERVABLE_DETECTION_CUSTOM_REGEX,
    OBSERVABLE_DETECTION_LIBRARY,
)
from reportimporter.models import Observable, Entity
from reportimporter.util import library_mapping


class ReportParser(object):
    """
    Report parser based on IOCParser
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        entity_list: List[Entity],
        observable_list: List[Observable],
    ):

        self.helper = helper
        self.entity_list = entity_list
        self.observable_list = observable_list

        # Disable INFO logging by pdfminer
        logging.getLogger("pdfminer").setLevel(logging.WARNING)

        # Supported file types
        self.supported_file_types = {
            MIME_PDF: self._parse_pdf,
            MIME_TXT: self._parse_text,
        }

        self.library_lookup = library_mapping()

    def _is_whitelisted(self, regex_list: List[Pattern], ind_match: str):
        for regex in regex_list:
            self.helper.log_debug("Regex value: {}".format(regex))
            result = regex.search(ind_match)
            if result:
                self.helper.log_debug(
                    "Value {} is whitelisted with {}".format(ind_match, regex)
                )
                return True
        return False

    def _post_parse_observables(self, ind_match: str, observable: Observable) -> Dict:
        self.helper.log_debug("Observable match {}".format(ind_match))

        if observable.defang:
            ind_match = self._defang(ind_match)

        if self._is_whitelisted(observable.filter_regex, ind_match):
            return {}

        return self._format_match(OBSERVABLE_CLASS, observable.stix_target, ind_match)

    def _parse(self, data: str) -> List[Dict]:
        list_matches = []

        for observable in self.observable_list:
            if observable.detection_option == OBSERVABLE_DETECTION_CUSTOM_REGEX:
                for regex in observable.regex:
                    matches = regex.findall(data)
                    for ind_match in matches:
                        if isinstance(ind_match, tuple):
                            ind_match = ind_match[0]

                        ind_match = self._post_parse_observables(ind_match, observable)
                        if ind_match:
                            list_matches.append(ind_match)

            elif observable.detection_option == OBSERVABLE_DETECTION_LIBRARY:
                lookup_function = self.library_lookup.get(observable.stix_target, None)
                if not lookup_function:
                    self.helper.log_error(
                        "Selected library function is not implemented: {}".format(
                            observable.iocfinder_function
                        )
                    )

                matches = lookup_function(data)

                for ind_match in matches:
                    ind_match = self._post_parse_observables(ind_match, observable)
                    if ind_match:
                        list_matches.append(ind_match)

        for entity in self.entity_list:
            regex_list = entity.regex
            for regex in regex_list:
                matches = regex.findall(data)

                if len(matches) > 0 and type(matches[0]) != tuple:
                    list_matches.append(
                        self._format_match(ENTITY_CLASS, entity.name, entity.stix_id)
                    )

        self.helper.log_debug("Text: {} -> extracts {}".format(data, list_matches))
        return list_matches

    def _parse_pdf(self, file_data: IO) -> List[Dict]:
        parse_info = []
        try:
            for page_layout in extract_pages(file_data):
                for element in page_layout:
                    if isinstance(element, LTTextContainer):
                        text = element.get_text()
                        no_newline_text = text.replace("\n", "")
                        parse_info += self._parse(no_newline_text)
                        # Parsing with newlines has been deprecated

                # TODO also extract information from images/figures using OCR
                # https://pdfminersix.readthedocs.io/en/latest/topic/converting_pdf_to_text.html#topic-pdf-to-text-layout

            # output_string = io.StringIO()
            # extract_text_to_fp(file_data, output_string)
            # parse_info += self._parse(output_string.getvalue())

        except Exception as e:
            logging.exception("Pdf Parsing Error: {}".format(e))

        return parse_info

    def _parse_text(self, file_data: IO) -> List[Dict]:
        parse_info = []
        for text in file_data.readlines():
            parse_info += self._parse(text.decode("utf-8"))
        return parse_info

    def run_parser(self, file_path: str, file_type: str) -> List[Dict]:
        parsing_results = []

        file_parser = self.supported_file_types.get(file_type, None)
        if not file_parser:
            raise NotImplementedError(
                "No parser available for file type {}".format(file_type)
            )

        if not os.path.isfile(file_path):
            raise IOError("File path is not a file: {}".format(file_path))

        self.helper.log_info("Parsing report {} {}".format(file_path, file_type))

        try:
            with open(file_path, "rb") as file_data:
                parsing_results = file_parser(file_data)
        except Exception as e:
            logging.exception("Parsing Error: {}".format(e))

        parsing_results = self._deduplicate(parsing_results)
        parsing_results = self._remove_entities_from_observables(parsing_results)

        return parsing_results

    @staticmethod
    def _deduplicate(parsed_info: List):
        unique_list = list()
        for value in parsed_info:
            if value not in unique_list:
                unique_list.append(value)

        return unique_list

    @staticmethod
    def _defang(value: str) -> str:
        defang_types = [
            ("[.]", "."),
            ("hxxx://", "http://"),
            ("hxxp://", "http://"),
            ("hxxxx://", "https://"),
            ("hxxps://", "https://"),
            ("hxxxs://", "https://"),
        ]

        for defang_type in defang_types:
            if defang_type[0] in value:
                value = value.replace(defang_type[0], defang_type[1])

        return value

    @staticmethod
    def _format_match(format_type: str, category: str, match: str) -> Dict:
        return {
            RESULT_FORMAT_TYPE: format_type,
            RESULT_FORMAT_CATEGORY: category,
            RESULT_FORMAT_MATCH: match,
        }

    def _remove_entities_from_observables(self, parsing_results: List) -> List:
        unique_list = list()
        for value in parsing_results:
            if value[RESULT_FORMAT_TYPE] != OBSERVABLE_CLASS:
                unique_list.append(value)
            else:
                match = False
                for entity in self.entity_list:
                    if self._is_whitelisted(entity.regex, value[RESULT_FORMAT_MATCH]):
                        match = True
                        self.helper.log_debug(
                            "Value {} is also matched by entity {}".format(
                                value, entity.name
                            )
                        )
                        break

                if not match:
                    unique_list.append(value)

        return unique_list
