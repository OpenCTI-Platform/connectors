import io
import logging
import os
from typing import IO, Dict, List, Pattern, Tuple

import chardet
import ioc_finder
from bs4 import BeautifulSoup
from pdfminer.high_level import extract_pages
from pdfminer.layout import LTTextContainer
from pycti import OpenCTIConnectorHelper
from reportimporter.constants import (
    ENTITY_CLASS,
    MIME_CSV,
    MIME_HTML,
    MIME_MD,
    MIME_PDF,
    MIME_TXT,
    OBSERVABLE_CLASS,
    OBSERVABLE_DETECTION_CUSTOM_REGEX,
    OBSERVABLE_DETECTION_LIBRARY,
    RESULT_FORMAT_CATEGORY,
    RESULT_FORMAT_MATCH,
    RESULT_FORMAT_RANGE,
    RESULT_FORMAT_TYPE,
)
from reportimporter.models import Entity, Observable
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
            MIME_HTML: self._parse_html,
            MIME_CSV: self._parse_text,
            MIME_MD: self._parse_text,
        }

        self.library_lookup = library_mapping()

    def _is_whitelisted(self, regex_list: List[Pattern], ind_match: str):
        for regex in regex_list:
            self.helper.log_debug(f"Filter regex '{regex}' for value '{ind_match}'")
            result = regex.search(ind_match)
            if result:
                self.helper.log_debug(f"Value {ind_match} is whitelisted with {regex}")
                return True
        return False

    def _post_parse_observables(
        self, ind_match: str, observable: Observable, match_range: Tuple
    ) -> Dict:
        self.helper.log_debug(f"Observable match: {ind_match}")

        if self._is_whitelisted(observable.filter_regex, ind_match):
            return {}

        return self._format_match(
            OBSERVABLE_CLASS, observable.stix_target, ind_match, match_range
        )

    def parse(self, data: str) -> Dict[str, Dict]:
        list_matches = {}

        # Defang text
        data = ioc_finder.prepare_text(data)

        for observable in self.observable_list:
            list_matches.update(self._extract_observable(observable, data))

        for entity in self.entity_list:
            list_matches = self._extract_entity(entity, list_matches, data)

        self.helper.log_debug(f"Text: '{data}' -> extracts {list_matches}")
        return list_matches

    def _parse_pdf(self, file_data: IO) -> Dict[str, Dict]:
        parse_info = {}
        try:
            for page_layout in extract_pages(file_data):
                for element in page_layout:
                    if isinstance(element, LTTextContainer):
                        text = element.get_text()
                        # Parsing with newlines has been deprecated
                        no_newline_text = text.replace("\n", "")
                        parse_info.update(self.parse(no_newline_text))

                # TODO also extract information from images/figures using OCR
                # https://pdfminersix.readthedocs.io/en/latest/topic/converting_pdf_to_text.html#topic-pdf-to-text-layout

        except Exception as e:
            logging.exception(f"Pdf Parsing Error: {e}")

        return parse_info

    def _parse_text(self, file_data: IO) -> Dict[str, Dict]:
        parse_info = {}
        text = file_data.read()
        encoding = chardet.detect(text)["encoding"]
        if encoding == "UTF-16":
            parse_info.update(self.parse(text.decode("utf-16")))
        else:
            parse_info.update(self.parse(text.decode("utf-8")))
        return parse_info

    def _parse_html(self, file_data: IO) -> Dict[str, Dict]:
        parse_info = {}
        soup = BeautifulSoup(file_data, "html.parser")
        buf = io.StringIO(soup.get_text(separator=" "))
        for text in buf.readlines():
            parse_info.update(self.parse(text))
        return parse_info

    def run_raw_parser(self, file_path: str, file_type: str) -> Dict:
        parsing_results = []

        file_parser = self.supported_file_types.get(file_type, None)
        if not file_parser:
            raise NotImplementedError(f"No parser available for file type {file_type}")

        if not os.path.isfile(file_path):
            raise IOError(f"File path is not a file: {file_path}")

        self.helper.log_info(f"Parsing report {file_path} {file_type}")

        try:
            with open(file_path, "rb") as file_data:
                parsing_results = file_parser(file_data)
        except Exception as e:
            logging.exception(f"Parsing Error: {e}")

        return parsing_results

    def run_parser(self, file_path: str, file_type: str) -> List[Dict]:
        raw_result = self.run_raw_parser(file_path, file_type)
        parsing_results = list(raw_result.values())

        return parsing_results

    @staticmethod
    def _format_match(
        format_type: str, category: str, match: str, match_range: Tuple = (0, 0)
    ) -> Dict:
        return {
            RESULT_FORMAT_TYPE: format_type,
            RESULT_FORMAT_CATEGORY: category,
            RESULT_FORMAT_MATCH: match,
            RESULT_FORMAT_RANGE: match_range,
        }

    @staticmethod
    def _sco_present(
        match_list: Dict, entity_range: Tuple, filter_sco_types: List
    ) -> str:
        for match_name, match_info in match_list.items():
            if match_info[RESULT_FORMAT_CATEGORY] in filter_sco_types:
                if (
                    match_info[RESULT_FORMAT_RANGE][0] <= entity_range[0]
                    and entity_range[1] <= match_info[RESULT_FORMAT_RANGE][1]
                ):
                    return match_name

        return ""

    def _extract_observable(self, observable: Observable, data: str) -> Dict:
        list_matches = {}
        if observable.detection_option == OBSERVABLE_DETECTION_CUSTOM_REGEX:
            for regex in observable.regex:
                for match in regex.finditer(data):
                    match_value = match.group()

                    ind_match = self._post_parse_observables(
                        match_value, observable, match.span()
                    )
                    if ind_match:
                        list_matches[match.group()] = ind_match

        elif observable.detection_option == OBSERVABLE_DETECTION_LIBRARY:
            lookup_function = self.library_lookup.get(observable.stix_target, None)
            if not lookup_function:
                self.helper.log_error(
                    f"Selected library function is not implemented: {observable.iocfinder_function}"
                )
                return {}

            matches = lookup_function(data)

            for match in matches:
                match_str = str(match)
                if match_str in data:
                    start = data.index(match_str)
                elif match_str in data.lower():
                    self.helper.log_debug(
                        f"External library manipulated the extracted value '{match_str}' from the "
                        f"original text '{data}' to lower case"
                    )
                    start = data.lower().index(match_str)
                else:
                    self.helper.log_error(
                        f"The extracted text '{match_str}' is not part of the original text '{data}'. "
                        f"Please open a GitHub issue to report this problem!"
                    )
                    continue

                ind_match = self._post_parse_observables(
                    match, observable, (start, len(match_str) + start)
                )
                if ind_match:
                    list_matches[match] = ind_match

        return list_matches

    def _extract_entity(self, entity: Entity, list_matches: Dict, data: str) -> Dict:
        regex_list = entity.regex

        observable_keys = []
        end_index = set()
        match_dict = {}
        match_key = ""

        # Run all regexes for entity X
        for regex in regex_list:
            for match in regex.finditer(data):
                match_key = match.group()
                if match_key in match_dict:
                    match_dict[match_key].append(match.span())
                else:
                    match_dict[match_key] = [match.span()]

        # No maches for this entity
        if len(match_dict) == 0:
            return list_matches

        # Run through all matches for entity X and check if they are part of a domain
        # yes -> skip
        # no -> add index to end_index
        for match, match_indices in match_dict.items():
            for match_index in match_indices:
                skip_val = self._sco_present(
                    list_matches, match_index, entity.omit_match_in
                )
                if skip_val:
                    self.helper.log_debug(
                        f"Skipping Entity '{match}', it is part of an omitted field '{entity.omit_match_in}' \"{skip_val}\""
                    )
                else:
                    self.helper.log_debug(
                        f"Entity match: '{match}' of regex: '{regex_list}'"
                    )
                    end_index.add(match_index)
                    if match in list_matches.keys():
                        observable_keys.append(match)

        # Remove all observables which found the same information/Entity match
        for observable_key in observable_keys:
            if observable_key in list_matches:
                del list_matches[observable_key]
                self.helper.log_debug(
                    f"Value {observable_key} is also matched by entity {entity.name}"
                )

        # Check if entity was matched at least once in the text
        # If yes, then add identity to match list
        if end_index:
            list_matches[match_key] = self._format_match(
                ENTITY_CLASS, entity.name, entity.stix_id
            )

        return list_matches
