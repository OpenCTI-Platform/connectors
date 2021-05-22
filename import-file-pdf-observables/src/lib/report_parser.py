# coding: utf-8
import io
import os
import re
from typing import Dict, List

from pdfminer.high_level import extract_pages, extract_text_to_fp
from pdfminer.layout import LTTextContainer, LTChar, LTImage

import logging
from .models import Observable, Entity


class ReportParser(object):
    """
    Report parser based on IOCParser
    """

    def __init__(self, entity_list: List[Entity], observable_list: List[Observable]):

        self.entity_list = entity_list
        self.observable_list = observable_list

        # Disable INFO logging by pdfminer
        logging.getLogger("pdfminer").setLevel(logging.WARNING)

        # Supported file types
        self.supported_file_types = {
            'application/pdf': self._parse_pdf,
            'text/plain': self._parse_text
        }

    def _is_whitelisted(self, observable: Observable, ind_match: str):
        for regex in observable.filter_regex:
            result = regex.search(ind_match)
            if result:
                return True
        return False

    def _parse(self, data: str) -> List[Dict]:
        list_matches = []
        values = set()


        for observable in self.observable_list:
            for regex in observable.regex:
                matches = regex.findall(data)
                for ind_match in matches:
                    if isinstance(ind_match, tuple):
                        ind_match = ind_match[0]

                    if observable.defang:
                        ind_match = self._defang(ind_match)

                    if self._is_whitelisted(observable, ind_match):
                        continue

                    values.add(ind_match)

                    list_matches.append(
                        self._format_match('observable', observable.stix_target, ind_match)
                    )

        for entity in self.entity_list:
            regex_list = entity.regex
            for regex in regex_list:
                matches = regex.findall(data)

                if len(matches) > 0 and type(matches[0]) != tuple:
                    list_matches.append(
                        self._format_match('entity', entity.name, entity.stix_id)
                    )

                # TODO: Avoid adding hits as entity AND as observable, like the entity cmd.exe
                # as well as the filename cmd.exe

        logging.debug("Text: {} -> extracts {}".format(data, list_matches))
        return list_matches

    def _parse_pdf(self, file_data: str) -> List[Dict]:
        parse_info = []
        try:
            for page_layout in extract_pages(file_data):
                for element in page_layout:
                    if isinstance(element, LTTextContainer):
                        text = element.get_text()
                        no_newline_text = text.replace('\n', '')
                        parse_info += self._parse(no_newline_text)
                        parse_info += self._parse(text)

                # TODO also extract information from images/figures using OCR
                # https://pdfminersix.readthedocs.io/en/latest/topic/converting_pdf_to_text.html#topic-pdf-to-text-layout

            # output_string = io.StringIO()
            # extract_text_to_fp(file_data, output_string)
            # parse_info += self._parse(output_string.getvalue())

        except Exception as e:
            logging.exception("Pdf Parsing Error: {}".format(e))

        return parse_info

    def _parse_text(self, file_data: io.BufferedReader) -> List[Dict]:
        parse_info = []
        for text in file_data.readlines():
            parse_info += self._parse(text.decode('utf-8'))
        return parse_info

    def run_parser(self, file_path: str, file_type: str) -> List[Dict]:
        parsing_results = []

        file_parser = self.supported_file_types.get(file_type, None)
        if not file_parser:
            raise NotImplementedError('No parser available for file type {}'.format(file_type))

        if not os.path.isfile(file_path):
            raise IOError("File path is not a file: %s" % (file_path))

        logging.info('Parsing report {} {}'.format(file_path, file_type))

        try:
            with open(file_path, "rb") as file_data:
                parsing_results = file_parser(file_data)
        except Exception as e:
            logging.exception('Parsing Error: {}'.format(e))

        parsing_results = self._deduplicate(parsing_results)

        return parsing_results

    def _deduplicate(self, parsed_info: List):
        unique_list = list()
        for value in parsed_info:
            if value not in unique_list:
                unique_list.append(value)

        return unique_list

    def _defang(self, value: str) -> str:
        """
        Defang sanitized value

        :param value: sanitized value
        :return: desanititzed value
        """
        defang_types = [
            ('[.]', '.'),
            ('hxxx://', 'http://'),
            ('hxxp://', 'http://'),
            ('hxxxx://', 'https://'),
            ('hxxps://', 'https://'),
            ('hxxxs://', 'https://')
        ]

        for defang_type in defang_types:
            if defang_type[0] in value:
                value.replace(defang_type[0], defang_type[1])

        return value

    def _format_match(self, type, category, match):
        return {'type': type, 'category': category, 'match': match}
