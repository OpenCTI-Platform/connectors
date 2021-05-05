#!/usr/bin/env python

###################################################################################################
#
# Copyright (c) 2015, Armin Buescher (armin.buescher@googlemail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
###################################################################################################
#
# File:             iocp.py
# Description:      IOC Parser is a tool to extract indicators of compromise from security reports
#                   in PDF format.
# Usage:            iocp.py [-h] [-p INI] [-f FORMAT] PDF
# Author:           Armin Buescher (@armbues)
# Contributors:     Angelo Dell'Aera (@angelodellaera)
# Thanks to:        Jose Ramon Palanco
#                   Koen Van Impe (@cudeso)
#
###################################################################################################

import os
import fnmatch
import argparse
import re
from io import StringIO
from setuptools.namespaces import flatten


try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

# Import optional third-party libraries
IMPORTS = []
try:
    from PyPDF2 import PdfFileReader

    IMPORTS.append("pypdf2")
except ImportError:
    pass
try:
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfinterp import PDFResourceManager
    from pdfminer.converter import TextConverter
    from pdfminer.pdfinterp import PDFPageInterpreter
    from pdfminer.layout import LAParams

    IMPORTS.append("pdfminer")
except ImportError:
    pass
try:
    from bs4 import BeautifulSoup

    IMPORTS.append("beautifulsoup")
except ImportError:
    pass


# Import additional project source files
import output
from whitelist import WhiteList


class IOC_Parser(object):
    patterns = {}
    defang = {}

    def __init__(
        self,
        patterns_ini=None,
        input_format="pdf",
        dedup=False,
        library="pdfminer",
        output_format="csv",
        output_handler=None,
        custom_indicators=None,
    ):
        basedir = os.path.dirname(os.path.abspath(__file__))
        if patterns_ini is None:
            patterns_ini = os.path.join(basedir, "patterns.ini")

        self.load_patterns(patterns_ini)
        self.whitelist = WhiteList(basedir)
        self.dedup = dedup
        if output_handler:
            self.handler = output_handler
        else:
            self.handler = output.getHandler(output_format)

        self.ext_filter = "*." + input_format
        self.custom_indicators = custom_indicators

        parser_format = "parse_" + input_format
        try:
            self.parser_func = getattr(self, parser_format)
        except AttributeError:
            e = "Selected parser format is not supported: %s" % (input_format)
            raise NotImplementedError(e)

        self.library = library
        if input_format == "pdf":
            if library not in IMPORTS:
                e = "Selected PDF parser library not found: %s" % (library)
                raise ImportError(e)
        elif input_format == "html":
            if "beautifulsoup" not in IMPORTS:
                e = "HTML parser library not found: BeautifulSoup"
                raise ImportError(e)

    def load_patterns(self, fpath):
        config = ConfigParser.ConfigParser()
        with open(fpath) as f:
            config.read_file(f)

        for ind_type in config.sections():
            try:
                ind_pattern = config.get(ind_type, "pattern")
            except:
                continue

            if ind_pattern:
                ind_regex = re.compile(ind_pattern)
                self.patterns[ind_type] = ind_regex

            try:
                ind_defang = config.get(ind_type, "defang")
            except:
                continue

            if ind_defang:
                self.defang[ind_type] = True

    def is_whitelisted(self, ind_match, ind_type):
        try:
            for w in self.whitelist[ind_type]:
                if w.findall(ind_match):
                    return True
        except KeyError:
            pass
        return False

    def parse_page(self, fpath, data, page_num):
        list_matches = []
        for ind_type, ind_regex in self.patterns.items():
            matches = ind_regex.findall(data)
            for ind_match in matches:
                if isinstance(ind_match, tuple):
                    ind_match = ind_match[0]

                if self.is_whitelisted(ind_match, ind_type):
                    continue

                if ind_type in self.defang:
                    ind_match = re.sub(r"\[\.\]", ".", ind_match)

                if self.dedup:
                    if (ind_type, ind_match) in self.dedup_store:
                        continue

                    self.dedup_store.add((ind_type, ind_match))
                list_matches.append(
                    self.handler.print_match(fpath, page_num, ind_type, ind_match)
                )

        if self.custom_indicators:
            for indicator_type, indicator_dict in self.custom_indicators.items():
                indicators = set(flatten(indicator_dict.values()))
                indicators = ["\\b{}\\b".format(v) for v in indicators]
                indicators = "|".join(indicators)
                findings = re.findall(indicators, data, re.IGNORECASE)

                if len(findings) > 0 and type(findings[0]) != tuple:
                    for stix_id, names in indicator_dict.items():
                        lower_names = set(map(lambda x: x.lower(), names))
                        for finding in findings:
                            try:
                                if finding.lower() in lower_names:
                                    list_matches.append(
                                        self.handler.print_match(
                                            fpath, page_num, indicator_type, stix_id
                                        )
                                    )
                            except Exception as e:
                                self.handler.print_error(findings, e)

        return list_matches

    def parse_pdf_pypdf2(self, f, fpath):
        try:
            list_pages = []
            pdf = PdfFileReader(f, strict=False)

            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)
            page_num = 0
            for page in pdf.pages:
                page_num += 1
                data = page.extractText()
                list_pages.append(self.parse_page(fpath, data, page_num))
            self.handler.print_footer(fpath)
            return list_pages
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_pdf_pdfminer(self, f, fpath):
        try:
            list_pages = []
            laparams = LAParams()
            laparams.all_texts = True
            rsrcmgr = PDFResourceManager()
            pagenos = set()

            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)
            page_num = 0
            for page in PDFPage.get_pages(f, pagenos, check_extractable=True):
                page_num += 1

                retstr = StringIO()
                device = TextConverter(rsrcmgr, retstr, laparams=laparams)
                interpreter = PDFPageInterpreter(rsrcmgr, device)
                interpreter.process_page(page)
                data = retstr.getvalue()
                retstr.close()
                list_pages.append(self.parse_page(fpath, data, page_num))
            self.handler.print_footer(fpath)
            return list_pages
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_pdf(self, f, fpath):
        parser_format = "parse_pdf_" + self.library
        try:
            self.parser_func = getattr(self, parser_format)
        except AttributeError:
            e = "Selected PDF parser library is not supported: %s" % (self.library)
            raise NotImplementedError(e)

        return self.parser_func(f, fpath)

    def parse_txt(self, f, fpath):
        try:
            if self.dedup:
                self.dedup_store = set()

            data = f.read()
            self.handler.print_header(fpath)
            self.parse_page(fpath, data, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_html(self, f, fpath):
        try:
            if self.dedup:
                self.dedup_store = set()

            data = f.read()
            soup = BeautifulSoup(data, features="lxml")
            html = soup.findAll(text=True)

            text = u""
            for elem in html:
                if elem.parent.name in [
                    "style",
                    "script",
                    "[document]",
                    "head",
                    "title",
                ]:
                    continue
                elif re.match("<!--.*-->", str(elem)):
                    continue
                else:
                    text += str(elem)

            self.handler.print_header(fpath)
            self.parse_page(fpath, text, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse(self, path):
        try:
            # TODO add support for URLs => this would require using pdfminer and modifying output.py
            # if path.startswith('http://') or path.startswith('https://'):
            # list_files = []
            # if 'requests' not in IMPORTS:
            #   e = 'HTTP library not found: requests'
            #  raise ImportError(e)
            # headers = { 'User-Agent': 'Mozilla/5.0 Gecko Firefox' }
            # r = requests.get(path, headers=headers)
            # r.raise_for_status()
            # f = BytesIO(r.content)
            # print(f)
            # list_files.append(self.parser_func(f, path))
            # print(list_files)
            # return list_files
            if os.path.isfile(path):
                list_files = []
                with open(path, "rb") as f:
                    list_files.append(self.parser_func(f, path))
                    # self.parser_func(f, path)
                return list_files
            elif os.path.isdir(path):
                list_files = []
                for walk_root, walk_dirs, walk_files in os.walk(path):
                    for walk_file in fnmatch.filter(walk_files, self.ext_filter):
                        fpath = os.path.join(walk_root, walk_file)
                        with open(fpath, "rb") as f:
                            list_files.append(self.parser_func(f, fpath))
                return list_files

            e = "File path is not a file or directory: %s" % (path)
            raise IOError(e)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(path, e)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "PATH", action="store", help="File/directory/URL to report(s)"
    )
    argparser.add_argument("-p", dest="INI", default=None, help="Pattern file")
    argparser.add_argument(
        "-i", dest="INPUT_FORMAT", default="pdf", help="Input format (pdf/txt/html)"
    )
    argparser.add_argument(
        "-o",
        dest="OUTPUT_FORMAT",
        default="csv",
        help="Output format (csv/json/yara/netflow)",
    )
    argparser.add_argument(
        "-d",
        dest="DEDUP",
        action="store_true",
        default=False,
        help="Deduplicate matches",
    )
    argparser.add_argument(
        "-l",
        dest="LIB",
        default="pdfminer",
        help="PDF parsing library (pypdf2/pdfminer)",
    )
    args = argparser.parse_args()

    parser = IOC_Parser(
        args.INI, args.INPUT_FORMAT, args.DEDUP, args.LIB, args.OUTPUT_FORMAT
    )
    parser.parse(args.PATH)
