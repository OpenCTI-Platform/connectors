import os
import sys
import csv
import json
import traceback

from stix.core import STIXPackage
from mixbox.idgen import set_id_namespace
from mixbox.namespaces import Namespace
from stix.indicator import Indicator
from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.common import Hash
from cybox.objects.uri_object import URI
from cybox.objects.win_registry_key_object import WinRegistryKey

# from cybox.objects.domain_name_object import DomainName
OUTPUT_FORMATS = ("csv", "json", "yara", "autofocus", "stix")

# NAMESPACE = {"http://www.cert.gov.uk" : "certuk"}
NAMESPACE = Namespace("http://www.cert.gov.uk", "certuk")
set_id_namespace(NAMESPACE)

stix_package = STIXPackage()
add_ind_list = []

ind_ip = Indicator()
ind_ip.add_indicator_type("IP Watchlist")

ind_file = Indicator()
ind_file.add_indicator_type("File Hash Watchlist")

ind_url = Indicator()
ind_url.add_indicator_type("URL Watchlist")

ind_domain = Indicator()
ind_domain.add_indicator_type("Domain Watchlist")

ind_email = Indicator()
ind_email.add_indicator_type("Malicious E-mail")

ind_registrykey = Indicator()
ind_registrykey.add_indicator_type("Host Characteristics")

ind_dict = {
    "IP": ind_ip,
    "HASH": ind_file,
    "URL": ind_url,
    "Host": ind_domain,
    "Email": ind_email,
    "Registry": ind_registrykey,
    # filename to be added,
    # filepath to be added,
    # CVE to be added
}


def getHandler(output_format):
    output_format = output_format.lower()
    if output_format not in OUTPUT_FORMATS:
        print("[WARNING] Invalid output format specified.. using CSV")
        output_format = "csv"

    handler_format = "OutputHandler_" + output_format
    handler_class = getattr(sys.modules[__name__], handler_format)

    return handler_class()


class OutputHandler(object):
    def print_match(self, fpath, page, name, match, last=False):
        pass

    def print_header(self, fpath):
        pass

    def print_footer(self, fpath):
        pass

    def print_error(self, fpath, exception):
        traceback.print_exc()
        print("[ERROR] %s" % (exception))


class OutputHandler_stix(OutputHandler):
    # Add all entities to stix indicator files (note: must collate objects before printing - unlike other formats!)
    # - It is noted that this isn't a very stix-ish way of doing things
    # - Expect an analyst to go through the output and re-link associated iocs where necessary
    # - eg: Email addresses are creted as a list of email address objects, should be re-built to email objects if other relevant indicators (such as file attachements) exist
    global stix_package
    global ind_dict
    global add_ind_list

    def print_match(self, fpath, page, name, match):

        # Resolve all hashes to single HASH reference to avoid repetition
        if name == "MD5" or name == "SHA1" or name == "SHA256":
            name = "HASH"

        if name in ind_dict:
            indicator = ind_dict[name]
            add_ind_list.append(name)
            indicator.title = fpath
            # ===========
            # Add new object handlers here:
            if name == "IP":
                new_obj = Address(address_value=match, category=Address.CAT_IPV4)
            elif name == "HASH":
                new_obj = File()
                new_obj.add_hash(Hash(match))

            elif name == "URL":
                new_obj = URI(type_=URI.TYPE_URL, value=match)

            elif name == "Host":
                new_obj = URI(type_=URI.TYPE_DOMAIN, value=match)

            elif name == "Email":
                new_obj = Address(
                    address_value=match, category=Address.CAT_EMAIL
                )  ## Not sure if this is right - should this be using the email_message_object?

            elif name == "Registry":
                new_obj = WinRegistryKey(values=match)
            # ===========

            new_obs = Observable(new_obj)
            new_obs.title = "Page Ref: " + str(page)
            indicator.add_observable(new_obs)

    def print_footer(self, fpath):
        global add_ind_list
        for key in ind_dict:
            if key in add_ind_list:
                stix_package.add_indicator(ind_dict[key])
        print(stix_package.to_xml())


class OutputHandler_csv(OutputHandler):
    def __init__(self):
        self.csv_writer = csv.writer(sys.stdout, delimiter="\t")

    def print_match(self, fpath, page, name, match):
        self.csv_writer.writerow((fpath, page, name, match))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((fpath, "0", "error", exception))


class OutputHandler_json(OutputHandler):
    def print_match(self, fpath, page, name, match):
        data = {"type": name, "match": match}
        return data

    def print_error(self, fpath, exception):
        data = {
            "path": fpath,
            "file": os.path.basename(fpath),
            "type": "error",
            "exception": exception,
        }
        print(data)
        try:
            dumped = json.dumps(data)
            print(dumped)
        except:
            print(data)


class OutputHandler_yara(OutputHandler):
    def __init__(self):
        self.rule_enc = "".join(
            chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else "_"
            for c in range(256)
        )

    def print_match(self, fpath, page, name, match):
        if name in self.cnt:
            self.cnt[name] += 1
        else:
            self.cnt[name] = 1

        string_id = "$%s%d" % (name, self.cnt[name])
        self.sids.append(string_id)
        string_value = match.replace("\\", "\\\\")
        print('\t\t%s = "%s"' % (string_id, string_value))

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(
            self.rule_enc
        )

        print("rule %s" % (rule_name))
        print("{")
        print("\tstrings:")

        self.cnt = {}
        self.sids = []

    def print_footer(self, fpath):
        cond = " or ".join(self.sids)

        print("\tcondition:")
        print("\t\t" + cond)
        print("}")


class OutputHandler_autofocus(OutputHandler):
    def __init__(self):
        self.rule_enc = "".join(
            chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else "_"
            for c in range(256)
        )

    def print_match(self, fpath, page, name, match):
        string_value = match.replace("hxxp", "http").replace("\\", "\\\\")

        if name == "MD5":
            auto_focus_query = (
                '{"field":"sample.md5","operator":"is","value":"%s"},' % (string_value)
            )
        elif name == "SHA1":
            auto_focus_query = (
                '{"field":"sample.sha1","operator":"is","value":"%s"},' % (string_value)
            )
        elif name == "SHA256":
            auto_focus_query = (
                '{"field":"sample.sha256","operator":"is","value":"%s"},'
                % (string_value)
            )
        elif name == "URL":
            auto_focus_query = (
                '{"field":"sample.tasks.connection","operator":"contains","value":"%s"},'
                % (string_value)
            )
        elif name == "Host":
            auto_focus_query = (
                '{"field":"sample.tasks.dns","operator":"contains","value":"%s"},'
                % (string_value)
            )
        elif name == "Registry":
            # auto_focus_query = '{"field":"sample.tasks.registry","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filepath":
            # auto_focus_query = '{"field":"sample.tasks.file","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Filename":
            # auto_focus_query = '{"field":"alias.filename","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "Email":
            # auto_focus_query = '{"field":"alias.email","operator":"is","value":\"%s\"},' % (string_value)
            return
        elif name == "IP":
            auto_focus_query = (
                '{"field":"sample.tasks.connection","operator":"contains","value":"%s"},'
                % (string_value)
            )
        elif name == "CVE":
            return
        print(auto_focus_query)

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(
            self.rule_enc
        )

        print("AutoFocus Search for: %s" % (rule_name))
        print('{"operator":"Any","children":[')

    def print_footer(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(
            self.rule_enc
        )
        print(
            '{"field":"sample.tag","operator":"is in the list","value":["%s"]}]}'
            % (rule_name)
        )
