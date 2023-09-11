import re


class RegexExtractor:
    def extract_ips(text):
        pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        ips = re.findall(pattern, text)
        return list(set(ips))

    def extract_urls(text):
        pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w.-]*"
        urls = re.findall(pattern, text)
        # if the last character is a dot, remove it
        urls = [url[:-1] if url[-1] == "." else url for url in urls]
        return list(set(urls))

    def extract_emails(text):
        pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        emails = re.findall(pattern, text)
        return list(set(emails))

    def extract_sha_256s(text):
        pattern = r"[A-Fa-f0-9]{64}"
        sha_256s = re.findall(pattern, text)
        return list(set(sha_256s))

    def extract_sha_1s(text):
        pattern = r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"
        sha_1s = re.findall(pattern, text)
        return list(set(sha_1s))

    def extract_md5s(text):
        pattern = r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"
        md5s = re.findall(pattern, text)
        return list(set(md5s))

    def extract_mitre_attack(text):
        pattern = r"(T[0-9]{4}(\.\d\d\d)?)"
        mitre_attacks = re.findall(pattern, text)
        # return [mitre_attack[0] for mitre_attack in mitre_attacks]
        return list(set([mitre_attack[0] for mitre_attack in mitre_attacks]))

    def extract_cve(text):
        pattern = r"CVE-[0-9]{4}-[0-9]{4,7}"
        cves = re.findall(pattern, text)
        return list(set(cves))

    def extract_cwe(text):
        pattern = r"CWE-[0-9]{1,4}"
        cwes = re.findall(pattern, text)
        return list(set(cwes))

    def extract_files(text):
        pattern = r"([a-zA-Z0-9_\\.\-\(\):]+\.(exe|dll|py|js|docx|doc|xls|xlsx|ppt|pptx|pdf|txt|rtf|zip|rar|tar|gz|7z|bin|sh|php|html|htm|xml|json|csv|tsv|ps1|bat|vbs|java|class|apk|ipa|iso|i))"
        files = re.findall(pattern, text)
        return list(set([file[0] for file in files]))

    def extract_all(text : str) -> dict:
        return {
            "ips": RegexExtractor.extract_ips(text),
            "urls": RegexExtractor.extract_urls(text),
            "emails": RegexExtractor.extract_emails(text),
            "sha_256s": RegexExtractor.extract_sha_256s(text),
            "sha_1s": RegexExtractor.extract_sha_1s(text),
            "md5s": RegexExtractor.extract_md5s(text),
            "mitre_attacks": RegexExtractor.extract_mitre_attack(text),
            "cves": RegexExtractor.extract_cve(text),
            "cwes": RegexExtractor.extract_cwe(text),
            "files": RegexExtractor.extract_files(text)
        }