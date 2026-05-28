import re

import requests


class GoogleDNSClient:
    def __init__(self):
        self.base_url = "https://dns.google.com/resolve"
        self.rr_types = {
            "A": 1,
            "CNAME": 5,
            "MX": 15,
            "NS": 2,
            "TXT": 16,
        }

    def _remove_dots(self, answers) -> list:
        results = [answer.rstrip(".") for answer in answers]
        return results

    def query(self, host, query_type) -> list:
        params = {"name": host, "type": query_type}
        query_type_id = self.rr_types.get(query_type, 1)

        try:
            response = requests.get(self.base_url, params)
            body = response.json()
        except Exception as e:
            print(e)
            return []

        if "Answer" in body.keys() and any(body["Answer"]):
            answers = body["Answer"]
            data = []

            for answer in answers:
                if answer["type"] == query_type_id:
                    data.append(answer["data"])
        else:
            data = []

        return data

    def a(self, host) -> list:
        data = self.query(host, "A")
        return data

    def cname(self, host) -> list:
        data = self.query(host, "CNAME")
        processed = self._remove_dots(data)
        return processed

    def mx(self, host) -> list:
        data = self.query(host, "MX")
        no_priority = [re.sub(r"(\d+)\s", "", answer) for answer in data]
        no_dots = self._remove_dots(no_priority)
        return no_dots

    def ns(self, host) -> list:
        data = self.query(host, "NS")
        processed = self._remove_dots(data)
        return processed

    def txt(self, host) -> list:
        data = self.query(host, "TXT")
        processed = self._remove_dots(data)
        return processed
