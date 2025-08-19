import requests
import time
import re
import json
import logging

# Simple file logger setup
metrics_logger = logging.getLogger('metrics')
metrics_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler('sentinelone_metrics.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
metrics_logger.addHandler(file_handler)

class SentinelOneClient:
    def __init__(self, config, helper):

        self.config = config
        self.helper = helper



        self.session = requests.Session()
        headers = {
            "Authorization": f"APIToken {self.config.api_key}",
            "Content-Type": "application/json"
        }
        self.session.headers.update(headers)



    def create_indicator(self, data: dict):
        """
        Create IOC from OpenCTI to SentinelOne
        :param data: Data of IOC in dict
        :param event: Event in string or None
        :return: None
        """

        #1. filter out multi-element patterns on indicators and only acceptable S1 types
        pattern = data["pattern"]
        if not self._is_valid_pattern(pattern):
            
            # self.helper.connector_logger.info(
            #     f"[API] Skipping multi-element pattern indicator: {pattern}"
            # )
            return None

        #2. map the indicator
        indicator = self._map_indicator(data)
        if indicator is not None:
            #3. create indicator bundle
            payload = self._generate_indicator_payload(indicator)

            #4. push to s1
            #TODO: logic here might be a little weird we will see what we implement.
            #Maybe try and get the success status code so we can confirm and log its sent!
            response = self._push_indicator_payload(payload)
            #time.sleep(5)

        else:
            # self.helper.connector_logger.info(
            #     "[API] IOC cannot be created in SentinelOne"
            # )
            pass


        return None

    def _is_valid_pattern(self, pattern: str) -> bool:
        """        
        Supported SCO types:
        - file:hashes.MD5, file:hashes.SHA1, file:hashes.SHA256
        - domain-name:value
        - url:value  
        - ipv4-addr:value
        """


        SUPPORTED_SCO_PATTERNS = [
            r'file:hashes\.(MD5|SHA1|SHA256)\s*=',
            r'domain-name:value\s*=',
            r'url:value\s*=',
            r'ipv4-addr:value\s*='
        ]


        pattern = pattern.strip()
        
        # check multi-element / more complex cases within single
        if re.search(r'\b(AND|OR|REPEATS|WITHIN|FOLLOWS)\b', pattern, re.IGNORECASE):
            return False
        
        #now ensure single-element pattern
        single_element_pattern = r'^\s*\[[^\[\]]+\]\s*$'
        if not re.match(single_element_pattern, pattern):
            return False
            
        # now ensure only valid s1 types..
        for sco_pattern in SUPPORTED_SCO_PATTERNS:
            if re.search(sco_pattern, pattern, re.IGNORECASE):
                return True
                
        return False




    #TODO: make this much more efficient, I think all we need to do is remove 
    #external refs from the original...
    #TODO: things like indicator types might be required, I believe... IF SO, RETURN NONE IF THAT NO PRESENT
    @staticmethod
    def _map_indicator(data: dict) -> dict | None:
        indicator = {
            "type":"indicator",
            "spec_version": "2.1",
            "id":data.get("id"),
            "created":data.get("created"),
            "modified": data.get("modified"),
            "indicator_types":["malicious-activity"],
            "pattern": data.get("pattern"),
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "name":data.get("name"),
            "description": data.get("description",""),
            "valid_from": data.get("valid_from"),
            "valid_until": data.get("valid_until"),
            "confidence": data.get("confidence"),
            "revoked": "false",
            "lang": data.get("lang"),
            "labels": data.get("labels",[]),
        }
        return indicator


    def _generate_indicator_payload(self, indicator:dict) -> dict:
        """
        """
        payload = {
            "bundle": {
                "objects": [indicator]
            },
            "filter": {
                "tenant": "false"
            }
        }
        
        if self.config.account_id is not None:
            payload["filter"]["accountIds"] = [self.config.account_id]
        if self.config.group_id is not None:
            payload["filter"]["groupIds"] = [self.config.group_id]
        if self.config.site_id is not None:
            payload["filter"]["siteIds"] = [self.config.site_ids]

        return payload


    def _push_indicator_payload(self, payload: dict):
        """
        """
        #TODO: move ts
        IOC_ENDPOINT_URL = "/web/api/v2.1/threat-intelligence/iocs/stix"
        TIMEOUT = 5
        TOTAL = 3
        BACKOFF_FACTOR = 5
            
        url = self.config.api_url + IOC_ENDPOINT_URL


        for attempt in range(TOTAL):
            
            try:

                #print(json.dumps(payload, indent=4))
                #print(self.session.headers)

                response = self.session.post(url, json=payload, timeout=TIMEOUT)
                
                #200 iff all is good, thus log it 
                if response.status_code  == 200:
                    metrics_logger.info("IOC_SUCCESS")
                    self.helper.connector_logger.info("sent successfully to s1")
                    return response
                
                # apply backoff for code 429
                elif response.status_code == 429:
                    if attempt < TOTAL - 1:  # Don't sleep on last attempt
                        delay = self.backoff_delay(BACKOFF_FACTOR, attempt + 1)
                        metrics_logger.info(f"RATE_LIMITED delay_seconds={delay}")
                        self.helper.connector_logger.warning(f"Rate limited, retrying in {delay} seconds")
                        time.sleep(delay)
                        continue
                
                #raise for status to handle all other cases: 400 (format), 401 (auth) and any others
                response.raise_for_status()

            except requests.RequestException as e:
                self.helper.connector_logger.error(f"request exception: {e}")

        return None


    #TODO: change rate limit to 5,10,15 ...  Although in practice ive never seen it go over 15.
    #We must also ensure it never goes ove ~ 35, as 45 seconds with no heartbeat will cause the connnector
    #to stop .... although does that even matter cause it legit just restarts..?
    @staticmethod
    def backoff_delay(backoff_factor: float, attempts: int) -> float:
        """
        Calculate the delay for a retry attempt using an exponential backoff algorithm.

        :param backoff_factor: float, the base delay time in seconds. This value is
                               multiplied by the exponential factor to determine the delay.
        :param attempts: int, the number of retry attempts already made (1-based).
        :return: float, the calculated delay time in seconds.

        Example:
            For `backoff_factor` = 0.5 and `attempts` = 3, the delay is calculated as:
            delay = 0.5 * (2 ** (3 - 1)) = 0.5 * 4 = 2.0 seconds.
        """
        delay = backoff_factor * (2 ** (attempts - 1))
        return delay