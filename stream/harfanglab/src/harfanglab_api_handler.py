##########################
# HARFANGLAB API HANDLER #
##########################

import requests
from pycti import OpenCTIConnectorHelper
# from stix2slider import slide_string
# from stix2slider.options import initialize_options

class HarfangLabApiHandler:
    def __init__(
            self,
            helper,
            url,
            login,
            password,
            ssl_verify=True,
            # indicators_scope,
            # ioc_list_name,
            # yara_list_name,
            # sigma_list_name,
    ):
        # Variables
        self.helper = helper
        self.url = url
        self.login = login
        self.password = password
        self.ssl_verify = ssl_verify
        # self.indicator_scope = indicators_scope
        # self.ioc_list_name = ioc_list_name
        # self.yara_list_name = yara_list_name
        # self.sigma_list_name = sigma_list_name
