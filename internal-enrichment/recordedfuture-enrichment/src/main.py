"""
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Recorded Future makes no       #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Recorded Future shall not be liable for, and you assume all risk of          #
# using the foregoing.                                                         #
################################################################################
"""

import traceback

from pycti import OpenCTIConnectorHelper
from rflib import ConnectorConfig, RFEnrichmentConnector

if __name__ == "__main__":
    """
    Entry point of the script

    - traceback.print_exc(): This function prints the traceback of the exception to the standard error (stderr).
    The traceback includes information about the point in the program where the exception occurred,
    which is very useful for debugging purposes.
    - exit(1): effective way to terminate a Python program when an error is encountered.
    It signals to the operating system and any calling processes that the program did not complete successfully.
    """
    try:
        config = ConnectorConfig()
        helper = OpenCTIConnectorHelper(
            config=config.model_dump_pycti(),
            playbook_compatible=True,
        )

        connector = RFEnrichmentConnector(config, helper)
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
