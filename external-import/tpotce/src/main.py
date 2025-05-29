import traceback
import sys

from external_import_connector import CustomConnector

if __name__ == "__main__":
    # Entry point of the script
    #
    # - traceback.print_exc(): This function prints the traceback of the exception to stderr.
    #   The traceback includes information about the point in the program where the exception occurred,
    #   which is very useful for debugging purposes.
    # - sys.exit(1): An effective way to terminate a Python program when an error is encountered.
    #   It signals to the OS and any calling processes that the program did not complete successfully.
    try:
        connector = CustomConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
