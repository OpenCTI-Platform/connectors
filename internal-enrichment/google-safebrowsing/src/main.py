from lib.SafeBrowsing import SafeBrowsingConnector


class CustomConnector(SafeBrowsingConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standarised way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()

    def _process_message(self, data):

        self.helper.log_info("Not Implemented")
        raise NotImplementedError("Method not implemented")


if __name__ == "__main__":
    connector = CustomConnector()
    connector.start()
