class ConnectorTemplate:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.splunk_client = None

    def set_splunk_client(self, client):
        self.splunk_client = client

    def run(self):
        """Continuously fetch OpenCTI indicators and forward them to Splunk."""
        while True:
            try:
                indicators = self.helper.fetch_new_indicators()
                for indicator in indicators:
                    event = process_indicator(indicator)
                    if event:
                        self.splunk_client.send_event(event)
            except Exception as e:
                # Log error but continue loop
                self.helper.logger.error(f"Error in connector loop: {e}")
            # Sleep according to config
            import time
            time.sleep(self.config.get('poll_interval', 30))
