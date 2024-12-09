import logging

from stream_connector import ZscalerConnector

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        # Initialize the connector with the configuration file config.yml
        connector = ZscalerConnector("/opt/opencti-connector-zscaler/config.yml")
        connector.authenticate_with_zscaler()  # Authenticate with Zscaler
        connector.start()  # Start listening for OpenCTI events
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
