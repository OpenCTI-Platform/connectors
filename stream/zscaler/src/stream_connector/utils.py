import logging
import time

import requests


def obfuscate_api_key(api_key, timestamp):
    """Obfuscate the API key with the provided timestamp."""
    high = timestamp[-6:]  # The last 6 digits of the timestamp
    low = str(int(high) >> 1)  # Right bitwise shift
    obfuscated_api_key = ""

    # Add zeros if necessary for low to be 6 characters long
    while len(low) < 6:
        low = "0" + low

    # Generate the "high" part
    for i in range(len(high)):
        obfuscated_api_key += api_key[int(high[i])]

    # Generate the "low" part
    for j in range(len(low)):
        obfuscated_api_key += api_key[int(low[j]) + 2]

    return obfuscated_api_key


def handle_rate_limit(request_func, retry_delay, *args, **kwargs):
    """Handle the rate limits of the Zscaler API."""
    while True:
        try:
            # Add a timeout to the request (10 seconds)
            kwargs["timeout"] = 10
            response = request_func(*args, **kwargs)
            if response.status_code == 429:  # HTTP code for too many requests
                logging.warning("Rate limit exceeded, retrying after delay...")
                time.sleep(retry_delay)
            else:
                return response
        except requests.Timeout:
            logging.error("Request timed out. Retrying...")
            time.sleep(retry_delay)
        except requests.RequestException as e:
            logging.error(f"Error making request: {e}")
            time.sleep(retry_delay)
