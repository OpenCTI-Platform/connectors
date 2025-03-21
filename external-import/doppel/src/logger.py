import os
import logging
import yaml

# Load configuration from config.yaml
with open("config/config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Ensure the log directory exists
log_file = config["logging"]["log_file"]
log_dir = os.path.dirname(log_file)

if not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)

# Setup logging
logging.basicConfig(
    filename=log_file,
    level=getattr(logging, config["logging"]["log_level"].upper(), logging.INFO),
    format=config["logging"]["log_format"]
)

# Function to get a logger
def get_logger(name=None):  # Accepts a logger name
    return logging.getLogger(name)

logger = get_logger(__name__)
logger.info("Logging setup complete!")
