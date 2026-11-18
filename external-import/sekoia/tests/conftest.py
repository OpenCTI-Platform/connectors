import os
import sys

# The connector code imports its modules as "src.connector...".
# So the connector root folder must be on the path, not "src".
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
