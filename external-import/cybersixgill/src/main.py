"""OpenCTI Cybersixgill connector main module."""

from cybersixgill import Cybersixgill

if __name__ == "__main__":
    connector = Cybersixgill()
    connector.run()
