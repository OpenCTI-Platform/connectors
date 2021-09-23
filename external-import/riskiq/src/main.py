# -*- coding: utf-8 -*-
"""RiskIQ connector main file."""

from riskiq import RiskIQConnector


if __name__ == "__main__":
    connector = RiskIQConnector()
    connector.run()
