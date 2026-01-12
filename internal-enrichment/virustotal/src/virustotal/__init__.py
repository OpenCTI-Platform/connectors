# -*- coding: utf-8 -*-
"""VirusTotal connector module."""
from .models.configs.config_loader import ConfigLoader
from .virustotal import VirusTotalConnector

__all__ = ["VirusTotalConnector", "ConfigLoader"]
