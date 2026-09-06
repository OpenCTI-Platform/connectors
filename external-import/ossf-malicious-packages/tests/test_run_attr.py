from ossf_malicious_packages import OSSFMaliciousPackagesConnector

print("Has run:", hasattr(OSSFMaliciousPackagesConnector, "run"))
print("Dir:", [a for a in dir(OSSFMaliciousPackagesConnector) if a.startswith("r")])
