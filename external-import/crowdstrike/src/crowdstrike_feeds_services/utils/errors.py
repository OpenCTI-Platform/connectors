class CrowdStrikeAPIError(Exception):
    def __init__(self, message: str, status_code: int):
        super().__init__(f"CrowdStrike API Error [{status_code}]: {message}")