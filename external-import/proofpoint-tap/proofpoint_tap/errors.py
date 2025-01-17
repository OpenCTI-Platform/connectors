"""Offer python errors and tools."""


class ProofpointAPIError(Exception):
    """Generic Proofpoint API error."""


class ProofPointAPIRequestParamsError(ProofpointAPIError):
    """Proofpoint API error with request parameters."""


class ProofpointAPI404Error(ProofpointAPIError):
    """Proofpoint API error with 400 status code."""


class ProofpointAPI404NoReasonError(ProofpointAPI404Error):
    """Proofpoint API error with 404 status code and no reason.

    Notes:
        * See client_api.v2.common.BaseClient._process_raw_response implementation for details.
        * See client_api.v2.campaign.CampaignClient.fetch_campaign implementation for technical decision log.

    """


class ProofpointAPI429Error(ProofpointAPIError):
    """Proofpoint API error with 429 status code.

    Used to handle rate limiting errors.
    """


class ProofpointAPIInvalidResponseError(ProofpointAPIError):
    """Proofpoint API error with an invalid response."""
