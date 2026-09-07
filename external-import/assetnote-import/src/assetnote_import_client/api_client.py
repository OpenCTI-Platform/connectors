from connectors_sdk import BaseClientApi, RateLimit
from pydantic import HttpUrl, SecretStr

# records per page for the top-level assets/exposures queries
PAGE_SIZE = 25
# the max amount of interactions per exposure to retrieve (usually only ever 1)
EXPOSURE_INTERACTION_LIMIT = 20


class AssetnoteImportClient(BaseClientApi):

    def __init__(self, base_url: HttpUrl, api_key: SecretStr):
        self._api_key = api_key
        self.page_size = PAGE_SIZE
        super().__init__(
            str(base_url),
            max_retries=3,
            rate_limit=RateLimit(100, "minute"),
            raise_on_limit_exceeded=False,
        )

    @property
    def session_headers(self) -> dict[str, str]:
        return {"X-ASSETNOTE-API-KEY": self._api_key.get_secret_value()}

    def _graphql_query(
        self, query: str, root: str, since: str, page: int
    ) -> list[dict]:
        body = self._post(
            "/api/v2/graphql",
            json={"query": query, "variables": {"page": page, "since": since}},
        )
        if body.get("errors"):
            raise RuntimeError(f"Assetnote GraphQL errors: {body['errors']}")
        return [edge["node"] for edge in body["data"][root]["edges"]]

    def get_exposures(self, since: str, page: int = 1) -> list[dict]:
        EXPOSURES_QUERY = f"""
        query Exposures($page: Int!, $since: JSONScalar!) {{
            exposures(
            s: [{{ field: "id", dir: ASC }}]
            f: [{{ field: "lastUpdated", op: GT, value: $since }}]
            count: {PAGE_SIZE}
            page: $page
            ) {{
            edges {{
                node {{
                ... on BaseExposure {{
                    id
                    exposureType
                    created
                    triageState
                    severityString
                    signature {{
                    ... on BaseExposureSignature {{
                        name
                        cve
                        signatureClass
                        description
                        recommendations
                    }}
                    }}
                    asset {{
                    ... on BaseAsset {{
                        id
                        assetType
                        host
                        platformUrl
                        onlineLastUpdated
                    }}
                    }}
                    knownExploitation {{
                    product
                    vendorProject
                    }}
                    exposureData(count: {EXPOSURE_INTERACTION_LIMIT}, page: 1) {{
                    edges {{
                        node {{
                        ... on HTTPExposureData {{
                            created
                            request
                            response
                        }}
                        ... on TPPEExposureData {{
                            created
                            repository
                            repositoryOwner
                            commitHash
                            patch
                        }}
                        }}
                    }}
                    }}
                }}
                }}
            }}
            }}
        }}
        """
        return self._graphql_query(EXPOSURES_QUERY, "exposures", since, page)

    def get_assets(self, since: str, page: int = 1) -> list[dict]:
        ASSETS_QUERY = f"""
        query Assets($page: Int!, $since: JSONScalar!) {{
            assets(
            s: [{{ field: "id", dir: ASC }}]
            f: [
                {{ field: "verifiedStatus", op: EQ, value: true }}
                {{ field: "lastUpdated", op: GT, value: $since }}
            ]
            count: {PAGE_SIZE}
            page: $page
            ) {{
            edges {{
                node {{     
                ... on BaseAsset {{
                    id                
                    host
                    assetType
                    created
                    onlineLastUpdated
                    platformUrl
                }}
                }}
            }}
            }}
        }}
        """
        return self._graphql_query(ASSETS_QUERY, "assets", since, page)
