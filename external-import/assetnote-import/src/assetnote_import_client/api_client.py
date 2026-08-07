import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl, SecretStr

# records per page for the top-level assets/exposures queries
PAGE_SIZE = 25
# the max amount of interactions per exposure to retrieve (usually only ever 1)
EXPOSURE_INTERACTION_LIMIT = 20


class AssetnoteImportClient:

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: HttpUrl, api_key: SecretStr
    ):
        self.helper = helper
        self.graphql_url = f"{str(base_url).rstrip('/')}/api/v2/graphql"
        self.page_size = PAGE_SIZE
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-ASSETNOTE-API-KEY": api_key.get_secret_value(),
                "Content-Type": "application/json",
            }
        )

    def _graphql_query(
        self, query: str, root: str, since: str, page: int
    ) -> list[dict]:
        variables = {"page": page, "since": since}
        self.helper.connector_logger.debug(
            f"[API] POST to {self.graphql_url} with variables: {variables}"
        )
        response = self.session.post(
            self.graphql_url,
            json={"query": query, "variables": variables},
            timeout=60,
        )
        response.raise_for_status()

        try:
            body = response.json()
        except ValueError:
            self.helper.connector_logger.error("[API] Response was not JSON")
            raise

        # raise an error for any non-request GraphQL errors
        if body.get("errors"):
            self.helper.connector_logger.error(
                f"[API] GraphQL errors: {body['errors']}"
            )
            raise RuntimeError(f"Assetnote GraphQL errors: {body['errors']}")

        # unwrap each GraphQL edge to the actual node
        edges = body["data"][root]["edges"]
        return [edge["node"] for edge in edges]

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
