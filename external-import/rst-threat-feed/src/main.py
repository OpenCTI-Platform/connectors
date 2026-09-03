import sys
import time
import traceback

from pycti import OpenCTIConnectorHelper
from pycti.entities.opencti_user import User

from connector.connector import RSTThreatFeed
from connector.settings import ConnectorSettings

__all__ = ["RSTThreatFeed"]


def _patch_pycti_create_token_response() -> None:
    """
    pycti 7.260817.0 auto-create service account assigns create_token()'s return
    value into user['api_tokens'], then looks up item['name'] / item['id'].

    userAdminTokenAdd returns {token_id, plaintext_token, expires_at} — no name/id —
    which raises KeyError and aborts helper init. Normalize the response shape.
    """
    if getattr(User.create_token, "_rst_threat_feed_patched", False):
        return

    original = User.create_token

    def create_token(self, **kwargs):
        token = original(self, **kwargs)
        if not isinstance(token, dict):
            return token
        if "name" not in token and kwargs.get("token_name"):
            token["name"] = kwargs["token_name"]
        if "id" not in token and token.get("token_id"):
            token["id"] = token["token_id"]
        return token

    create_token._rst_threat_feed_patched = True
    User.create_token = create_token  


if __name__ == "__main__":
    try:
        _patch_pycti_create_token_response()
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
        connector = RSTThreatFeed(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)
