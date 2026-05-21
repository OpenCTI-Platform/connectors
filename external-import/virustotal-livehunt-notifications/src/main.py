"""Virustotal livehunt notifications main file."""

import traceback

from livehunt import ConnectorSettings, VirustotalLivehuntNotifications
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        vt_livehunt_notifications = VirustotalLivehuntNotifications(
            config=settings,
            helper=helper,
        )
        vt_livehunt_notifications.run()
    except Exception:
        traceback.print_exc()
        exit(1)
