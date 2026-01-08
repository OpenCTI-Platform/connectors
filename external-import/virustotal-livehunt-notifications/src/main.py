"""Virustotal livehunt notifications main file."""

import traceback
from livehunt import VirustotalLivehuntNotifications

if __name__ == "__main__":
    try:
        vt_livehunt_notifications = VirustotalLivehuntNotifications()
        vt_livehunt_notifications.run()
    except Exception:
        traceback.print_exc()
        exit(1)
