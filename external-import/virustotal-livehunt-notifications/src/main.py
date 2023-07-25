"""Virustotal livehunt notifications main file."""
from livehunt import VirustotalLivehuntNotifications

if __name__ == "__main__":
    connector = VirustotalLivehuntNotifications()
    connector.run()
