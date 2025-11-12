"""The module contains the Windows PE Binary Type OV Enums."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class WindowsPEBinaryTypeOV(BaseOV):
    """Windows PE Binary Type Enumeration."""

    DLL = "dll"
    EXE = "exe"
    SYS = "sys"
