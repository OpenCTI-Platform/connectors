"""The module defines the Course of Action Type Enumeration."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class CourseOfActionTypeOV(BaseOV):
    """Course of Action Type Enumeration."""

    TEXTUAL_PLAIN = "textual:text/plain"
    TEXTUAL_HTML = "textual:text/html"
    TEXTUAL_MD = "textual:text/md"
    TEXTUAL_PDF = "textual:pdf"
