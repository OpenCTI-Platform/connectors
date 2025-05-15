"""The module defines the Course of Action Type Enumeration."""

from enum import Enum


class CourseOfActionTypeOV(str, Enum):
    """Course of Action Type Enumeration."""

    TEXTUAL_PLAIN = "textual:text/plain"
    TEXTUAL_HTML = "textual:text/html"
    TEXTUAL_MD = "textual:text/md"
    TEXTUAL_PDF = "textual:pdf"
