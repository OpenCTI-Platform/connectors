"""The module contains the PlatformOV enum class for OpenCTI platforms."""

from enum import Enum


class PlatformOV(str, Enum):
    """Platform Open Vocabulary.

    See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts#L797
    """

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"
