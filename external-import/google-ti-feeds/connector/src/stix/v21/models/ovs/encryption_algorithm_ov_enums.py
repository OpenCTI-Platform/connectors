"""The file contains the EncryptionAlgorithmOV enum class for OpenAI API encryption algorithms."""

from enum import Enum


class EncryptionAlgorithmOV(str, Enum):
    """Encryption Algorithm Enumeration."""

    AES_256_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"
    MIME_TYPE_INDICATED = "mime-type-indicated"
