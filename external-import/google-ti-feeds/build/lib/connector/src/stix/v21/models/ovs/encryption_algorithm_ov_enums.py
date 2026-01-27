"""The file contains the EncryptionAlgorithmOV enum class for OpenAI API encryption algorithms."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class EncryptionAlgorithmOV(BaseOV):
    """Encryption Algorithm Enumeration."""

    AES_256_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"
    MIME_TYPE_INDICATED = "mime-type-indicated"
