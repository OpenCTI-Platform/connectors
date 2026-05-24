"""Fake REST API to test the ImportDocAI connector."""

import base64
import datetime
import json
import logging
from pathlib import Path
from typing import Awaitable, Callable

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

RESPONSES_DIR = Path(__file__).parent / "responses"


def generate_fake_certificate(
    common_name: str,
    validity_start: datetime.datetime | None,
    validity_duration: datetime.timedelta | None,
    base_64=True,
) -> bytes:
    """Generate a fake certificate.

    This is a tools to generate a self-signed certificate for testing purposes.

    Args:
        common_name (str): The common name for the certificate.
        validity_start (datetime.datetime | None): The start date of the certificate's validity. If None, it defaults to the current time.
        validity_duration (datetime.timedelta | None): The duration of the certificate's validity. If None, it defaults to 365 days.
        base_64 (bool): Whether to return the certificate in base64 format. Defaults to True.

    Returns:
        (bytes): The generated certificate in PEM format, optionally encoded in base64.

    Examples:
    >>> with open(Path(__file__).parent / "certificate_outdated.pem", "wb") as f:
    ...     cert_bytes=generate_fake_certificate("test", datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=10), datetime.timedelta(days=5))
    ...     f.write(cert_bytes)
    >>> with open(Path(__file__).parent / "certificate_trial.pem", "wb") as f:
    ...     cert_bytes=generate_fake_certificate("trial", None, None)
    ...     f.write(cert_bytes)
    >>> with open(Path(__file__).parent / "certificate_unauthorized.pem", "wb") as f:
    ...     cert_bytes=generate_fake_certificate("unauthorized", None, None)
    ...     f.write(cert_bytes)
    >>> with open(Path(__file__).parent / "certificate_valid.pem", "wb") as f:
    ...     cert_bytes=generate_fake_certificate("test", None, None)
    ...     f.write(cert_bytes)

    """
    # Generate an RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Define the subject (and issuer, since it's self-signed)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    if not validity_start:
        validity_start = datetime.datetime.now(datetime.timezone.utc)
    if not validity_duration:
        validity_duration = datetime.timedelta(days=365)
    # Create the certificate
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(validity_start)
        .not_valid_after(validity_start + validity_duration)
        .sign(private_key, hashes.SHA256())
    )

    pem_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    if base_64:  # encode in base64
        pem_bytes = base64.b64encode(pem_bytes)
    return pem_bytes


def _get_common_name(cert: x509.Certificate) -> str:
    """Get the common name from the certificate.

    Args:
        cert (x509.Certificate): The certificate to extract the common name from.

    Returns:
        str: The common name of the certificate.
    """
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


class V1AuthMiddleware(BaseHTTPMiddleware):
    """Define Middleware to authenticate requests."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response | JSONResponse:
        """Dispatch method for the middleware.

        This method checks for the presence of a certificate in the request headers and validates it.
        If the certificate is missing or invalid, it returns a JSON response with an error message:
        - 400 if the certificate is missing or invalid.
        - 403 if the certificate indicates a trial or unauthorized access (based on its common_name property).

        Args:
            request (Request): The incoming request.
            call_next (Callable[[Request], Awaitable[Response]]): The next middleware or endpoint to call.

        Returns:
            Response | JSONResponse: The response from the next middleware or endpoint, or a JSON response
            with an error message if authentication fails.
        """
        certificate_pem = request.headers.get("X-OpenCTI-Certificate")

        if not certificate_pem:
            with open(RESPONSES_DIR / "response_400_missing.json") as f:
                content = json.load(f)
            return JSONResponse(status_code=400, content=content)

        invalid_flag = False
        try:
            logger.error(f"Certificate: {certificate_pem}")
            cert = x509.load_pem_x509_certificate(
                base64.decodebytes(certificate_pem.encode("utf-8")), default_backend()
            )
            if cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
                # generate_fake_certificate("Test", datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=10), datetime.timedelta(days=5))
                invalid_flag = True
            else:
                common_name = _get_common_name(cert)
                if "trial" in common_name:
                    # generate_fake_certificate("trial")
                    with open(RESPONSES_DIR / "response_403_trial.json") as f:
                        content = json.load(f)
                    return JSONResponse(status_code=403, content=content)
                if "unauthorized" in common_name:
                    # generate_fake_certificate("unauthorized")
                    with open(RESPONSES_DIR / "response_403_unauthorized.json") as f:
                        content = json.load(f)
                    return JSONResponse(status_code=403, content=content)
        except Exception as e:
            logger.error(e, stack_info=True, stacklevel=2)
            invalid_flag = True

        if invalid_flag:
            with open(RESPONSES_DIR / "response_400_invalid.json") as f:
                content = json.load(f)
            return JSONResponse(status_code=400, content=content)

        return await call_next(request)


app = FastAPI()
app.add_middleware(V1AuthMiddleware)


@app.post("/stix", status_code=200)
async def extract_stix(file: UploadFile):
    """Fake endpoint to extract stix objects.

    Args:
        file (UploadFile): The file to process.

    Returns:
        JSONResponse: A response indicating the status of the operation.
    """
    with open(RESPONSES_DIR / "response_stix_200.json") as f:
        content = json.load(f)
    logger.warning(f"Received file: {file.filename}")
    return JSONResponse(status_code=200, content=content)
