from __future__ import annotations

import datetime
import ipaddress
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.config import settings

logger = logging.getLogger(__name__)

# Long enough not to be a recurring chore, short enough to still be a rotation. Public
# CAs cap at 398 days; a self-signed cert nobody validates has no such constraint, but
# a certificate that never expires is one nobody ever revisits.
_VALIDITY_DAYS = 825


def _write_private(path: Path, data: bytes) -> None:
    # Opened with 0600 from the start rather than chmod'd after: between creating a key
    # world-readable and fixing it there is a window, and this one is avoidable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def generate_self_signed(cert_path: Path, key_path: Path, hostname: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)

    alt_names: list[x509.GeneralName] = [x509.DNSName(hostname)]
    if hostname != "localhost":
        alt_names.append(x509.DNSName("localhost"))
    alt_names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=_VALIDITY_DAYS))
        # Without a SAN, everything modern rejects the certificate outright — CN alone
        # has not been accepted for years.
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    _write_private(
        key_path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def ensure_certificate() -> tuple[Path, Path]:
    """Resolve the cert/key to serve with, generating a self-signed pair if asked.

    Returns the paths uvicorn should use. Raises with an actionable message rather than
    starting insecurely if TLS was requested and can't be provided — silently falling
    back to plaintext is the one behaviour nobody wants from this function.
    """
    cert_path = Path(settings.tls_cert_path)
    key_path = Path(settings.tls_key_path)

    if settings.tls_mode == "provided":
        missing = [str(p) for p in (cert_path, key_path) if not p.is_file()]
        if missing:
            raise FileNotFoundError(
                f"TLS_MODE=provided but these files are missing: {', '.join(missing)}. "
                "Mount them into the container or switch to TLS_MODE=self-signed."
            )
        logger.info("using provided TLS certificate", extra={"cert_path": str(cert_path)})
        return cert_path, key_path

    # self-signed: reuse what's on the data volume. Regenerating every boot would mean
    # a fresh fingerprint on every restart, which breaks any pinning and retrains
    # operators to click through certificate warnings.
    if cert_path.is_file() and key_path.is_file():
        logger.info("reusing existing self-signed certificate", extra={"cert_path": str(cert_path)})
        return cert_path, key_path

    generate_self_signed(cert_path, key_path, settings.tls_hostname)
    logger.warning(
        "generated a self-signed TLS certificate — browsers and any client that "
        "validates chains will not trust it. Suitable for a load balancer or reverse "
        "proxy terminating public TLS in front; use TLS_MODE=provided for anything "
        "that must validate.",
        extra={"cert_path": str(cert_path), "hostname": settings.tls_hostname},
    )
    return cert_path, key_path
