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

# Ruling 5 on #133: renew at the earlier of half the certificate's own validity period
# or six months — never at half alone (dead weight on today's 825-day span: 412 days
# would win every time) and never at six months alone (absurd on a short mounted cert:
# a 90-day certificate would be "due" before it was even issued). `min` is the only
# reading under which both clauses ever do any work, and it degrades cleanly in both
# directions. Measured off the certificate's own not_valid_before/not_valid_after —
# never off _VALIDITY_DAYS itself, so editing that constant later does not retroactively
# reclassify a certificate already sitting on an operator's data volume.
_RENEWAL_WINDOW = datetime.timedelta(days=183)


def _replace_atomically(path: Path, data: bytes, *, mode: int) -> None:
    """Write `data` to a temp file beside `path` and atomically rename it into place.

    The bug this closes (#133's spike, folded into #186): the original `_write_private`
    wrote the cert then the key as two independent calls, so a crash between them left
    a parsable fresh cert beside a stale key — one-shot before renewal existed, and
    recurring every ~183 days now that it does. `os.replace` is a single rename syscall
    on the same filesystem, so a reader never observes a partially written file for
    *either* one. Cert and key stay two separate files — `TLS_CERT_PATH` /
    `TLS_KEY_PATH` are independent settings, and `TLS_MODE=provided` operators mount
    them separately — so this narrows the crash window between the two files from
    "however long key generation and two full writes take" down to the gap between two
    adjacent rename() calls with no I/O in between. Not a perfect guarantee under a
    hard kill landing in that exact gap; the only way to close that entirely would be
    collapsing both into one file, which is a bigger change than this bug earns.
    """
    tmp_path = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _renewal_due(cert_path: Path) -> bool:
    """True once `cert_path` is inside its own renewal window (ruling 5 on #133)."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    span = cert.not_valid_after_utc - cert.not_valid_before_utc
    renew_at = cert.not_valid_before_utc + min(span / 2, _RENEWAL_WINDOW)
    return datetime.datetime.now(datetime.timezone.utc) >= renew_at


def _warn_if_provided_cert_aging(cert_path: Path) -> None:
    """`TLS_MODE=provided`'s half of ruling 5: never regenerate, overwrite, or delete a
    certificate the operator mounted — we cannot mint someone else's certificate. Warn
    once it is past its own renewal point, and log louder once it has actually expired,
    since a browser or API client validating the chain will now refuse it outright.
    """
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = cert.not_valid_after_utc

    if now >= not_after:
        logger.error(
            "the provided TLS certificate has EXPIRED — any client that validates the "
            "chain will now refuse it. This process will never regenerate, overwrite, "
            "or delete a certificate mounted under TLS_MODE=provided; replace %s with "
            "a current certificate.",
            cert_path,
            extra={"cert_path": str(cert_path), "not_valid_after": not_after.isoformat()},
        )
    elif _renewal_due(cert_path):
        logger.warning(
            "the provided TLS certificate is past the midpoint of its validity window "
            "and due for renewal by whoever issues it. This process will never "
            "regenerate a certificate mounted under TLS_MODE=provided.",
            extra={"cert_path": str(cert_path), "not_valid_after": not_after.isoformat()},
        )


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

    # Both blobs are fully built in memory before any file I/O begins; each is then
    # written to a temp path beside its target and atomically renamed into place — see
    # _replace_atomically for why that matters once this path is called on a renewal
    # and not just on first boot.
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Opened with 0600 from the start rather than chmod'd after: between creating a key
    # world-readable and fixing it there is a window, and this one is avoidable.
    _replace_atomically(key_path, key_bytes, mode=0o600)
    _replace_atomically(cert_path, certificate.public_bytes(serialization.Encoding.PEM), mode=0o644)


def ensure_certificate() -> tuple[Path, Path]:
    """Resolve the cert/key to serve with, generating or renewing a self-signed pair
    as needed (#186, ruling 5 on #133).

    Returns the paths uvicorn should use. Raises with an actionable message rather than
    starting insecurely if TLS was requested and can't be provided — silently falling
    back to plaintext is the one behaviour nobody wants from this function.

    Runs at boot only (app.serve) — a container up for months at a stretch will not
    renew mid-run. Accepted for v0: an image update restarts the process, and a
    scheduled re-check independent of boot is a v1 conversation, not a launch blocker.
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
        # Warn only — never regenerate, overwrite, or delete a certificate the
        # operator mounted. We cannot mint someone else's certificate.
        _warn_if_provided_cert_aging(cert_path)
        logger.info("using provided TLS certificate", extra={"cert_path": str(cert_path)})
        return cert_path, key_path

    # self-signed: reuse what's on the data volume unless it is inside its renewal
    # window, in which case it is regenerated and overwritten in place. Regenerating
    # on every boot regardless would mean a fresh fingerprint on every restart, which
    # breaks any pinning and retrains operators to click through certificate warnings
    # — a predictable half-life rotation is a different animal: scheduled, logged, and
    # documented, rather than every-restart churn.
    if cert_path.is_file() and key_path.is_file():
        if not _renewal_due(cert_path):
            logger.info("reusing existing self-signed certificate", extra={"cert_path": str(cert_path)})
            return cert_path, key_path

        generate_self_signed(cert_path, key_path, settings.tls_hostname)
        renewed = x509.load_pem_x509_certificate(cert_path.read_bytes())
        logger.warning(
            "self-signed TLS certificate renewed — it had passed the midpoint of its "
            "validity window. The previous certificate is no longer served; expect a "
            "pinned client to need to re-pin.",
            extra={
                "cert_path": str(cert_path),
                "hostname": settings.tls_hostname,
                "serial_number": renewed.serial_number,
                "not_valid_after": renewed.not_valid_after_utc.isoformat(),
            },
        )
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
