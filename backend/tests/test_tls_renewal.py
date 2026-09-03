"""Certificate renewal and the atomic-write fix (#186, ruling 5 on #133).

No database — pure filesystem and `cryptography`, against `tmp_path` and monkeypatched
settings. Pins the ruling as implemented: renew at `min(half the certificate's own
validity span, 183 days)`, measured from its own `not_valid_before_utc` — never off
`_VALIDITY_DAYS`, so editing that constant later does not retroactively reclassify a
certificate already on an operator's data volume. `TLS_MODE=provided` is the mirror
case: never regenerated, overwritten, or deleted — warn only, louder once expired.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core import tls
from app.core.config import settings

_HOSTNAME = "tls-test.example"


def _write_cert(
    cert_path, key_path, *, not_valid_before: datetime.datetime, not_valid_after: datetime.datetime
) -> x509.Certificate:
    """Build and write a self-signed pair with an explicit validity window.

    Doesn't reuse `tls.generate_self_signed`: that function derives both timestamps
    from `datetime.now()`, and these tests need certificates planted both inside and
    outside the renewal window, which only an explicit window can produce.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _HOSTNAME)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(_HOSTNAME)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return certificate


@pytest.fixture
def cert_paths(tmp_path, monkeypatch: pytest.MonkeyPatch):
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    monkeypatch.setattr(settings, "tls_cert_path", str(cert_path))
    monkeypatch.setattr(settings, "tls_key_path", str(key_path))
    monkeypatch.setattr(settings, "tls_hostname", _HOSTNAME)
    return cert_path, key_path


class TestSelfSignedRenewal:
    def test_fresh_pair_is_reused_not_regenerated(
        self, cert_paths, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "tls_mode", "self-signed")
        cert_path, key_path = cert_paths
        now = datetime.datetime.now(datetime.timezone.utc)
        original = _write_cert(
            cert_path,
            key_path,
            not_valid_before=now - datetime.timedelta(minutes=5),
            not_valid_after=now + datetime.timedelta(days=825),
        )

        tls.ensure_certificate()

        reused = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert reused.serial_number == original.serial_number

    def test_pair_inside_renewal_window_is_regenerated(
        self, cert_paths, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """825-day span, issued 400 days ago: past min(412, 183) = 183 days, not yet
        expired — the case ruling 5 exists for."""
        monkeypatch.setattr(settings, "tls_mode", "self-signed")
        cert_path, key_path = cert_paths
        not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
        original = _write_cert(
            cert_path, key_path, not_valid_before=not_before, not_valid_after=not_before + datetime.timedelta(days=825)
        )

        with caplog.at_level("WARNING", logger="app.core.tls"):
            tls.ensure_certificate()

        renewed = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert renewed.serial_number != original.serial_number
        assert renewed.not_valid_before_utc > original.not_valid_before_utc
        assert any("renewed" in record.getMessage() for record in caplog.records)

    def test_short_lived_cert_renews_at_half_life_not_183_days(
        self, cert_paths, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """min(span/2, 183): a 90-day certificate is due at 45 days, not 183 — the
        reading under which the "or six months" clause is not dead weight."""
        monkeypatch.setattr(settings, "tls_mode", "self-signed")
        cert_path, key_path = cert_paths
        not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=50)
        original = _write_cert(
            cert_path, key_path, not_valid_before=not_before, not_valid_after=not_before + datetime.timedelta(days=90)
        )

        tls.ensure_certificate()

        renewed = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert renewed.serial_number != original.serial_number

    def test_new_cert_still_generated_when_none_exists(
        self, cert_paths, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pre-existing first-boot path, unchanged by renewal landing beside it."""
        monkeypatch.setattr(settings, "tls_mode", "self-signed")
        cert_path, key_path = cert_paths

        tls.ensure_certificate()

        assert cert_path.is_file()
        assert key_path.is_file()


class TestProvidedCertIsNeverTouched:
    def test_inside_window_warns_and_is_left_alone(
        self, cert_paths, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(settings, "tls_mode", "provided")
        cert_path, key_path = cert_paths
        not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
        _write_cert(
            cert_path, key_path, not_valid_before=not_before, not_valid_after=not_before + datetime.timedelta(days=825)
        )
        original_cert_bytes = cert_path.read_bytes()
        original_key_bytes = key_path.read_bytes()

        with caplog.at_level("WARNING", logger="app.core.tls"):
            result_cert, result_key = tls.ensure_certificate()

        assert result_cert == cert_path
        assert result_key == key_path
        assert cert_path.read_bytes() == original_cert_bytes, "a provided cert must never be overwritten"
        assert key_path.read_bytes() == original_key_bytes, "a provided key must never be overwritten"
        assert any(
            record.levelname == "WARNING" and "renewal" in record.getMessage() for record in caplog.records
        )

    def test_expired_logs_loudly_and_is_left_alone(
        self, cert_paths, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(settings, "tls_mode", "provided")
        cert_path, key_path = cert_paths
        not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=900)
        _write_cert(
            cert_path, key_path, not_valid_before=not_before, not_valid_after=not_before + datetime.timedelta(days=825)
        )
        original_cert_bytes = cert_path.read_bytes()

        with caplog.at_level("WARNING", logger="app.core.tls"):
            tls.ensure_certificate()

        assert cert_path.read_bytes() == original_cert_bytes, "an expired provided cert must never be overwritten"
        assert any(
            record.levelname == "ERROR" and "EXPIRED" in record.getMessage() for record in caplog.records
        )

    def test_fresh_provided_cert_is_silent(
        self, cert_paths, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(settings, "tls_mode", "provided")
        cert_path, key_path = cert_paths
        now = datetime.datetime.now(datetime.timezone.utc)
        _write_cert(cert_path, key_path, not_valid_before=now, not_valid_after=now + datetime.timedelta(days=825))

        with caplog.at_level("WARNING", logger="app.core.tls"):
            tls.ensure_certificate()

        assert caplog.records == []

    def test_missing_file_still_refuses_to_start(self, cert_paths, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unchanged pre-existing behaviour: renewal must not paper over a missing
        mount by generating a self-signed pair in its place."""
        monkeypatch.setattr(settings, "tls_mode", "provided")

        with pytest.raises(FileNotFoundError):
            tls.ensure_certificate()


class TestAtomicWrite:
    def test_leaves_no_temp_file_behind_on_success(self, tmp_path) -> None:
        target = tmp_path / "server.crt"
        tls._replace_atomically(target, b"hello", mode=0o644)

        assert target.read_bytes() == b"hello"
        assert [p.name for p in tmp_path.iterdir()] == [target.name]

    def test_original_file_untouched_if_replace_fails(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The bug this closes (#133's spike): a crash between writing the cert and
        writing the key used to leave a fresh file beside a stale one. Simulating the
        failure at the rename step pins that the pre-existing file — and only it — is
        what's left behind, with no half-written temp file littering the directory.
        """
        target = tmp_path / "server.key"
        target.write_bytes(b"original")

        def _boom(*args, **kwargs):
            raise OSError("simulated failure")

        monkeypatch.setattr(tls.os, "replace", _boom)

        with pytest.raises(OSError):
            tls._replace_atomically(target, b"new", mode=0o600)

        assert target.read_bytes() == b"original"
        assert [p.name for p in tmp_path.iterdir()] == [target.name], "temp file must be cleaned up on failure"

    def test_key_written_with_owner_only_permissions(self, tmp_path) -> None:
        target = tmp_path / "server.key"
        tls._replace_atomically(target, b"secret", mode=0o600)
        assert (target.stat().st_mode & 0o777) == 0o600
