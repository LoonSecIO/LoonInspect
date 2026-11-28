"""A passkey in memory for the tests (#955): it answers a challenge the way `PublicKeyCredential.toJSON()` writes it.

A P-256 key with the credential id, counter and backup flags a test chooses, so a test can answer the way Apple
Passwords does (a synced passkey, counter zero for good), the way a security key does (a counter that climbs), or
the ways no honest browser does: for another origin or host, without user verification, with a counter going back.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256

_UP, _UV, _BE, _BS, _AT = 0x01, 0x04, 0x08, 0x10, 0x40


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SoftPasskey:
    def __init__(self, *, credential_id: bytes | None = None, synced: bool = True) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = credential_id if credential_id is not None else os.urandom(32)
        self.synced = synced
        self.counter = 0
        self.user_handle: bytes | None = None

    def _flags(self, *, verified: bool, attested: bool = False) -> int:
        return _UP | (_UV if verified else 0) | ((_BE | _BS) if self.synced else 0) | (_AT if attested else 0)

    @staticmethod
    def _client(kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}).encode()

    def create(self, options: dict, *, origin: str, verified: bool = True, rp_id: str | None = None) -> dict:
        """The answer to a registration's `publicKey` options, made for `rp_id` (the options' own by default)."""
        self.user_handle = unb64(options["user"]["id"])
        client = self._client("webauthn.create", options["challenge"], origin)
        public = cbor.encode(ES256.from_cryptography_key(self.key.public_key()))
        attested = b"\0" * 16 + struct.pack(">H", len(self.credential_id)) + self.credential_id + public
        rp_hash = hashlib.sha256((rp_id or options["rp"]["id"]).encode()).digest()
        data = rp_hash + struct.pack(">BI", self._flags(verified=verified, attested=True), self.counter) + attested
        attestation = cbor.encode({"fmt": "none", "attStmt": {}, "authData": data})
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64(client),
                "attestationObject": b64(attestation),
                "transports": ["internal", "hybrid", "carrier-pigeon"],
            },
            "clientExtensionResults": {"credProps": {"rk": True}},
        }

    def get(
        self,
        options: dict,
        *,
        origin: str,
        verified: bool = True,
        rp_id: str | None = None,
        counter: int | None = None,
        user_handle: bytes | None = None,
    ) -> dict:
        """The answer to a sign-in's `publicKey` options. A security key's counter climbs by one each time unless a
        test sets it; a synced passkey's stays at zero."""
        if counter is not None:
            self.counter = counter
        elif not self.synced:
            self.counter += 1
        client = self._client("webauthn.get", options["challenge"], origin)
        rp_hash = hashlib.sha256((rp_id or options["rpId"]).encode()).digest()
        data = rp_hash + struct.pack(">BI", self._flags(verified=verified), self.counter)
        signature = self.key.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        handle = user_handle if user_handle is not None else self.user_handle
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64(client),
                "authenticatorData": b64(data),
                "signature": b64(signature),
                "userHandle": b64(handle) if handle else None,
            },
            "clientExtensionResults": {},
        }
