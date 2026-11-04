"""A software passkey: stands in for the legitimate user's phone or laptop in scenarios.

It builds the same WebAuthn responses a real authenticator would ("none"
attestation, ES256 key) so the app's normal passkey checks run unchanged.
"""
import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftPasskey:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id, self.origin = rp_id, origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0
        self.user_handle: str | None = None

    def _rp_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest()

    def _client_data(self, kind: str, challenge: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin,
                           "crossOrigin": False}).encode()

    def _cose_key(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def register(self, options: dict) -> dict:
        """Answer /account/passkeys/register/begin options."""
        self.user_handle = options["user"]["id"]
        client_data = self._client_data("webauthn.create", options["challenge"])
        flags = 0x01 | 0x04 | 0x40  # user present, user verified, attested credential data
        auth_data = (self._rp_hash() + bytes([flags]) + struct.pack(">I", self.sign_count) + bytes(16)
                     + struct.pack(">H", len(self.credential_id)) + self.credential_id + self._cose_key())
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cid = b64u(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(attestation),
                             "transports": ["internal"]},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

    def sign_in(self, options: dict) -> dict:
        """Answer /auth/passkey/begin options."""
        self.sign_count += 1
        client_data = self._client_data("webauthn.get", options["challenge"])
        auth_data = self._rp_hash() + bytes([0x05]) + struct.pack(">I", self.sign_count)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        cid = b64u(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                             "signature": b64u(signature), "userHandle": self.user_handle},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}
