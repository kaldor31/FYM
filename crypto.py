import base64
import os
import time
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Identity:
    """Persistent identity based on Ed25519."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey = None):
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self.id = base64.urlsafe_b64encode(self.public_key_bytes).decode().rstrip("=")
        self.fingerprint = self.id[:16]

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def verify_signature(self, data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, data)
            return True
        except Exception:
            return False

    def save(self, path: str) -> None:
        private_raw = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        text = base64.b64encode(private_raw).decode()
        with open(path, "w") as f:
            f.write(text)

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path, "r") as f:
            text = f.read()
        private_raw = base64.b64decode(text)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_raw)
        return cls(private_key)

    def clear(self) -> None:
        """Drop the private key from memory."""
        self._private_key = None


class EphemeralKey:
    """Ephemeral X25519 key for one session."""

    def __init__(self):
        self._private_key = x25519.X25519PrivateKey.generate()

    @property
    def public_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def private_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @property
    def private_key(self):
        return self._private_key

    def shared_secret(self, remote_public_bytes: bytes) -> bytes:
        remote = x25519.X25519PublicKey.from_public_bytes(remote_public_bytes)
        return self._private_key.exchange(remote)

    def clear(self) -> None:
        """Drop the ephemeral private key from memory."""
        self._private_key = None


class SessionCipher:
    """ChaCha20-Poly1305 session keys derived from an ephemeral DH secret."""

    def __init__(self, shared_secret: bytes, is_initiator: bool):
        keys = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"fym-chat-v1",
        ).derive(shared_secret)
        # Asymmetric derivation so both sides use distinct send/recv keys.
        self.send_key = keys[:32] if is_initiator else keys[32:64]
        self.recv_key = keys[32:64] if is_initiator else keys[:32]
        self.send_nonce = 0
        self.recv_nonce = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = self.send_nonce.to_bytes(12, "big")
        self.send_nonce += 1
        ciphertext = ChaCha20Poly1305(self.send_key).encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 12:
            raise ValueError("packet too short")
        nonce = data[:12]
        expected = self.recv_nonce.to_bytes(12, "big")
        if nonce != expected:
            raise ValueError("nonce mismatch / replay detected")
        self.recv_nonce += 1
        return ChaCha20Poly1305(self.recv_key).decrypt(nonce, data[12:], None)


def encode_handshake(ephemeral: EphemeralKey, identity: Identity) -> bytes:
    """Build a handshake message: ephemeral_pub || timestamp || identity_pub || signature."""
    timestamp = int(time.time()).to_bytes(8, "big")
    public_key = identity.public_key_bytes
    msg = ephemeral.public_bytes + timestamp + public_key
    sig = identity.sign(msg)
    return msg + sig


def decode_handshake(payload: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """Parse handshake into ephemeral_pub, timestamp, identity_pub, signature."""
    if len(payload) != 136:
        raise ValueError("invalid handshake length")
    return payload[:32], payload[32:40], payload[40:72], payload[72:136]
