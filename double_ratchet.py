#!/usr/bin/env python3
"""Minimal Double Ratchet (Signal) for forward/future secrecy inside a session.

Uses X25519 DH ratchet + KDF chain + ChaCha20-Poly1305.

Encrypted message format:
  [4 bytes header length] [header] [nonce(12) + tag(16) + ciphertext]

Header:
  [dh_public_key(32)] [message_number(4)] [previous_chain_length(4)]
"""

import os
import struct
import hmac
import hashlib
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


HEADER_LEN = 4
PUBKEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def _hkdf(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(secret)


def _kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Derive message key and next chain key from a chain key (HMAC)."""
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, next_chain_key


def _kdf_rk(root_key: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """Derive new root key and chain key from DH output and current root key."""
    keys = _hkdf(dh_out + root_key, b"", b"DoubleRatchetRoot", 64)
    return keys[:32], keys[32:]


def _pubkey_bytes(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _load_pubkey(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


class DoubleRatchet:
    """Encrypt/decrypt with Double Ratchet."""

    def __init__(
        self,
        shared_secret: bytes,
        is_initiator: bool,
        own_private_key_bytes: bytes,
        remote_public_key_bytes: bytes,
        max_skip: int = 1000,
    ):
        own_key = X25519PrivateKey.from_private_bytes(own_private_key_bytes)
        remote_key = X25519PublicKey.from_public_bytes(remote_public_key_bytes)
        self._root_key = _hkdf(shared_secret, b"", b"DoubleRatchetInit", 32)
        self._dh_pair = (own_key, own_key.public_key())
        self._remote_key = remote_key
        self._is_initiator = is_initiator
        self._max_skip = max_skip

        # Derive initial send/recv chain keys from the root key.
        keys = _hkdf(self._root_key, b"", b"DoubleRatchetChain", 64)
        if is_initiator:
            self._send_ck, self._recv_ck = keys[:32], keys[32:]
        else:
            self._recv_ck, self._send_ck = keys[:32], keys[32:]

        self._send_mn = 0
        self._recv_mn = 0
        self._prev_chain_length = 0
        self._skipped: Dict[Tuple[bytes, int], bytes] = {}
        self._pending_ratchet = False  # set when remote key is updated in recv

    def _current_pubkey_bytes(self) -> bytes:
        return _pubkey_bytes(self._dh_pair[1])

    def _dh(self, private: X25519PrivateKey, public: X25519PublicKey) -> bytes:
        return private.exchange(public)

    def _start_send_chain(self) -> None:
        """Generate a new DH key pair and ratchet the sending chain."""
        old_chain_length = self._send_mn
        new_priv = X25519PrivateKey.generate()
        self._dh_pair = (new_priv, new_priv.public_key())
        dh_out = self._dh(new_priv, self._remote_key)
        self._root_key, self._send_ck = _kdf_rk(self._root_key, dh_out)
        self._send_mn = 0
        self._prev_chain_length = old_chain_length
        self._pending_ratchet = False

    def _start_recv_chain(self, new_remote_key: X25519PublicKey, prev_chain_length: int) -> None:
        """Ratchet the receiving chain with a new remote DH public key."""
        dh_out = self._dh(self._dh_pair[0], new_remote_key)
        self._root_key, self._recv_ck = _kdf_rk(self._root_key, dh_out)
        self._remote_key = new_remote_key
        self._recv_mn = 0
        self._prev_chain_length = prev_chain_length
        self._pending_ratchet = True

    def _skip_message_keys(self, until: int, remote_key: X25519PublicKey) -> None:
        """Derive and store skipped message keys up to a target message number."""
        remote_bytes = _pubkey_bytes(remote_key)
        if self._recv_mn >= until:
            return
        if until - self._recv_mn > self._max_skip:
            raise ValueError("too many skipped messages")
        while self._recv_mn < until:
            mk, self._recv_ck = _kdf_ck(self._recv_ck)
            self._skipped[(remote_bytes, self._recv_mn)] = mk
            self._recv_mn += 1

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext; returns a self-contained message."""
        if self._pending_ratchet:
            self._start_send_chain()

        message_key, self._send_ck = _kdf_ck(self._send_ck)
        header = (
            self._current_pubkey_bytes()
            + struct.pack(">I", self._send_mn)
            + struct.pack(">I", self._prev_chain_length)
        )
        self._send_mn += 1

        nonce = os.urandom(NONCE_LEN)
        cipher = ChaCha20Poly1305(message_key)
        ciphertext = nonce + cipher.encrypt(nonce, plaintext, header)

        return struct.pack(">I", len(header)) + header + ciphertext

    def decrypt(self, message: bytes) -> bytes:
        """Decrypt a self-contained message."""
        if len(message) < HEADER_LEN:
            raise ValueError("message too short")
        header_len = struct.unpack(">I", message[:HEADER_LEN])[0]
        if len(message) < HEADER_LEN + header_len:
            raise ValueError("message too short")
        header = message[HEADER_LEN : HEADER_LEN + header_len]
        ciphertext = message[HEADER_LEN + header_len :]

        if len(header) != PUBKEY_LEN + 8:
            raise ValueError("invalid header")

        remote_key = _load_pubkey(header[:PUBKEY_LEN])
        message_number = struct.unpack(">I", header[PUBKEY_LEN : PUBKEY_LEN + 4])[0]
        prev_chain_length = struct.unpack(">I", header[PUBKEY_LEN + 4 : PUBKEY_LEN + 8])[0]

        remote_bytes = _pubkey_bytes(remote_key)

        current_remote_bytes = _pubkey_bytes(self._remote_key)

        # New DH ratchet from remote public key?
        if remote_bytes != current_remote_bytes:
            self._skip_message_keys(prev_chain_length, self._remote_key)
            self._start_recv_chain(remote_key, prev_chain_length)

        # Out-of-order message in the current chain?
        if message_number < self._recv_mn:
            message_key = self._skipped.pop((remote_bytes, message_number), None)
            if message_key is None:
                raise ValueError("message key not found (duplicate or too old)")
            nonce, encrypted = self._split_ciphertext(ciphertext)
            cipher = ChaCha20Poly1305(message_key)
            return cipher.decrypt(nonce, encrypted, header)

        # Skip to target message number.
        self._skip_message_keys(message_number, self._remote_key)

        # Derive message key.
        message_key, self._recv_ck = _kdf_ck(self._recv_ck)
        self._recv_mn = message_number + 1

        nonce, encrypted = self._split_ciphertext(ciphertext)
        cipher = ChaCha20Poly1305(message_key)
        return cipher.decrypt(nonce, encrypted, header)

    def _split_ciphertext(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        if len(ciphertext) < NONCE_LEN + TAG_LEN:
            raise ValueError("ciphertext too short")
        return ciphertext[:NONCE_LEN], ciphertext[NONCE_LEN:]

    def clear(self) -> None:
        """Wipe key material from memory."""
        self._root_key = b""
        self._send_ck = b""
        self._recv_ck = b""
        self._send_mn = 0
        self._recv_mn = 0
        self._prev_chain_length = 0
        self._skipped.clear()
        self._dh_pair = None
        self._remote_key = None

