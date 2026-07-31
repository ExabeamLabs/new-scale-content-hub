"""Local encryption helpers for saved destination credentials.

Windows uses the current user's Data Protection API (DPAPI). Other platforms
use a user-and-machine-bound key derivation plus Fernet authenticated encryption.
The encrypted credential is stored in destination.json; plaintext secrets are
never written to disk.
"""
from __future__ import annotations

import base64
import ctypes
import getpass
import hashlib
import importlib
import os
import platform
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any


class _CryptographyInvalidToken(Exception):
    """Fallback exception used when cryptography is not loaded."""


Fernet: Any = None
InvalidToken: type[BaseException] = _CryptographyInvalidToken
hashes: Any = None
PBKDF2HMAC: Any = None
_CRYPTOGRAPHY_IMPORT_ERROR: ImportError | None = None

# Windows uses DPAPI and must not require the third-party cryptography package.
# Load cryptography dynamically only on platforms that use the Fernet fallback.
if sys.platform != "win32":
    try:
        _fernet_module = importlib.import_module("cryptography.fernet")
        _hashes_module = importlib.import_module("cryptography.hazmat.primitives.hashes")
        _pbkdf2_module = importlib.import_module("cryptography.hazmat.primitives.kdf.pbkdf2")
        Fernet = _fernet_module.Fernet
        InvalidToken = _fernet_module.InvalidToken
        hashes = _hashes_module
        PBKDF2HMAC = _pbkdf2_module.PBKDF2HMAC
    except ImportError as exc:
        _CRYPTOGRAPHY_IMPORT_ERROR = exc


class CredentialEncryptionError(RuntimeError):
    """Raised when a saved credential cannot be encrypted or decrypted."""


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data)
    value = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return value, buffer


def _dpapi_protect(data: bytes) -> bytes:
    source, source_buffer = _blob(data)
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    # CRYPTPROTECT_UI_FORBIDDEN: never show an interactive OS dialog.
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        "Exabeam Replay destination token",
        None,
        None,
        None,
        0x1,
        ctypes.byref(output),
    ):
        raise CredentialEncryptionError(f"Windows DPAPI encryption failed: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
        del source_buffer


def _dpapi_unprotect(data: bytes) -> bytes:
    source, source_buffer = _blob(data)
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        0x1,
        ctypes.byref(output),
    ):
        raise CredentialEncryptionError(f"Windows DPAPI decryption failed: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
        del source_buffer


def _machine_material() -> bytes:
    """Return stable user/machine material without writing a key to disk."""
    components = [
        getpass.getuser(),
        str(Path.home()),
        platform.system(),
        platform.node(),
    ]
    if sys.platform.startswith("linux"):
        for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
            try:
                value = candidate.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if value:
                components.append(value)
                break
    elif sys.platform == "darwin":
        components.append(os.environ.get("USER", ""))
    try:
        components.append(str(os.getuid()))
    except AttributeError:
        components.append(os.environ.get("USERNAME", ""))
    return "\0".join(components).encode("utf-8", errors="surrogatepass")


def _fernet_for_salt(salt: bytes) -> Any:
    if _CRYPTOGRAPHY_IMPORT_ERROR is not None or Fernet is None or hashes is None or PBKDF2HMAC is None:
        raise CredentialEncryptionError(
            "Secure credential storage on this platform requires the cryptography package. "
            "Install it with: python -m pip install -r requirements.txt"
        ) from _CRYPTOGRAPHY_IMPORT_ERROR
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(hashlib.sha256(_machine_material()).digest()))
    return Fernet(key)


def encrypt_secret(secret: str) -> dict[str, Any] | None:
    """Encrypt a secret for the current user and return JSON-safe metadata."""
    if not secret:
        return None
    raw = secret.encode("utf-8")
    if sys.platform == "win32":
        encrypted = _dpapi_protect(raw)
        return {
            "algorithm": "windows-dpapi-current-user",
            "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        }

    salt = os.urandom(16)
    encrypted = _fernet_for_salt(salt).encrypt(raw)
    return {
        "algorithm": "fernet-machine-user-v1",
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": encrypted.decode("ascii"),
    }


def decrypt_secret(record: Any) -> str:
    """Decrypt a record created by :func:`encrypt_secret`."""
    if record in (None, ""):
        return ""
    if not isinstance(record, dict):
        raise CredentialEncryptionError("Saved credential metadata is invalid.")
    algorithm = record.get("algorithm")
    try:
        if algorithm == "windows-dpapi-current-user":
            encrypted = base64.b64decode(str(record["ciphertext"]), validate=True)
            return _dpapi_unprotect(encrypted).decode("utf-8")
        if algorithm == "fernet-machine-user-v1":
            salt = base64.b64decode(str(record["salt"]), validate=True)
            encrypted = str(record["ciphertext"]).encode("ascii")
            return _fernet_for_salt(salt).decrypt(encrypted).decode("utf-8")
    except (KeyError, ValueError, UnicodeError, InvalidToken) as exc:
        raise CredentialEncryptionError("Saved credential could not be decrypted for this user and machine.") from exc
    raise CredentialEncryptionError(f"Unsupported saved credential algorithm: {algorithm!r}")
