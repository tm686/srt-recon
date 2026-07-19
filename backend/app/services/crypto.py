import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def generate_salt() -> bytes:
    return os.urandom(32)


def derive_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600_000
    ).hex()


def verify_password(password: str, salt: bytes, stored_hash: str) -> bool:
    return hash_password(password, salt) == stored_hash


def encrypt_value(plaintext: str, fernet_key: bytes) -> str:
    f = Fernet(fernet_key)
    return f.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str, fernet_key: bytes) -> str:
    f = Fernet(fernet_key)
    return f.decrypt(ciphertext.encode()).decode()


def mask_key(key: str) -> str:
    if len(key) <= 8:
        return key[:2] + "*" * (len(key) - 2)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]
