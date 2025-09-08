from cryptography.fernet import Fernet
from pathlib import Path
import hmac, hashlib

class Crypto:
    def __init__(self, fernet_key_path: Path, hmac_key_path: Path, hash_algo: str = "sha256"):
        if not fernet_key_path.exists():
            raise FileNotFoundError("Missing Fernet key.")
        if not hmac_key_path.exists():
            raise FileNotFoundError("Missing HMAC key.")

        self.fernet_key = fernet_key_path.read_bytes()
        self.hmac_key = hmac_key_path.read_bytes()
        self.fernet = Fernet(self.fernet_key)
        self.hash_algo = hash_algo

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self.fernet.encrypt(data)

    def decrypt_bytes(self, token: bytes) -> bytes:
        return self.fernet.decrypt(token)

    def hmac_sign(self, data: bytes) -> bytes:
        return hmac.new(self.hmac_key, data, getattr(hashlib, self.hash_algo)).digest()

    def hmac_verify(self, data: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(
            hmac.new(self.hmac_key, data, getattr(hashlib, self.hash_algo)).digest(),
            signature
        )

    def digest(self, data: bytes) -> str:
        return hashlib.new(self.hash_algo, data).hexdigest()