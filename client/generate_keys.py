from cryptography.fernet import Fernet
from pathlib import Path
import secrets

BASE = Path("/home/rocky/Desktop/keylogger/client").resolve().parent
FERNET_FILE = BASE / "fernet.key"
HMAC_FILE = BASE / "hmac.key"

if not FERNET_FILE.exists():
    FERNET_FILE.write_bytes(Fernet.generate_key())
    print("Fernet key created.")
else:
    print("Fernet key already exists.")

if not HMAC_FILE.exists():
    HMAC_FILE.write_bytes(secrets.token_bytes(32))  # 32-byte HMAC key
    print("HMAC key created.")
else:
    print("HMAC key already exists.")

