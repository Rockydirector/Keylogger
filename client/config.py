from pathlib import Path

SERVER_URL = "http://127.0.0.1:5000/upload"
ANALYTICS_URL = "http://127.0.0.1:5000/analytics/html"

BASE = Path("/home/rocky/Desktop/keylogger").resolve()
LOGS_DIR = BASE / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_ENC_LOG = LOGS_DIR / "encrypted.log"

FERNET_KEY_FILE = BASE / "fernet.key"
HMAC_KEY_FILE = BASE / "hmac.key"

FLUSH_INTERVAL_SEC = 1
MIN_CHARS_TO_SEND = 10
APP_NAME = "Consent Logger"

HASH_ALGO = "sha256"
