from pathlib import Path
from client.encryption import Crypto
from client.config import FERNET_KEY_FILE, HMAC_KEY_FILE, LOCAL_ENC_LOG

crypto = Crypto(FERNET_KEY_FILE, HMAC_KEY_FILE)

if not LOCAL_ENC_LOG.exists():
    print("No local log found.")
else:
    raw = [line for line in LOCAL_ENC_LOG.read_bytes().splitlines() if line.strip()]
    i = 0
    while i + 2 < len(raw):  # need at least meta, token, sig
        try:
            meta = raw[i].decode("utf-8", errors="replace")
            token, sig = raw[i+1], raw[i+2]
            print("\n-- Entry:", meta)

            if crypto.hmac_verify(token, sig):
                print("Verified ✔")
                print("Decrypted:", crypto.decrypt_bytes(token).decode("utf-8", errors="replace"))
            else:
                print("Verification failed ✘")

        except Exception as e:
            print(f"[!] Error parsing entry at index {i}: {e}")

        i += 3
