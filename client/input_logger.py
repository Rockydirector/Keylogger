import json, platform, queue, threading, time
from datetime import datetime
from tkinter import Tk, Text, BOTH, Frame, Button, Label
import requests

from client.encryption import Crypto
from client.config import SERVER_URL, LOCAL_ENC_LOG, FERNET_KEY_FILE, HMAC_KEY_FILE, FLUSH_INTERVAL_SEC, MIN_CHARS_TO_SEND, APP_NAME, HASH_ALGO

BUFFER_Q = queue.Queue()
STOP_EVENT = threading.Event()
KILL_SWITCH_TRIGGERED = threading.Event()

def now_local():
    """Get system local time in ISO format (local system time)."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def do_flush(buf, crypto):
    plaintext = {
        "ts": now_local(),
        "host": platform.node(),
        "os": platform.platform(),
        "app": APP_NAME,
        "data": "".join(buf)
    }
    raw = json.dumps(plaintext).encode()
    token = crypto.encrypt_bytes(raw)
    payload_hash = crypto.digest(token)
    signature = crypto.hmac_sign(token)

    # Local log
    with open(LOCAL_ENC_LOG, "ab") as f:
        f.write(json.dumps({"ts": plaintext["ts"], "hash": payload_hash}).encode() + b"\n")
        f.write(token + b"\n")
        f.write(signature + b"\n")

    # Send to server
    try:
        requests.post(
            SERVER_URL,
            files={
                "blob": ("log.bin", token, "application/octet-stream"),
                "sig": ("sig.bin", signature, "application/octet-stream"),
            },
            data={
                "ts": plaintext["ts"],
                "host": plaintext["host"],
                "hash": payload_hash
            },
            timeout=3
        )
    except Exception as e:
        print("[WARN] Server POST failed:", e)


def worker_flush_loop():
    crypto = Crypto(FERNET_KEY_FILE, HMAC_KEY_FILE, HASH_ALGO)
    buf, last_flush = [], time.time()

    while not STOP_EVENT.is_set() and not KILL_SWITCH_TRIGGERED.is_set():
        try:
            ch = BUFFER_Q.get(timeout=0.2)

            if ch == "__FLUSH__" and buf:
                do_flush(buf, crypto)
                buf.clear()
                last_flush = time.time()
                continue
            else:
                buf.append(ch)

        except queue.Empty:
            pass

        # fallback timed flush
        if ((time.time() - last_flush) >= FLUSH_INTERVAL_SEC or len(buf) >= MIN_CHARS_TO_SEND) and buf:
            do_flush(buf, crypto)
            buf.clear()
            last_flush = time.time()

def on_keypress(event, text_widget: Text):
    ch = event.char if event.char else f"<{event.keysym}>"
    BUFFER_Q.put(ch)

    # Flush immediately when SPACE or ENTER is pressed
    if event.keysym in ["space", "Return"]:
        BUFFER_Q.put("__FLUSH__")

    return None


def start_gui():
    root = Tk()
    root.title(APP_NAME + " — Ethical Demo")
    root.geometry("720x420")
    frame = Frame(root)
    frame.pack(fill=BOTH, expand=True)

    Label(frame, text="Type here. Only this window is recorded, encrypted, signed & sent to server.").pack()
    text = Text(frame, wrap="word")
    text.pack(fill=BOTH, expand=True)
    text.bind("<Key>", lambda e: on_keypress(e, text))

    def do_kill():
        KILL_SWITCH_TRIGGERED.set()
        STOP_EVENT.set()
        root.destroy()

    Button(frame, text="Kill Switch (Stop)", command=do_kill).pack()
    root.bind_all("<Control-Alt-k>", lambda e: do_kill())

    threading.Thread(target=worker_flush_loop, daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    start_gui()
