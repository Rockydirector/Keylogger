from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from flask import Flask, request, jsonify, send_from_directory, render_template
from client.encryption import Crypto
from client.config import BASE as CLIENT_BASE

app = Flask(__name__, template_folder=str(Path(__file__).resolve().parent / "templates"))
BASE_DIR = Path(__file__).resolve().parent

OUT_DIR = BASE_DIR / "received_logs"
OUT_DIR.mkdir(parents=True, exist_ok=True)
DB = BASE_DIR / "metadata.db"

# Crypto with keys
crypto = Crypto(CLIENT_BASE / "fernet.key", CLIENT_BASE / "hmac.key")

# IST timezone
IST = timezone(timedelta(hours=5, minutes=30))

def now_local():
    """Return current IST time as string."""
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")

# DB setup
conn = sqlite3.connect(DB)
conn.execute("""CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, host TEXT, filename TEXT, hash TEXT,
    verified INTEGER, received_at TEXT, decrypted TEXT
)""")
conn.commit()
conn.close()

# ---------------------- Routes ----------------------
@app.route('/upload', methods=['POST'])
def upload():
    blob, sig = request.files.get('blob'), request.files.get('sig')
    host = request.form.get('host') or 'unknown'
    ts = request.form.get('ts') or now_local()
    claimed_hash = request.form.get('hash')

    if not blob or not sig:
        return jsonify({'ok': False, 'error': 'missing'}), 400

    raw, signature = blob.read(), sig.read()
    verified = crypto.hmac_verify(raw, signature)
    computed_hash = crypto.digest(raw)

    # decrypt immediately
    try:
        plaintext = crypto.decrypt_bytes(raw).decode()
    except Exception as e:
        plaintext = f"[ERROR decrypting: {e}]"

    # Save raw encrypted log
    filename = f"{ts.replace(':','-').replace(' ','_')}_{host}.bin"
    path = OUT_DIR / filename
    path.write_bytes(raw)

    # Save metadata in DB
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO logs (ts, host, filename, hash, verified, received_at, decrypted) VALUES (?,?,?,?,?,?,?)",
        (ts, host, filename, computed_hash, 1 if verified else 0, now_local(), plaintext)
    )
    conn.commit()
    conn.close()

    return jsonify({'ok': True, 'saved': filename, 'verified': verified, 'hash': computed_hash})


@app.route('/analytics/html', methods=['GET'])
def analytics_html():
    conn = sqlite3.connect(DB)
    rows = conn.execute(
        "SELECT id, ts, host, filename, hash, verified, received_at, decrypted FROM logs ORDER BY id DESC"
    ).fetchall()
    conn.close()

    logs = []
    for row in rows:
        log_id, ts, host, filename, hash_, verified, received_at, decrypted = row
        logs.append({
            "id": log_id,
            "ts": ts,
            "host": host,
            "filename": filename,
            "hash": hash_,
            "verified": verified,
            "received_at": received_at,
            "decrypted": decrypted,
        })

    return render_template('analytics.html', logs=logs)


@app.route('/download/<path:filename>', methods=['GET'])
def download(filename):
    return send_from_directory(OUT_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
