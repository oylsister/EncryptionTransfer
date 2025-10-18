"""TTP service: single POST endpoint to generate AES-256 key and filename token.

Endpoints:
  POST /generate?filename=<name>
    - Generates a 256-bit AES key, computes a deterministic token for the provided
      filename (HMAC-SHA256 using the generated key), stores the mapping in
      `TTP/keys.json`, and returns JSON { token, key } where key is base64.

  GET /search?filename=<name>
    - Lookup stored entries by original filename and return matching records.

Security note: This is a development TTP only. Do NOT use in production without
authentication, secure storage, and transport protection.
"""

import os
import time
import json
import base64
import hmac
import hashlib
from flask import Flask, request, jsonify
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

APP_DIR = os.path.dirname(__file__)
KEYS_PATH = os.path.join(APP_DIR, 'keys.json')

app = Flask(__name__)


def _load_store():
    if not os.path.exists(KEYS_PATH):
        return {}
    try:
        with open(KEYS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_store(store: dict):
    tmp = KEYS_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(store, f, indent=2)
    os.replace(tmp, KEYS_PATH)


def _generate_key_bytes() -> bytes:
    if AESGCM is None:
        raise RuntimeError('cryptography package required')
    return AESGCM.generate_key(bit_length=256)


def _compute_token(key: bytes, filename: str) -> str:
    mac = hmac.new(key, filename.encode('utf-8'), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode('ascii').rstrip('=')


@app.route('/generate', methods=['POST'])
def generate():
    # filename must be provided in query string as requested
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'filename query parameter is required'}), 400

    try:
        key = _generate_key_bytes()
    except Exception as e:
        return jsonify({'error': 'server cannot generate key', 'detail': str(e)}), 500

    key_b64 = base64.urlsafe_b64encode(key).decode('ascii')
    token = _compute_token(key, filename)

    # persist mapping: store tokens as keys (allows multiple tokens for different filenames)
    store = _load_store()
    # Use token as map key to avoid filename collisions; save original filename too
    entry = {
        'filename': filename,
        'key': key_b64,
        'created_at': int(time.time())
    }
    store[token] = entry
    try:
        _save_store(store)
    except Exception as e:
        return jsonify({'error': 'failed to persist key', 'detail': str(e)}), 500

    return jsonify({'token': token, 'key': key_b64})


@app.route('/search', methods=['GET'])
def search():
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'filename query parameter is required'}), 400
    store = _load_store()
    matches = []
    for token, ent in store.items():
        if ent.get('filename') == filename:
            matches.append({'token': token, 'key': ent.get('key'), 'created_at': ent.get('created_at')})
    if not matches:
        return jsonify({'matches': []}), 200
    return jsonify({'matches': matches})


if __name__ == '__main__':
    port = int(os.environ.get('TTP_PORT', 9000))
    app.run(host='0.0.0.0', port=port)
