"""TTP service: provide AES-256 key generation and filename tokenization.

Endpoints:
  POST /generate-key -> { key: <base64> }
  POST /token -> { token: <string> }

Note: This is a simple local TTP for development. In production you'd protect
the endpoints, use authenticated channels, and store keys securely.

Requires: pip install flask cryptography
"""
import os
import base64
import hmac
import hashlib
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)


def generate_key_bytes() -> bytes:
    return AESGCM.generate_key(bit_length=256)


@app.route('/generate-key', methods=['POST'])
def generate_key():
    key = generate_key_bytes()
    return jsonify({'key': base64.urlsafe_b64encode(key).decode('ascii')})


@app.route('/token', methods=['POST'])
def token():
    data = request.get_json(force=True)
    if not data or 'key' not in data or 'filename' not in data:
        return jsonify({'error': 'key and filename required (key base64)'}), 400
    try:
        key = base64.urlsafe_b64decode(data['key'].encode('ascii'))
    except Exception:
        return jsonify({'error': 'invalid key encoding'}), 400
    filename = data['filename']
    mac = hmac.new(key, filename.encode('utf-8'), hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(mac).decode('ascii').rstrip('=')
    return jsonify({'token': token})


if __name__ == '__main__':
    port = int(os.environ.get('TTP_PORT', 9000))
    app.run(host='0.0.0.0', port=port)
