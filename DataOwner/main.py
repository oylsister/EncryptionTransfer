import argparse
import sys
import os
import requests
import base64
import json
import hmac
import hashlib
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

_NONCE_SIZE = 12


def cmd_upload(server: str, src_path: str):
    if not os.path.exists(src_path) or not os.path.isfile(src_path):
        print('Source file not found:', src_path)
        return 2
    # If TTP is configured via env var TTP_URL use it; otherwise proceed plain
    ttp_url = os.environ.get('TTP_URL')
    # Create Encryption folder
    enc_dir = os.path.join(os.path.dirname(__file__), 'Encryption')
    os.makedirs(enc_dir, exist_ok=True)

    if ttp_url:
        # Ask TTP for a key and token, encrypt locally, and upload encrypted file named by token
        try:
            # generate key
            rkey = requests.post(ttp_url.rstrip('/') + '/generate-key')
            rkey.raise_for_status()
            key_b64 = rkey.json().get('key')
            # persist last key for this DataOwner in Encryption folder
            try:
                with open(os.path.join(enc_dir, 'last_key.b64'), 'w', encoding='utf-8') as kf:
                    kf.write(key_b64)
            except Exception:
                pass
            key_bytes = base64.urlsafe_b64decode(key_b64.encode('ascii'))
            # request token for filename
            payload = {'key': key_b64, 'filename': os.path.basename(src_path)}
            rtoken = requests.post(ttp_url.rstrip('/') + '/token', json=payload)
            rtoken.raise_for_status()
            token = rtoken.json().get('token')
        except Exception as e:
            print('TTP request failed:', e)
            return 2

        # encrypt file contents with AES-GCM
        if AESGCM is None:
            print('cryptography library not available; install with: pip install cryptography')
            return 2
        with open(src_path, 'rb') as f:
            plain = f.read()
        aes = AESGCM(key_bytes)
        nonce = os.urandom(_NONCE_SIZE)
        ct = aes.encrypt(nonce, plain, associated_data=None)
        blob = nonce + ct

        enc_path = os.path.join(enc_dir, token)
        try:
            with open(enc_path, 'wb') as ef:
                ef.write(blob)
        except Exception as e:
            print('Failed to write encrypted file:', e)
            return 2

        # upload encrypted file using token as filename
        url = server.rstrip('/') + '/upload'
        with open(enc_path, 'rb') as f:
            files = {'file': (token, f)}
            r = requests.post(url, files=files)
    else:
        url = server.rstrip('/') + '/upload'
        with open(src_path, 'rb') as f:
            files = {'file': (os.path.basename(src_path), f)}
            r = requests.post(url, files=files)
    if r.status_code not in (200, 201):
        try:
            print(r.status_code, r.json())
        except Exception:
            print(r.status_code, r.text)
        return 2

    try:
        data = r.json()
        print('Uploaded:', data)
        if isinstance(data, dict) and 'fileID' in data:
            print('Assigned fileID:', data['fileID'])
    except Exception:
        print(r.status_code, r.text)
    return 0

def _compute_token_from_key(key_bytes: bytes, filename: str) -> str:
    """Deterministic token = HMAC-SHA256(key, filename) urlsafe base64 (no padding)."""
    mac = hmac.new(key_bytes, filename.encode('utf-8'), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode('ascii').rstrip('=')


###
def cmd_download(server: str, filename: str, out_path: str = None):
    # Do NOT call TTP for download. Use locally stored key/token (Encryption/last_key.b64) if present.
    req_name = filename
    key_bytes = None

    key_file = os.path.join(os.path.dirname(__file__), 'Encryption', 'last_key.b64')
    if os.path.exists(key_file) and not filename.isdigit():
        try:
            key_b64 = open(key_file, 'r', encoding='utf-8').read().strip()
            key_bytes = base64.urlsafe_b64decode(key_b64.encode('ascii'))
            # compute deterministic token locally (same algorithm used by TTP)
            req_name = _compute_token_from_key(key_bytes, filename)
        except Exception as e:
            print('Failed to read/parse local key, proceeding with given name:', e)

    url = server.rstrip('/') + '/download/' + requests.utils.requote_uri(req_name)
    r = requests.get(url, stream=True)
    if r.status_code != 200:
        try:
            print(r.status_code, r.json())
        except Exception:
            print(r.status_code, r.text)
        return 2

    # If no out_path provided, save to Downloads folder next to this script
    if not out_path:
        downloads_dir = os.path.join(os.path.dirname(__file__), 'Downloads')
        os.makedirs(downloads_dir, exist_ok=True)
        # Try to infer filename from Content-Disposition header
        cd = r.headers.get('content-disposition') or r.headers.get('Content-Disposition') or ''
        fname = None
        if 'filename="' in cd:
            try:
                fname = cd.split('filename="', 1)[1].split('"', 1)[0]
            except Exception:
                fname = None
        if not fname:
            # fallback to provided key (may be fileID or filename)
            fname = os.path.basename(str(filename))
        out_path = os.path.join(downloads_dir, fname)

    # If we have a local key, try to decrypt (assumes the server stored encrypted blob)
    if key_bytes:
        # read all content (server returns encrypted blob)
        blob = r.content
        if AESGCM is None:
            print('cryptography library not available; cannot decrypt file')
            return 2
        try:
            aes = AESGCM(key_bytes)
            nonce = blob[:_NONCE_SIZE]
            ct = blob[_NONCE_SIZE:]
            plain = aes.decrypt(nonce, ct, associated_data=None)
        except Exception as e:
            print('Decryption failed:', e)
            return 2
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(plain)
        print('Downloaded and decrypted to', out_path)
        return 0

    # No decryption, write raw bytes stream
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        for chunk in r.iter_content(8192):
            if chunk:
                f.write(chunk)
    print('Downloaded to', out_path)
    return 0



def cmd_delete(server: str, filename: str):
    ttp_url = os.environ.get('TTP_URL')
    req_name = filename
    if ttp_url:
        try:
            key_file = os.path.join(os.path.dirname(__file__), 'Encryption', 'last_key.b64')
            if os.path.exists(key_file):
                key_b64 = open(key_file, 'r', encoding='utf-8').read().strip()
                payload = {'key': key_b64, 'filename': filename}
                rtoken = requests.post(ttp_url.rstrip('/') + '/token', json=payload)
                rtoken.raise_for_status()
                req_name = rtoken.json().get('token')
        except Exception as e:
            print('TTP token request failed, proceeding with given name:', e)
    url = server.rstrip('/') + '/delete/' + requests.utils.requote_uri(req_name)
    r = requests.delete(url)
    if r.status_code != 200:
        try:
            print(r.status_code, r.json())
        except Exception:
            print(r.status_code, r.text)
        return 2
    try:
        print(r.status_code, r.json())
    except Exception:
        print(r.status_code, r.text)
    return 0


def cmd_health(server: str):
    url = server.rstrip('/') + '/health'
    r = requests.get(url)
    if r.status_code != 200:
        try:
            print(r.status_code, r.json())
        except Exception:
            print(r.status_code, r.text)
        return 2
    try:
        print(r.status_code, r.json())
    except Exception:
        print(r.status_code, r.text)
    return 0


def _run_repl(server: str):
    """Run an interactive REPL that accepts commands:
    upload <local-path>
    download <remote-filename> <out-path>
    delete <remote-filename>
    health
    help
    exit
    """
    import shlex

    prompt = 'dataowner> '
    print(f'Starting interactive mode. Server: {server}')
    print('Type "help" for commands.')
    while True:
        try:
            raw = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print('\nExiting')
            return 0
        if not raw:
            continue
        parts = []
        try:
            parts = shlex.split(raw)
        except ValueError as e:
            print('Parse error:', e)
            continue
        cmd = parts[0].lower()
        try:
            if cmd in ('exit', 'quit'):
                print('Exiting')
                return 0
            if cmd == 'help':
                print('Commands: upload <local-path>, download <remote-filename> <out-path>,')
                print('          delete <remote-filename>, health, help, exit')
                continue
            if cmd == 'upload':
                if len(parts) != 2:
                    print('Usage: upload <local-path>')
                    continue
                rc = cmd_upload(server, parts[1])
                if rc != 0:
                    print('Upload failed with code', rc)
                continue
            if cmd == 'download':
                if len(parts) < 3 and len(parts) > 1:
                    rc = cmd_download(server, parts[1])
                elif len(parts == 3):
                    rc = cmd_download(server, parts[1], parts[2])
                else :
                    print("Usage: download <remote-filename> [out-path]")
                    continue

                if rc != 0:
                    print('Download failed with code', rc)
                continue
            if cmd == 'delete':
                if len(parts) != 2:
                    print('Usage: delete <remote-filename>')
                    continue
                rc = cmd_delete(server, parts[1])
                if rc != 0:
                    print('Delete failed with code', rc)
                continue
            if cmd == 'health':
                cmd_health(server)
                continue
            print('Unknown command:', cmd)
        except Exception as e:
            print('Error while executing command:', e)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='dataowner')
    parser.add_argument('--server', default='http://localhost:8000', help='Cloud server base URL')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive REPL mode')
    sub = parser.add_subparsers(dest='cmd')

    p_upload = sub.add_parser('upload')
    p_upload.add_argument('src', help='Local file to upload')

    p_download = sub.add_parser('download')
    p_download.add_argument('filename', help='Remote filename or fileID to download')
    p_download.add_argument('out', nargs='?', default=None, help='Local path to write file (optional)')

    p_delete = sub.add_parser('delete')
    p_delete.add_argument('filename', help='Remote filename to delete')

    p_health = sub.add_parser('health')

    args = parser.parse_args(argv)

    if args.interactive or args.cmd is None:
        return _run_repl(args.server)

    if args.cmd == 'upload':
        return cmd_upload(args.server, args.src)
    if args.cmd == 'download':
        return cmd_download(args.server, args.filename, args.out)
    if args.cmd == 'delete':
        return cmd_delete(args.server, args.filename)
    if args.cmd == 'health':
        return cmd_health(args.server)

    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())