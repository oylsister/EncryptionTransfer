import os
import sys
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote
import cgi
import json
import mimetypes
import time


DATA_DIR = os.path.join(os.path.dirname(__file__), 'CloudData')
INDEX_FILE = 'index.json'

# In-memory index structures (populated at startup)
_INDEX = {}  # maps str(fileID) -> {filename, path, size, uploaded_at}
_NEXT_ID = 1


def _index_path():
    return os.path.join(DATA_DIR, INDEX_FILE)


def load_index():
    global _INDEX, _NEXT_ID
    try:
        p = _index_path()
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                data = json.load(f)
            _INDEX = data.get('files', {}) or {}
            _NEXT_ID = int(data.get('next_id', 1))
        else:
            _INDEX = {}
            _NEXT_ID = 1
    except Exception:
        # If index is corrupt, start fresh but don't crash server
        _INDEX = {}
        _NEXT_ID = 1


def save_index():
    try:
        p = _index_path()
        tmp = p + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump({'next_id': _NEXT_ID, 'files': _INDEX}, f, indent=2)
        os.replace(tmp, p)
    except Exception as e:
        # best-effort logging to stderr
        print('Failed to save index:', e, file=sys.stderr)


def register_file(safe_name: str, dest_path: str):
    """Register a saved file in the index and return assigned fileID (int)."""
    global _NEXT_ID, _INDEX
    try:
        fid = _NEXT_ID
        stat = os.stat(dest_path)
        _INDEX[str(fid)] = {
            'filename': safe_name,
            'path': dest_path,
            'size': stat.st_size,
            'uploaded_at': int(time.time())
        }
        _NEXT_ID += 1
        save_index()
        return fid
    except Exception as e:
        print('Failed to register file:', e, file=sys.stderr)
        return None


def unregister_file_by_id(fid: str):
    global _INDEX
    if fid in _INDEX:
        del _INDEX[fid]
        save_index()
        return True
    return False


def find_file_by_id_or_name(key: str):
    """Return tuple (fileID_str, entry) for numeric id or filename match, else (None, None)."""
    # numeric id lookup
    if key.isdigit():
        ent = _INDEX.get(key)
        if ent:
            return key, ent
        return None, None
    # filename lookup (return first match)
    for fid, ent in _INDEX.items():
        if ent.get('filename') == key:
            return fid, ent
    return None, None


class UploadHandler(BaseHTTPRequestHandler):
    def _send_json(self, code, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Only accept uploads to /upload
        if self.path != '/upload':
            self._send_json(404, {'error': 'Not found'})
            return

        content_type = self.headers.get('Content-Type')
        if not content_type:
            self._send_json(400, {'error': 'Missing Content-Type header'})
            return

        ctype, pdict = cgi.parse_header(content_type)
        if ctype != 'multipart/form-data':
            self._send_json(400, {'error': 'Content-Type must be multipart/form-data'})
            return

        # Parse multipart form data
        pdict['boundary'] = bytes(pdict['boundary'], 'utf-8')
        pdict['CONTENT-LENGTH'] = int(self.headers.get('Content-Length', 0))

        try:
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD':'POST'}, keep_blank_values=True)
        except Exception as e:
            self._send_json(400, {'error': 'Failed to parse form data', 'detail': str(e)})
            return

        if 'file' not in form:
            self._send_json(400, {'error': 'No file field in form (expected name="file")'})
            return

        file_field = form['file']
        if not file_field.filename:
            self._send_json(400, {'error': 'Uploaded file has no filename'})
            return

        # Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)

        safe_name = os.path.basename(file_field.filename)
        dest_path = os.path.join(DATA_DIR, safe_name)

        # Write file to disk
        try:
            with open(dest_path, 'wb') as out_f:
                data = file_field.file.read()
                out_f.write(data)
        except Exception as e:
            self._send_json(500, {'error': 'Failed to save file', 'detail': str(e)})
            return

        # Register in index and return assigned fileID
        fid = register_file(safe_name, dest_path)
        resp = {'message': 'File saved', 'path': dest_path}
        if fid is not None:
            resp['fileID'] = fid
        self._send_json(201, resp)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Health check
        if path == '/health' or path == '/':
            self._send_json(200, {'status': 'ok', 'storage_dir': DATA_DIR})
            return

        # Download: GET /download/<fileID_or_filename>
        if path.startswith('/download/'):
            key = unquote(path[len('/download/'):])
            if not key:
                self._send_json(400, {'error': 'Missing filename or fileID'})
                return

            fid, ent = find_file_by_id_or_name(key)
            if ent is None:
                self._send_json(404, {'error': 'File not found'})
                return

            file_path = ent.get('path')

            # Send file with appropriate headers
            ctype, _ = mimetypes.guess_type(file_path)
            if not ctype:
                ctype = 'application/octet-stream'
            try:
                fs = os.stat(file_path)
                self.send_response(200)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(fs.st_size))
                # Use indexed filename if available
                disp_name = ent.get('filename') or os.path.basename(file_path)
                self.send_header('Content-Disposition', f'attachment; filename="{disp_name}"')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    # stream in chunks
                    chunk_size = 64 * 1024
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except BrokenPipeError:
                # client disconnected; just return
                return
            except Exception as e:
                self._send_json(500, {'error': 'Failed to read file', 'detail': str(e)})
            return

        # Convenience delete via GET (optional): GET /delete/<fileID_or_filename>
        if path.startswith('/delete/'):
            key = unquote(path[len('/delete/'):])
            if not key:
                self._send_json(400, {'error': 'Missing filename or fileID'})
                return
            fid, ent = find_file_by_id_or_name(key)
            if ent is None:
                self._send_json(404, {'error': 'File not found'})
                return
            file_path = ent.get('path')
            try:
                os.remove(file_path)
                # unregister index entry
                unregister_file_by_id(fid)
                self._send_json(200, {'message': 'File deleted', 'path': file_path, 'fileID': fid})
            except Exception as e:
                self._send_json(500, {'error': 'Failed to delete file', 'detail': str(e)})
            return

        # Not found
        self._send_json(404, {'error': 'Not found'})

    def do_DELETE(self):
        # DELETE /delete/<filename>
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith('/delete/'):
            self._send_json(404, {'error': 'Not found'})
            return

        raw_name = unquote(path[len('/delete/'):])
        key = raw_name
        if not key:
            self._send_json(400, {'error': 'Missing filename or fileID'})
            return

        fid, ent = find_file_by_id_or_name(key)
        if ent is None:
            self._send_json(404, {'error': 'File not found'})
            return

        file_path = ent.get('path')
        try:
            os.remove(file_path)
            unregister_file_by_id(fid)
            self._send_json(200, {'message': 'File deleted', 'path': file_path, 'fileID': fid})
        except Exception as e:
            self._send_json(500, {'error': 'Failed to delete file', 'detail': str(e)})


def run_server(host: str, port: int):
    # Ensure data directory exists before starting the server
    os.makedirs(DATA_DIR, exist_ok=True)
    # Load or initialize index
    load_index()

    server = HTTPServer((host, port), UploadHandler)
    print(f"Starting server on {host}:{port}. Upload endpoint: POST /upload\nCloudData dir: {DATA_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down')
        server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Simple Cloud file receiver')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    args = parser.parse_args(argv)

    run_server(args.host, args.port)


if __name__ == '__main__':
    main()
