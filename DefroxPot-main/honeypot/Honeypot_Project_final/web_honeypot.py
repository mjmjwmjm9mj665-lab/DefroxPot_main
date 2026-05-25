# WebsiteTrap — upgraded with Payload Scanner & Telegram alert trigger
# Intercepts all form submissions and flags malicious payloads

from .mydesign import *
from . import mydesign
import json
import os
import re
from datetime import datetime


# ─── Payload Scanner ───────────────────────────────────────────────────────────
# Attack signatures to look for in any form field value
PAYLOAD_PATTERNS = [
    # XSS
    (r'<\s*script', 'XSS'),
    (r'javascript\s*:', 'XSS'),
    (r'on\w+\s*=', 'XSS'),
    (r'<\s*img[^>]+src\s*=', 'XSS'),
    # SQL Injection
    (r"'\s*(or|and)\s*'?\d", 'SQLi'),
    (r'--\s', 'SQLi'),
    (r';\s*drop\s+table', 'SQLi'),
    (r'union\s+select', 'SQLi'),
    (r'\bselect\b.+\bfrom\b', 'SQLi'),
    # Command Injection
    (r';\s*(ls|cat|whoami|id|uname|pwd|rm|wget|curl)\b', 'RCE'),
    (r'\|\s*(ls|cat|whoami|nc|bash|sh)\b', 'RCE'),
    (r'`[^`]+`', 'RCE'),
    # Path Traversal
    (r'\.\./', 'PATH_TRAVERSAL'),
    (r'\.\.\\\\', 'PATH_TRAVERSAL'),
    # SSTI
    (r'\{\{.*\}\}', 'SSTI'),
    (r'\{%.*%\}', 'SSTI'),
]

HIGH_RISK_CHARS = set('<>;\'\"--/*')


def scan_payload(value: str):
    """
    Scan a string for known attack patterns.
    Returns (is_malicious: bool, attack_type: str, severity: str)
    """
    if not value or not isinstance(value, str):
        return False, 'CLEAN', 'LOW'

    lower = value.lower()

    for pattern, attack_type in PAYLOAD_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            return True, attack_type, 'CRITICAL'

    # Generic suspicious chars check
    risky = [c for c in value if c in HIGH_RISK_CHARS]
    if len(risky) >= 2:
        return True, 'SUSPICIOUS_INPUT', 'HIGH'

    return False, 'CLEAN', 'LOW'


def log_payload(ip, endpoint, method, payload_raw, attack_type, severity):
    """Append a detected payload to payload.log and optionally fire Telegram alert."""
    entry = {
        'date': datetime.now().strftime('%d/%m/%Y'),
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'ip_addr': ip,
        'endpoint': endpoint,
        'method': method,
        'attack_type': attack_type,
        'severity': severity,
        'payload': payload_raw[:1024],   # cap at 1KB
    }
    log_path = os.path.join(os.path.dirname(__file__), 'var', 'payload.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a', encoding='utf-8') as f:
        json.dump(entry, f, ensure_ascii=False)
        f.write('\n')

    # ── Fire Telegram alert ────────────────────────────────────────────────────
    try:
        import django
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeypot.settings')
        from honeypot.models import TelegramSettings
        from honeypot.telegram_alerts import send_telegram_alert
        for tg in TelegramSettings.objects.filter(is_active=True):
            send_telegram_alert(
                bot_token=tg.bot_token,
                chat_id=tg.chat_id,
                event_type=f'PAYLOAD [{attack_type}]',
                protocol='HTTP',
                ip=ip,
                payload=f'[{severity}] {payload_raw[:300]}',
                timestamp=entry['timestamp'],
            )
    except Exception:
        pass   # Never crash the honeypot because of a Telegram error


class WebsiteTrap:

    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 2048 * 2048
    app.config['UPLOAD_PATH'] = os.path.join(os.path.dirname(__file__), 'uploads')

    # ── Global request interceptor ─────────────────────────────────────────────
    @app.before_request
    def intercept_all_requests():
        """Scan every incoming request for malicious payloads before routing."""
        ip = request.remote_addr
        endpoint = request.path
        method = request.method

        # Collect all values from GET + POST params
        all_values = list(request.args.values()) + list(request.form.values())

        # Also scan JSON body if present
        try:
            body = request.get_json(silent=True, force=True)
            if isinstance(body, dict):
                all_values += [str(v) for v in body.values()]
        except Exception:
            pass

        for val in all_values:
            is_bad, attack_type, severity = scan_payload(str(val))
            if is_bad:
                log_payload(ip, endpoint, method, str(val), attack_type, severity)
                break  # one log entry per request

    # Close db
    @app.teardown_appcontext
    def close_db(error):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('404.html'), 404

    app.secret_key = '122k'

    # Login Page
    @app.route('/', methods=['GET', 'POST'])
    def login():
        try:
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                user_data = mydesign.check_credentials(username, password)
                if user_data:
                    session['user_id'] = user_data[0]
                    session['new_account'] = False
                    return render_template('dashboard.html')
                else:
                    return render_template('incorrect_pass.html')
        except Exception as e:
            print(f"Error in login: {e}")
            return "Error occurred during login. Please try again."
        return mydesign.track_and_response(request, 'login.html')

    # Registration Page
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        try:
            if request.method == 'POST':
                username = request.form.get('username')
                email = request.form.get('email')
                password = request.form.get('password')
                if 'photo' in request.files:
                    photo = request.files['photo']
                    allowed_extensions = {'jpg', 'jpeg', 'png', 'pdf'}
                    if '.' in photo.filename and photo.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                        username = request.form.get('username', 'unknown_user')
                        file_path = os.path.join(os.path.dirname(__file__), "uploads", photo.filename)
                        photo.save(file_path)
                        mydesign.file_analysis(filepath=file_path)
                        mydesign.meta_data_extract(file_path)
                        session['user_id'] = username
                        session['new_account'] = True
                        mydesign.insert_credentials(username, email, password)
                        return render_template('registration_success.html')
                    else:
                        return 'Invalid file type. Please upload an image file.'
                else:
                    return 'No file found in the request.'
        except Exception as e:
            print(f"Error in registration: {e}")
            return "Error occurred during registration. Please try again."
        return mydesign.track_and_response(request, 'register.html')

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        return render_template('login.html')

    @app.route('/about', methods=['GET'])
    def about():
        return render_template('about.html')

    # Keylogger endpoint
    @app.route('/s', methods=['POST'])
    def keypress():
        json_logs = {
            "date": "", "timestamp": "",
            "ip_addr": "", "keystrokes": ""
        }
        data = request.get_json()
        json_logs["date"] = datetime.now().strftime('%d/%m/%Y')
        json_logs["timestamp"] = datetime.now().strftime('%H:%M:%S')
        json_logs["ip_addr"] = request.remote_addr
        pressed_key = data.get('key')
        key = 'defronix'
        json_logs['keystrokes'] = ''
        for i in range(len(pressed_key)):
            json_logs['keystrokes'] += chr(ord(pressed_key[i]) ^ ord(key[i % len(key)]))
        json_logs['keystrokes'] += ' '
        f = open(os.path.join(os.path.dirname(__file__), 'var', 'key_logger.log'), 'a')
        json.dump(json_logs, f, ensure_ascii=False)
        f.write("\n")
        f.close()
        return 'Keypress handled successfully'