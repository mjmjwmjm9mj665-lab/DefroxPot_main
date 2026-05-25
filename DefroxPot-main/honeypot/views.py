from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .Honeypot_Project_final import main
from werkzeug.serving import make_server
import threading
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import json
import logging
import os
import csv
import datetime
from .models import TelegramSettings
from .telegram_alerts import send_telegram_alert, test_telegram_connection

logger = logging.getLogger('defroxpot.views')

server = None
t2 = None

# ==============================================================
# BUG FIX #1, #2: Robust log parser with per-line error handling
# and graceful FileNotFoundError fallback
# ==============================================================
def is_port_in_use(port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('0.0.0.0', port)) == 0

def handle_logs(LOG_FILE_PATH, max_lines=500):
    """Parse JSON-lines log file safely with memory protection (only last N lines)."""
    from collections import deque
    logs = deque(maxlen=max_lines)
    
    if not os.path.exists(LOG_FILE_PATH):
        logger.warning(f'Log file not found: {LOG_FILE_PATH}')
        return list(logs)
        
    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8', errors='replace') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError as e:
                    continue
    except (IOError, OSError) as e:
        logger.error(f'Error reading log file {LOG_FILE_PATH}: {e}')
        
    return list(logs)


@login_required
def dashboard(request):
    ip_addr = []
    try:
        logs_web = handle_logs('./honeypot/Honeypot_Project_final/var/web_honeypot.log')
        for log in logs_web:
            ip = log.get('ip_addr')
            if ip and ip not in ip_addr:
                ip_addr.append(ip)

        logs_net = handle_logs('./honeypot/Honeypot_Project_final/var/net_honeypot.log')
        for log in logs_net:
            ip = log.get('ip_address') or log.get('ip_addr')
            if ip and ip not in ip_addr:
                ip_addr.append(ip)

        logs_key = handle_logs('./honeypot/Honeypot_Project_final/var/key_logger.log')
        for log in logs_key:
            ip = log.get('ip_addr')
            if ip and ip not in ip_addr:
                ip_addr.append(ip)

        return render(request, 'dashboard.html', {"active": "dashboard", "ip_addr": ip_addr})
    except Exception as e:
        logger.error(f'Dashboard error: {e}')
        return render(request, 'dashboard.html', {"active": "dashboard", "ip_addr": ip_addr})


flask_thread = None
flask_server = None
ftp_thread = None
ssh_thread = None


@csrf_exempt
def start_flask_server(request):
    global flask_thread, flask_server
    if request.method == 'POST':
        if flask_thread is None or not flask_thread.is_alive():
            if is_port_in_use(5000):
                return JsonResponse({'status': 'error', 'message': 'Port 5000 is already in use by another application.'})
                
            def run_flask():
                global flask_server
                try:
                    flask_server = make_server('0.0.0.0', 5000, main.WebsiteTrap.app, threaded=True)
                    flask_server.serve_forever()
                except Exception as e:
                    logger.error(f'Flask server error: {e}')

            flask_thread = threading.Thread(target=run_flask, daemon=True)
            flask_thread.start()
            return JsonResponse({'status': 'started', 'ip': '0.0.0.0', 'port': '5000'})
        else:
            return JsonResponse({'status': 'already_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def stop_flask_server(request):
    global flask_thread, flask_server
    if request.method == 'POST':
        if flask_thread is not None and flask_thread.is_alive():
            try:
                flask_server.shutdown()
                flask_thread.join(timeout=5)
            except Exception as e:
                logger.error(f'Error stopping Flask: {e}')
            flask_thread = None
            flask_server = None
            return JsonResponse({'status': 'stopped'})
        else:
            return JsonResponse({'status': 'not_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)


# ==============================================================
# BUG FIX #11: Return proper status for both FTP and SSH
# ==============================================================
@csrf_exempt
def start_network_server(request):
    global ftp_thread, ssh_thread
    if request.method == 'POST':
        started_services = []

        if ftp_thread is None or not ftp_thread.is_alive():
            if is_port_in_use(21):
                return JsonResponse({'status': 'error', 'message': 'Port 21 is in use. Check if another FTP is running.'})
            ftp_thread = threading.Thread(target=main.FtpHoneypot.run_ftp_server, daemon=True)
            ftp_thread.start()
            started_services.append('FTP')

        if ssh_thread is None or not ssh_thread.is_alive():
            if is_port_in_use(22):
                return JsonResponse({'status': 'error', 'message': 'Port 22 is in use. Cannot deploy SSH honeypot alongside real SSH.'})
            ssh_thread = threading.Thread(target=main.SSHhoneypot.start_ssh_server, daemon=True)
            ssh_thread.start()
            started_services.append('SSH')

        if started_services:
            return JsonResponse({'status': 'started', 'services': started_services})
        else:
            return JsonResponse({'status': 'already_running'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def stop_network_server(request):
    global ftp_thread, ssh_thread
    if request.method == 'POST':
        if ftp_thread is not None and ftp_thread.is_alive():
            try:
                main.FtpHoneypot.stop_ftp_server()
                ftp_thread.join(timeout=5)
            except Exception as e:
                logger.error(f'Error stopping FTP: {e}')
            ftp_thread = None

        if ssh_thread is not None and ssh_thread.is_alive():
            try:
                main.SSHhoneypot.stop_ssh_server()
                ssh_thread.join(timeout=5)
            except Exception as e:
                logger.error(f'Error stopping SSH: {e}')
            ssh_thread = None

        return JsonResponse({'status': 'stopped'})
    return JsonResponse({'error': 'Invalid request method'}, status=400)


def network_setup(request):
    global ftp_thread, ssh_thread
    if (ftp_thread is not None and ftp_thread.is_alive()) or \
       (ssh_thread is not None and ssh_thread.is_alive()):
        return JsonResponse({'status': 'running'})
    return JsonResponse({'status': 'stopped'})


def server_setup(request):
    global flask_thread
    if flask_thread is not None and flask_thread.is_alive():
        return JsonResponse({'status': 'running'})
    else:
        return JsonResponse({'status': 'stopped'})


@login_required
def setup(request):
    return render(request, "setup.html", {"active": "setup"})


@login_required
def file_analysis(request):
    try:
        key_logs = handle_logs('./honeypot/Honeypot_Project_final/var/file_analysis.log')
        keys = []
        for key_log in key_logs:
            for key in key_log.keys():
                if key not in keys:
                    keys.append(key)
        return render(request, "file.html", {"active": "details", 'key_logs': key_logs, 'keys': keys})
    except Exception as e:
        logger.error(f'File analysis error: {e}')
        return render(request, "file.html", {"active": "details"})


@login_required
def Keylogger(request):
    try:
        key_logs = handle_logs('./honeypot/Honeypot_Project_final/var/key_logger.log')
        keys = []
        for key_log in key_logs:
            for key in key_log.keys():
                if key not in keys:
                    keys.append(key)
        return render(request, "Keylogger.html", {"active": "Keylogger", 'key_logs': key_logs, 'keys': keys})
    except Exception as e:
        logger.error(f'Keylogger error: {e}')
        return render(request, "Keylogger.html", {"active": "Keylogger"})


@login_required
def network(request):
    try:
        key_logs = handle_logs('./honeypot/Honeypot_Project_final/var/net_honeypot.log')
        keys = []
        for key_log in key_logs:
            for key in key_log.keys():
                if key not in keys:
                    keys.append(key)
        return render(request, "network.html", {"active": "network", 'key_logs': key_logs, 'keys': keys})
    except Exception as e:
        logger.error(f'Network logs error: {e}')
        return render(request, "network.html", {"active": "network"})


@login_required
def photo(request):
    try:
        key_logs = handle_logs('./honeypot/Honeypot_Project_final/var/photo_metadata.log')
        keys = []
        for key_log in key_logs:
            for key in key_log.keys():
                if key not in keys:
                    keys.append(key)
        return render(request, "photo.html", {"active": "photo", 'key_logs': key_logs, 'keys': keys})
    except Exception as e:
        logger.error(f'Photo metadata error: {e}')
        return render(request, "photo.html", {"active": "photo"})


@login_required
def website(request):
    try:
        key_logs = handle_logs('./honeypot/Honeypot_Project_final/var/web_honeypot.log')
        keys = []
        for key_log in key_logs:
            for key in key_log.keys():
                if key not in keys:
                    keys.append(key)
        return render(request, "website.html", {"active": "website", 'key_logs': key_logs, 'keys': keys})
    except Exception as e:
        logger.error(f'Website logs error: {e}')
        return render(request, "website.html", {"active": "website"})


def handlelogin(request):
    if request.method == "POST":
        Username = request.POST.get("loginusername", "")
        Password = request.POST.get("loginpassword", "")
        user = authenticate(username=Username, password=Password)
        if user is not None:
            login(request, user)
            return redirect("dashboard")
        else:
            messages.error(request, "Username or Password is incorrect.")
            return redirect('handlelogin')
    return render(request, 'login.html')


@login_required
def handlelogout(request):
    logout(request)
    messages.info(request, "Logged out Successfully!")
    return redirect('handlelogin')

@login_required
def about(request):
    return render(request, 'about.html')


@login_required
def clear_logs(request):
    import os
    var_path = os.path.join(os.path.dirname(__file__), 'Honeypot_Project_final', 'var')
    uploads_path = os.path.join(os.path.dirname(__file__), 'Honeypot_Project_final', 'uploads')
    
    try:
        # Clear log files
        if os.path.exists(var_path):
            for file in os.listdir(var_path):
                if file.endswith('.log'):
                    open(os.path.join(var_path, file), 'w').close()
                    
        # Delete captured uploads
        if os.path.exists(uploads_path):
            for file in os.listdir(uploads_path):
                file_path = os.path.join(uploads_path, file)
                if os.path.isfile(file_path):
                    try:
                        os.unlink(file_path)
                    except Exception:
                        pass
    except Exception as e:
        logger.error(f'Failed to clear logs: {e}')
        
    return redirect('setup')

@login_required
def payload_analysis(request):
    """Show all detected malicious payloads from the payload scanner."""
    payload_log_path = './honeypot/Honeypot_Project_final/var/payload.log'
    payloads = handle_logs(payload_log_path)

    critical_count = sum(1 for p in payloads if p.get('severity') == 'CRITICAL')
    high_count     = sum(1 for p in payloads if p.get('severity') == 'HIGH')
    attack_types   = {}
    for p in payloads:
        at = p.get('attack_type', 'UNKNOWN')
        attack_types[at] = attack_types.get(at, 0) + 1

    max_count = max(attack_types.values()) if attack_types else 1
    attack_types_pct = {k: min(100, round(v / max_count * 100)) for k, v in attack_types.items()}

    context = {
        'active':           'payload',
        'payloads':         list(reversed(payloads)),
        'total':            len(payloads),
        'critical_count':   critical_count,
        'high_count':       high_count,
        'attack_types':     attack_types,
        'attack_types_pct': attack_types_pct,
        'signatures': ['XSS', 'SQLi', 'RCE', 'SSTI', 'PATH_TRAVERSAL', 'SUSPICIOUS_INPUT'],
    }
    return render(request, 'payload_analysis.html', context)
