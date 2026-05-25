import time
import json
import urllib.request
import urllib.error
import socket

print("\n" + "="*50)
print("   [ DefroxPot Automated QA Simulator ]")
print("="*50 + "\n")

# Configuration
WEB_URL = "http://127.0.0.1:5000"
KEYLOGGER_URL = "http://127.0.0.1:5000/s"
XOR_KEY = "defronix"

passed = 0
failed = 0

def log_result(test_name, success, info=""):
    global passed, failed
    if success:
        print(f"[PASS] {test_name}: {info}")
        passed += 1
    else:
        print(f"[FAIL] {test_name}: {info}")
        failed += 1

def xor_encrypt(text, key):
    return "".join(chr(ord(t) ^ ord(key[i % len(key)])) for i, t in enumerate(text))

# ---------------------------------------------------------
# Test 1: Check if Web Honeypot is running
# ---------------------------------------------------------
try:
    response = urllib.request.urlopen(f"{WEB_URL}/")
    if response.status == 200:
        log_result("Web Trap Live", True, "Honeypot is answering on port 5000")
    else:
        log_result("Web Trap Live", False, f"Status code {response.status}")
except Exception as e:
    log_result("Web Trap Live", False, f"Server unreachable: {e}")

# ---------------------------------------------------------
# Test 2: Check Keylogger Endpoint
# ---------------------------------------------------------
try:
    # Encrypt 'QA_TEST_KEY' with XOR 'defronix'
    payload_text = "QA_TEST_KEY"
    encrypted = xor_encrypt(payload_text, XOR_KEY)
    
    data = json.dumps({'key': encrypted}).encode('utf-8')
    req = urllib.request.Request(KEYLOGGER_URL, data=data, headers={'Content-Type': 'application/json'})
    
    response = urllib.request.urlopen(req)
    if response.status == 200:
        log_result("Keylogger API", True, f"Successfully injected '{payload_text}' into /s")
    else:
        log_result("Keylogger API", False, f"Failed with status: {response.status}")
except Exception as e:
    log_result("Keylogger API", False, f"Error: {e}")

# ---------------------------------------------------------
# Test 3: Check SSH Honeypot (Port 22)
# ---------------------------------------------------------
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    result = s.connect_ex(('127.0.0.1', 22))
    s.close()
    if result == 0:
        log_result("SSH Trap Live", True, "Port 22 is open and listening")
    else:
        log_result("SSH Trap Live", False, "Port 22 is closed. Did you Deploy the Network Trap?")
except Exception as e:
    log_result("SSH Trap Live", False, str(e))

# ---------------------------------------------------------
# Test 4: Check FTP Honeypot (Port 21)
# ---------------------------------------------------------
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    result = s.connect_ex(('127.0.0.1', 21))
    s.close()
    if result == 0:
        log_result("FTP Trap Live", True, "Port 21 is open and listening")
    else:
        log_result("FTP Trap Live", False, "Port 21 is closed. Did you Deploy the Network Trap?")
except Exception as e:
    log_result("FTP Trap Live", False, str(e))


print("\n" + "="*50)
if failed == 0:
    print(f"QA COMPLETE: {passed}/{passed+failed} tests passed perfectly! Your enterprise setup is SOLID.")
else:
    print(f"QA COMPLETE: {failed} tests failed. Remember to click 'Deploy' in your Dashboard first!")
print("="*50 + "\n")
