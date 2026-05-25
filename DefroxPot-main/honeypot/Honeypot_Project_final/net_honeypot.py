from .mydesign import *
from . import mydesign

# ==============================================================
# FTP Honeypot — Fixed version
# Bug fixes: #3 (missing ip_address in on_login/on_login_failed),
#            #13 (file handle leak — use context managers)
# ==============================================================

server = None
ssh_server = None


def _write_log(log_entry):
    """Thread-safe log writer using context manager (BUG FIX #13)."""
    try:
        log_path = os.path.join(os.path.dirname(__file__), 'var', 'net_honeypot.log')
        with open(log_path, 'a', encoding='utf-8') as f:
            json.dump(log_entry, f, ensure_ascii=False)
            f.write("\n")
    except Exception as e:
        print(f"[net_honeypot] Log write error: {e}")


class FtpHoneypot(FTPHandler):

    def on_connect(self):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "message": "Connection established"
        }
        _write_log(log_entry)

    # BUG FIX #3: Added ip_address field to on_login
    def on_login(self, username):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "username": username,
            "message": "Login attempt"
        }
        _write_log(log_entry)

    # BUG FIX #4: Added ip_address field to on_login_failed
    def on_login_failed(self, username):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "username": username,
            "message": "Failed login attempt"
        }
        _write_log(log_entry)

    def on_logout(self, username):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "username": username,
            "message": "Logout"
        }
        _write_log(log_entry)

    def on_version(self, version):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "version": version,
            "message": "Version information"
        }
        _write_log(log_entry)

    def on_auth(self, username):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "username": username,
            "message": "Authentication successful"
        }
        _write_log(log_entry)

    def on_auth_failed(self, username):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "username": username,
            "message": "Authentication failed"
        }
        _write_log(log_entry)

    def on_disconnect(self):
        log_entry = {
            "ip_address": self.remote_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "FTP",
            "port": 21,
            "message": "Connection closed"
        }
        _write_log(log_entry)

    def run_ftp_server():
        global server
        authorizer = DummyAuthorizer()
        filepath = os.path.join(os.path.dirname(__file__), 'home')
        os.makedirs(filepath, exist_ok=True)

        authorizer.add_anonymous(filepath, perm="")
        authorizer.add_user(username="incog", password="pass",
                            homedir=filepath, perm="elradfm")

        handler = FtpHoneypot
        handler.authorizer = authorizer

        server = FTPServer(("0.0.0.0", 21), handler)
        print("[FTP Honeypot] Listening on port 21")
        server.serve_forever()

    def stop_ftp_server():
        global server
        print("Stopping FTP server...")
        try:
            if server:
                server.close_all()
                print("FTP server stopped")
        except Exception as e:
            print(f"Error stopping FTP server: {e}")


# ==============================================================
# SSH Honeypot — Fixed version
# Bug fixes: #5 (recv_ready().register() crash),
#            #6 (broken indentation in while loop),
#            #10 (bind to 0.0.0.0 instead of 127.0.0.1)
# ==============================================================

class SSHhoneypot(paramiko.ServerInterface):

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_auth_password(self, username, password):
        # Log every auth attempt with attacker IP (captured during accept)
        log_entry = {
            "ip_address": getattr(self, '_client_ip', 'unknown'),
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "SSH",
            "port": 22,
            "username": username,
            "message": f"Auth attempt (user={username})"
        }
        _write_log(log_entry)

        if username == "incog" and password == "pass":
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def log_event(self, message, client_ip='unknown'):
        log_entry = {
            "ip_address": client_ip,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "protocol": "SSH",
            "port": 22,
            "message": message
        }
        _write_log(log_entry)

    # BUG FIX #10: Bind to 0.0.0.0 (was 127.0.0.1 — external connections rejected)
    def start_ssh_server(bind_host='0.0.0.0', bind_port=22):
        global ssh_server
        try:
            ssh_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ssh_server.bind((bind_host, bind_port))
            ssh_server.listen(5)
            print(f"[SSH Honeypot] Listening on {bind_host}:{bind_port}")

            while True:
                try:
                    client, addr = ssh_server.accept()
                    client_ip = addr[0]
                    print(f"[SSH Honeypot] Connection from {addr}")

                    # Log connection
                    log_entry = {
                        "ip_address": client_ip,
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "protocol": "SSH",
                        "port": bind_port,
                        "message": "SSH connection attempt"
                    }
                    _write_log(log_entry)

                    transport = paramiko.Transport(client)
                    key_path = os.path.join(os.path.dirname(__file__), 'id_rsa')
                    server_key = paramiko.RSAKey.from_private_key_file(
                        filename=key_path, password="pass"
                    )
                    transport.add_server_key(server_key)
                    transport.set_gss_host(socket.getfqdn(""))

                    ssh = SSHhoneypot()
                    ssh._client_ip = client_ip  # Pass IP to auth handler

                    try:
                        transport.start_server(server=ssh)
                    except paramiko.SSHException as e:
                        print(f"[SSH Honeypot] SSH negotiation failed: {e}")
                        client.close()
                        continue

                    channel = transport.accept(20)
                    if channel is None:
                        print("[SSH Honeypot] Channel request failed.")
                        transport.close()
                        client.close()
                        continue

                    print(f"[SSH Honeypot] Authenticated: {client_ip}")

                    # BUG FIX #5/#6: Properly handle channel I/O
                    # The original code called channel.recv_ready().register()
                    # which crashes because recv_ready() returns a boolean.
                    # Fixed: Simple recv loop with proper exception handling.
                    try:
                        channel.settimeout(0.5)
                        while transport.is_active():
                            try:
                                if channel.recv_ready():
                                    command = channel.recv(4096).decode('utf-8', errors='replace').strip()
                                    if command:
                                        ssh.log_event(
                                            f"Executed command: {command}",
                                            client_ip=client_ip
                                        )
                                        # Send fake response
                                        channel.send(f"bash: {command}: command not found\r\n")
                            except socket.timeout:
                                continue
                            except Exception:
                                break
                    except Exception as e:
                        print(f"[SSH Honeypot] Session error: {e}")
                    finally:
                        try:
                            channel.close()
                        except Exception:
                            pass
                        try:
                            transport.close()
                        except Exception:
                            pass
                        client.close()

                except Exception as e:
                    print(f"[SSH Honeypot] Connection handler error: {e}")
                    continue

        except OSError as e:
            print(f"[SSH Honeypot] Cannot bind to {bind_host}:{bind_port}: {e}")
            print("  Hint: Port 22 may require root/admin privileges or be in use.")
        except Exception as e:
            print(f"[SSH Honeypot] Fatal error: {e}")

    def stop_ssh_server():
        global ssh_server
        try:
            if ssh_server:
                ssh_server.close()
                print("[SSH Honeypot] Server stopped")
        except Exception as e:
            print(f"Error stopping SSH server: {e}")
