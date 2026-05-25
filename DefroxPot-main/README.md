<div align="center">

<h1>🛡️ DefroxPot</h1>

<img src="https://github.com/TeamDefronix/DefroxPot/assets/64286654/c8b70e39-59d1-4a4c-9ada-74b7dba0e923" width="55%"><br>

<img src="https://forthebadge.com/images/badges/made-with-python.svg">


<br><br>

<a href="https://github.com/TeamDefronix/DefroxPot/releases/latest">
  <img alt="Latest release" src="https://img.shields.io/github/v/release/TeamDefronix/DefroxPot?style=for-the-badge&logo=starship&color=C9CBFF&logoColor=D9E0EE&labelColor=302D41"/>
</a>

<a href="https://github.com/TeamDefronix/DefroxPot/blob/main/LICENSE">
  <img alt="License" src="https://img.shields.io/github/license/TeamDefronix/DefroxPot?style=for-the-badge&logo=starship&color=ee999f&logoColor=D9E0EE&labelColor=302D41"/>
</a>
<a href="https://github.com/TeamDefronix/DefroxPot/stargazers">
  <img alt="Stars" src="https://img.shields.io/github/stars/TeamDefronix/DefroxPot?style=for-the-badge&logo=starship&color=c69ff5&logoColor=D9E0EE&labelColor=302D41"/>
</a>
<a href="https://github.com/TeamDefronix/DefroxPot/issues">
  <img alt="Issues" src="https://img.shields.io/github/issues/TeamDefronix/DefroxPot?style=for-the-badge&logo=bilibili&color=F5E0DC&logoColor=D9E0EE&labelColor=302D41"/>
</a>
<a href="https://github.com/TeamDefronix/DefroxPot">
  <img alt="Repo Size" src="https://img.shields.io/github/repo-size/TeamDefronix/DefroxPot?color=%23DDB6F2&label=SIZE&logo=codesandbox&style=for-the-badge&logoColor=D9E0EE&labelColor=302D41"/>
</a>

<br><br>

**[<kbd> <br> Features <br> </kbd>](#-features)**
**[<kbd> <br> Installation <br> </kbd>](#-installation)**
**[<kbd> <br> Usage <br> </kbd>](#-usage)**
**[<kbd> <br> Stack <br> </kbd>](#-technology-stack)**
**[<kbd> <br> Screenshots <br> </kbd>](#-screenshots)**
**[<kbd> <br> Contributors <br> </kbd>](#-contributors)**

</div>

---

## 📖 Description

**DefroxPot** is an enterprise-grade cybersecurity honeypot command center designed to **detect, monitor, and analyze malicious activity** in a controlled environment. Built for security researchers and professionals, it combines a multi-layer trap system (Web, SSH, FTP, Keylogger) with a real-time glassmorphism dashboard, automated payload detection, and instant Telegram alerting.

---

## ✨ Features

### 🌐 Web Honeypot (Port 5000)
- Serves a fake login/registration page to trap attackers
- **Payload Scanner** — intercepts every HTTP request and scans for XSS, SQLi, RCE, SSTI, and Path Traversal patterns using regex
- **Keylogger** — captures and decrypts attacker keystrokes (XOR cipher)
- **File Analysis** — runs uploaded files through VirusTotal API and extracts EXIF metadata (GPS, device model)
- Logs IP address, user agent, session cookies, and paths visited

### 🔐 Network Honeypot (SSH Port 22 / FTP Port 21)
- Simulates real SSH and FTP servers using `paramiko` and `pyftpdlib`
- Captures every login attempt (username + password combinations)
- Port collision detection — prevents silent thread failures

### 📊 Enterprise Dashboard
- **AniGravity UI** — Glassmorphism design with spring-physics animations, 3D Three.js globe, and GSAP micro-interactions
- **Payload Analysis** — Dedicated page visualizing every intercepted malicious payload with syntax highlighting and glitch-red animations
- **Keylogger Viewer** — Real-time keystroke feed
- **Photo Intelligence** — Extracts GPS coordinates and EXIF metadata from attacker-uploaded images
- **Dark / Light mode** — No-reload theme switcher
- **Clear History** — Secure maintenance function to purge all logs and uploads

### 📲 Telegram Alerts
- Connect your own Telegram bot in the **Notifications** settings page
- Receives a formatted alert for every new attack event:
  ```
  🚨 DefroxPot — Payload Intercepted!
  ⚡ Event: PAYLOAD [XSS]
  📍 Attacker IP: 203.0.113.14
  🛠 Detected Payload: <script>alert(1)</script>
  ⚠️ Risk Level: CRITICAL
  ```
- **Test Connection** button to verify your bot before going live

### 📁 Export & Reporting
- One-click **CSV Threat Report** export covering all log sources

### 🔒 Production Hardening
- Memory-safe log parsing with `collections.deque` (max 500 entries, prevents OOM crashes)
- Port-in-use checks before spawning any honeypot thread
- Thread-safe background service management

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/mjmjwmjm9mj665-lab/DefroxPot
cd DefroxPot
```

### 2. Create a Virtual Environment (Recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

> **Note:** [ExifTool](https://exiftool.org) must be installed separately for image metadata extraction.  
> Place `exiftool(-k).exe` (Windows) or `exiftool` (Linux) in `honeypot/Honeypot_Project_final/`.

### 4. Set Up the Database
```bash
python manage.py migrate
python manage.py createsuperuser
```

### 5. Start the Dashboard
```bash
python manage.py runserver
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and log in with your superuser credentials.

### 6. (Optional) Start Real-Time Streaming Server
```bash
python realtime_server.py
```
This enables the live WebSocket attack feed on the 3D globe (requires separate terminal, port 9000).

---

## 🎯 Usage

| What you want to do | Steps |
|---|---|
| **Deploy the Web Trap** | Go to **Setup** → click **Start Flask Server** → share Port 5000 URL |
| **Deploy SSH/FTP Trap** | Go to **Setup** → click **Start Network Server** |
| **View intercepted payloads** | Go to **Payload Analysis** in the sidebar |
| **View keystroke captures** | Go to **Keylogger** in the sidebar |
| **Set up Telegram alerts** | Go to **Notifications** → paste Bot Token + Chat ID → Test → Save |
| **Export full report** | Click **Export CSV Report** on any page |
| **Clear all captured data** | Go to **Setup** → click **Clear All Logs** |

---

## 🔧 Technology Stack

| Layer | Technology |
|---|---|
| **Backend Framework** | Django 5.0, Flask 3.0 |
| **Network Traps** | Paramiko (SSH), pyftpdlib (FTP) |
| **Real-Time Streaming** | Socket.IO + Eventlet |
| **Packet Sniffing** | Scapy |
| **Frontend UI** | Vanilla CSS (Glassmorphism), GSAP, Three.js |
| **Alerting** | Telegram Bot API (via `requests`) |
| **Database** | SQLite (Django ORM) |
| **File Intelligence** | ExifTool, VirusTotal API |
| **Cryptography** | XOR cipher (keylogger), bcrypt, PyNaCl |

---

## 📦 Dependencies

All Python packages are in `requirements.txt`. Additional tools:

- **ExifTool** (required for photo metadata): [https://exiftool.org](https://exiftool.org)
- **VirusTotal API** (optional, for file scanning): [https://www.virustotal.com](https://www.virustotal.com)

Verify tool authenticity:
- `exiftool.exe` (Windows): [VirusTotal Report](https://www.virustotal.com/gui/file/e9bfbb1ae99f3b5587f926393c3e9ccd86ad7e03a779a06f5e68601a6a85a714)
- `exiftool` (Linux): [VirusTotal Report](https://www.virustotal.com/gui/file/4827ade560b85f0877c635fd7e32144e9196f4fa256cc504c42f8593cc79a32b)

---

## 📸 Screenshots

> Dashboard, Payload Analysis, Keylogger, Network Monitor, Telegram Settings, and more.

![Dashboard](https://github.com/TeamDefronix/DefroxPot/assets/104693696/f9f2965d-37ec-4750-9287-673c2608b065)

![Payload Analysis](https://github.com/TeamDefronix/DefroxPot/assets/104693696/5bfb2d44-6c8d-4da8-aaee-badb4b21b897)

![Keylogger](https://github.com/TeamDefronix/DefroxPot/assets/104693696/09b4b4e5-5872-432e-a465-0f401e52c4c4)

![Network Monitor](https://github.com/TeamDefronix/DefroxPot/assets/104693696/0ea91eea-d965-42c4-81d1-4b440a0e2ab3)

![Setup](https://github.com/TeamDefronix/DefroxPot/assets/104693696/804c461e-61f4-4850-827f-b787a80a3c55)

![Notifications](https://github.com/TeamDefronix/DefroxPot/assets/104693696/3abda9aa-d3ad-479f-8f11-f2ab5600b6f8)

---

## ⚠️ Legal Disclaimer

This tool is intended **for educational and research purposes only**. Only deploy DefroxPot on systems and networks you own or have explicit written permission to test. The authors are not responsible for any misuse.

---

## 📞 Contacts

<p align="left">
<a href="https://github.com/TeamDefronix"><img src="https://github.com/gauravghongde/social-icons/raw/master/SVG/Color/Github.svg" width="48" height="48" alt="GitHub"/></a>&nbsp;
<a href="https://www.facebook.com/defronix"><img src="https://raw.githubusercontent.com/gauravghongde/social-icons/master/SVG/Color/Facebook.svg" width="48" height="48" alt="Facebook"/></a>&nbsp;
<a href="https://twitter.com/teamdefronix"><img src="https://github.com/gauravghongde/social-icons/raw/master/SVG/Color/Twitter.svg" width="48" height="48" alt="Twitter"/></a>&nbsp;
<a href="https://instagram.com/teamdefronix"><img src="https://github.com/gauravghongde/social-icons/raw/master/SVG/Color/Instagram.svg" width="48" height="48" alt="Instagram"/></a>&nbsp;
<a href="https://youtube.com/@defronix"><img src="https://github.com/gauravghongde/social-icons/raw/master/SVG/Color/Youtube.svg" width="48" height="48" alt="YouTube"/></a>&nbsp;
<a href="https://www.linkedin.com/company/defronix/"><img src="https://github.com/gauravghongde/social-icons/raw/master/SVG/Color/LinkedIN.svg" width="48" height="48" alt="LinkedIn"/></a>
</p>

---

## 💖 Support the Project

<p>
<a href="https://www.buymeacoffee.com/metaxone" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" width="210" alt="Buy Me A Coffee"/></a>
</p>

---

## 🤝 Contributors

<div align="center">

<h3>Thanks To All Contributors</h3>

<a href="https://github.com/TeamDefronix/DefroxPot/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=TeamDefronix/DefroxPot"/>
</a>

</div>

---

*DefroxPot is a professional-grade prototype actively being improved. Contributions, issues, and feature requests are welcome!*
