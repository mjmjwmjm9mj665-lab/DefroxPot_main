"""
DefroxPot Telegram Alert Engine
================================
Drop-in utility for sending formatted Telegram alerts from any Django view.
Usage:
    from honeypot.telegram_alerts import send_telegram_alert, test_telegram_connection
"""
import requests
import logging
from datetime import datetime

logger = logging.getLogger('defroxpot.telegram')


def send_telegram_alert(bot_token: str, chat_id: str, event_type: str,
                        protocol: str = "TCP", ip: str = "Unknown",
                        payload: str = "", timestamp: str = None) -> dict:
    """
    Send a formatted threat alert to a Telegram chat.
    Returns dict: {'ok': True/False, 'description': '...'}
    """
    if not bot_token or not chat_id:
        return {'ok': False, 'description': 'Missing bot_token or chat_id'}

    if timestamp is None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    SEVERITY_EMOJI = {
        'keylog': '⌨️',
        'web':    '🌐',
        'ftp':    '📁',
        'ssh':    '🔐',
        'icmp':   '📡',
        'tcp':    '⚡',
        'photo':  '📸',
    }
    icon = SEVERITY_EMOJI.get(event_type.lower(), '🔴')

    RISK_EMOJI = {
        'CRITICAL': '🔴',
        'HIGH':     '🟠',
        'MEDIUM':   '🟡',
        'LOW':      '🟢',
    }
    risk_icon = RISK_EMOJI.get(payload.split(']')[0].lstrip('[').strip() if payload.startswith('[') else 'LOW', '🔴')

    # Detect if this is a payload event
    is_payload_event = 'PAYLOAD' in event_type.upper() or any(
        k in event_type.upper() for k in ('XSS', 'SQLI', 'RCE', 'SSTI', 'PATH')
    )

    # Truncate payload to avoid Telegram message size limit
    if payload and len(payload) > 300:
        payload = payload[:297] + '...'

    if is_payload_event:
        # Enhanced format for payload events
        risk_level = 'CRITICAL' if 'CRITICAL' in payload else 'HIGH'
        message = (
            f"🚨 *DefroxPot — Payload Intercepted!*\n"
            f"{'─' * 28}\n"
            f"⚡ *Event:* `{event_type.upper()}`\n"
            f"🌐 *Protocol:* `{protocol.upper()}`\n"
            f"📍 *Attacker IP:* `{ip}`\n"
            f"⏰ *Timestamp:* `{timestamp}`\n"
            f"{'─' * 28}\n"
            f"🛠 *Detected Payload:*\n"
            f"```\n{payload or 'N/A'}\n```\n"
            f"⚠️ *Risk Level:* `{risk_level}`\n"
            f"{'─' * 28}\n"
            f"_Powered by DefroxPot Enterprise_"
        )
    else:
        message = (
            f"🚨 *DefroxPot Alert*\n"
            f"{'─' * 28}\n"
            f"{SEVERITY_EMOJI.get(event_type.lower(), '🔴')} *Event:* `{event_type.upper()}`\n"
            f"🌐 *Protocol:* `{protocol.upper()}`\n"
            f"📍 *Attacker IP:* `{ip}`\n"
            f"⏰ *Timestamp:* `{timestamp}`\n"
            f"💻 *Payload:* `{payload or 'N/A'}`\n"
            f"{'─' * 28}\n"
            f"_Powered by DefroxPot Enterprise_"
        )

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = requests.post(url, json={
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'Markdown',
        }, timeout=8)
        data = response.json()
        if not data.get('ok'):
            logger.warning(f"Telegram alert failed: {data.get('description')}")
        return data
    except requests.exceptions.Timeout:
        logger.error("Telegram API timed out.")
        return {'ok': False, 'description': 'Request timed out (8s)'}
    except Exception as e:
        logger.error(f"Telegram alert exception: {e}")
        return {'ok': False, 'description': str(e)}


def test_telegram_connection(bot_token: str, chat_id: str) -> dict:
    """Send a test 'System Connected' message to verify credentials."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = (
        f"✅ *DefroxPot — System Connected*\n"
        f"{'─' * 28}\n"
        f"🛡️ Your Telegram alerts are now *active*.\n"
        f"⏰ Connected at: `{now}`\n"
        f"{'─' * 28}\n"
        f"_You will be notified in real-time for every\n"
        f"keylog, web attack, SSH/FTP intrusion captured._"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = requests.post(url, json={
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'Markdown',
        }, timeout=8)
        return response.json()
    except requests.exceptions.Timeout:
        return {'ok': False, 'description': 'Request timed out (8s). Check your internet connection.'}
    except Exception as e:
        return {'ok': False, 'description': str(e)}
