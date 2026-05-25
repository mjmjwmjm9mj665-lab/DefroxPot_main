
# =====================================================================
# TELEGRAM ALERT INTEGRATION + EXPORT REPORT
# =====================================================================
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
import json
import csv
import datetime
import logging

logger_tg = logging.getLogger('defroxpot.telegram_views')


def _get_tg(user):
    from .models import TelegramSettings
    try:
        return TelegramSettings.objects.get(user=user)
    except TelegramSettings.DoesNotExist:
        return None


@login_required
def telegram_settings_view(request):
    from django.shortcuts import render
    tg = _get_tg(request.user)
    return render(request, 'telegram_settings.html', {'active': 'telegram', 'tg': tg})


@login_required
@csrf_exempt
def save_telegram_view(request):
    if request.method == 'POST':
        try:
            from .models import TelegramSettings
            data = json.loads(request.body)
            bot_token = data.get('bot_token', '').strip()
            chat_id = data.get('chat_id', '').strip()
            is_active = data.get('is_active', True)
            tg, _ = TelegramSettings.objects.get_or_create(user=request.user)
            tg.bot_token = bot_token
            tg.chat_id = chat_id
            tg.is_active = bool(is_active)
            tg.save()
            return JsonResponse({'status': 'saved', 'message': 'Telegram settings saved successfully.'})
        except Exception as e:
            logger_tg.error(f'save_telegram error: {e}')
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'error': 'POST only'}, status=405)


@login_required
@csrf_exempt
def test_telegram_view(request):
    if request.method == 'POST':
        try:
            from .telegram_alerts import test_telegram_connection
            data = json.loads(request.body)
            bot_token = data.get('bot_token', '').strip()
            chat_id = data.get('chat_id', '').strip()
            if not bot_token or not chat_id:
                return JsonResponse({'status': 'error', 'message': 'Bot token and Chat ID are required.'}, status=400)
            result = test_telegram_connection(bot_token, chat_id)
            if result.get('ok'):
                return JsonResponse({'status': 'ok', 'message': 'Test message sent! Check your Telegram.'})
            else:
                return JsonResponse({'status': 'error', 'message': result.get('description', 'Unknown Telegram error')}, status=400)
        except Exception as e:
            logger_tg.error(f'test_telegram error: {e}')
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'error': 'POST only'}, status=405)


@login_required
def export_report_view(request):
    """Generate a comprehensive CSV Threat Report for all captured honeypot logs."""
    try:
        from .views import handle_logs
        response = HttpResponse(content_type='text/csv')
        ts = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        response['Content-Disposition'] = f'attachment; filename="DefroxPot_ThreatReport_{ts}.csv"'
        writer = csv.writer(response)
        writer.writerow(['DefroxPot Enterprise Command Center - Threat Report'])
        writer.writerow(['Generated on', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])

        def section(name, path):
            logs = handle_logs(path)
            writer.writerow([f'--- {name.upper()} LOGS ---'])
            if logs:
                hdrs = []
                for e in logs:
                    for k in e:
                        if k not in hdrs:
                            hdrs.append(k)
                writer.writerow(hdrs)
                for e in logs:
                    writer.writerow([e.get(k, '') for k in hdrs])
            else:
                writer.writerow(['No logs captured yet.'])
            writer.writerow([])

        section('Website', './honeypot/Honeypot_Project_final/var/web_honeypot.log')
        section('Network', './honeypot/Honeypot_Project_final/var/net_honeypot.log')
        section('Keylogger', './honeypot/Honeypot_Project_final/var/key_logger.log')
        section('Photo Metadata', './honeypot/Honeypot_Project_final/var/photo_metadata.log')
        section('File Analysis', './honeypot/Honeypot_Project_final/var/file_analysis.log')
        return response
    except Exception as e:
        logger_tg.error(f'export_report error: {e}')
        return HttpResponse('Error generating report', status=500)
