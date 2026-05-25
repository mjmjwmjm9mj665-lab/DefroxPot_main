from django.db import models
from django.contrib.auth.models import User


class TelegramSettings(models.Model):
    """
    Stores per-user Telegram Bot credentials for real-time honeypot alerts.
    One-to-one relationship with Django's built-in User model.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='telegram_settings')
    bot_token = models.CharField(
        max_length=128,
        blank=True,
        default='',
        help_text="Telegram Bot API token from @BotFather"
    )
    chat_id = models.CharField(
        max_length=64,
        blank=True,
        default='',
        help_text="Target chat or group ID from @IDBot"
    )
    is_active = models.BooleanField(
        default=False,
        help_text="Whether to send alerts for new events"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Telegram Settings"
        verbose_name_plural = "Telegram Settings"

    def __str__(self):
        return f"TelegramSettings(user={self.user.username}, active={self.is_active})"

    def has_credentials(self):
        return bool(self.bot_token and self.chat_id)
