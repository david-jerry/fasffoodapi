from django.apps import AppConfig


class AnalyticsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "chowapi.analytics"

    def ready(self):
        try:
            import chowapi.analytics.signals  # noqa: F401
        except ImportError:
            pass
