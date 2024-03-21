from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class MonetizeConfig(AppConfig):
    name = "chowapi.monetize"
    verbose_name = _("Monetize")

    def ready(self):
        try:
            import chowapi.monetize.signals  # noqa: F401
        except ImportError:
            pass
