from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class VendorsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "chowapi.vendors"
    verbose_name = _("Vendors")


    def ready(self):
        try:
            import chowapi.vendors.signals  # noqa: F401
        except ImportError:
            pass
