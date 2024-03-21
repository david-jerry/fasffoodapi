from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class NutritionConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "chowapi.nutrition"
    verbose_name = _("Nutritions")

    def ready(self):
        try:
            import chowapi.nutrition.signals  # noqa: F401
        except ImportError:
            pass
