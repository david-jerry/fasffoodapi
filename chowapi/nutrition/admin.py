from django.contrib import admin

from chowapi.nutrition.models import Nutrition
from chowapi.utils.mixins import ExportMixin


# Register your models here.
@admin.register(Nutrition)
class NutritionAdmin(admin.ModelAdmin, ExportMixin):
    model = Nutrition
    list_per_page = 250
    empty_value_display = "-empty-"
    search_fields = ['name']
    list_display = [
        "__str__",
        "name",
        "icon",
        "description",
    ]
    list_editable = [
        "name",
        "icon",
        "description",
    ]
    actions = ["export_as_csv", "export_as_pdf"]
