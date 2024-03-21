from django.contrib import admin

from chowapi.management.models import CompanyDetails, CompanyPercentageEarning, DeliveryCityLocations

# Register your models here.
admin.site.register(CompanyDetails)


class CompanyPercentageEarningAdmin(admin.ModelAdmin):
    list_display = [
        "sales_charge_percentage",
        "cost_per_km",
        "withdrawal_charge",
    ]

admin.site.register(CompanyPercentageEarning, CompanyPercentageEarningAdmin)

admin.site.register(DeliveryCityLocations)
