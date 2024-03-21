from django.contrib import admin

from ..utils.mixins import ExportMixin
from .models import (
    VendorShop,
    Locations,
    OpenHours,
    MenuItems,
    MenuNutritionalValue,
    MenuItemImages,
    VendorsEarnings,
    MenuItemOrder,
    DeliveryDetails,
)

admin.site.register(DeliveryDetails)


class VendorsEarningsInline(admin.TabularInline):
    model = VendorsEarnings
    extra = 0


# Register your models here.
class MenuNutritionalValueInline(admin.StackedInline):
    model = MenuNutritionalValue
    extra = 3


class MenuItemImagesInline(admin.StackedInline):
    model = MenuItemImages
    extra = 3


@admin.register(MenuItemOrder)
class MenuItemOrderAdmin(admin.ModelAdmin, ExportMixin):
    model = MenuItemOrder
    list_per_page = 250
    empty_value_display = "-empty-"
    list_display = [
        "user",
        "delivery_lat",
        "delivery_lon",
        "delivery_address",
        "order_id",
        "amount",
        "quantity",
        "paid",
        "failed",
    ]
    actions = ["export_as_csv", "export_as_pdf"]


@admin.register(MenuItems)
class MenuItemsInline(admin.ModelAdmin, ExportMixin):
    model = MenuItems
    list_per_page = 250
    empty_value_display = "-empty-"
    search_fields = ["name", "unique_id", "description"]
    list_display = [
        "name",
        "vendor",
        "unique_id",
        "description",
        "quantity",
        "price",
    ]
    list_editable = [
        "quantity",
        "price",
    ]
    inlines = [MenuNutritionalValueInline, MenuItemImagesInline]
    actions = ["export_as_csv", "export_as_pdf"]


class LocationsInline(admin.TabularInline):
    model = Locations
    extra = 1


class OpenHoursInline(admin.TabularInline):
    model = OpenHours
    extra = 1


@admin.register(VendorShop)
class VendorShopAdmin(admin.ModelAdmin, ExportMixin):
    model = VendorShop
    list_per_page = 250
    empty_value_display = "-empty-"
    search_fields = ["name"]
    inlines = [VendorsEarningsInline, LocationsInline, OpenHoursInline]
    list_display = [
        "__str__",
        "name",
        "logo",
    ]
    list_editable = [
        "name",
        "logo",
    ]
    actions = ["export_as_csv", "export_as_pdf"]
