from django.conf import settings
from django.contrib import admin
from django.contrib.auth import admin as auth_admin
from django.contrib.auth.decorators import login_required
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.contrib.auth.models import Group

from .forms import UserAdminCreationForm, PhonePinAdminAuthenticationForm, UserAdminChangeForm
from .models import User, Activities, RiderParticulars, SaveDebitCards, SavedAddresses, UserSessions
from chowapi.utils.mixins import ExportMixin

if settings.DJANGO_ADMIN_FORCE_ALLAUTH:
    # Force the `admin` sign in process to go through the `django-allauth` workflow:
    # https://docs.allauth.org/en/latest/common/admin.html#admin
    admin.site.login = login_required(admin.site.login)  # type: ignore[method-assign]

admin.site.register(Activities)

@admin.register(UserSessions)
class UserSessionsAdmin(admin.ModelAdmin, ExportMixin):
    model = UserSessions
    list_per_page = 250
    empty_value_display = "-empty-"
    list_filter = [
        "continent_code",
        "uses_vpn",
        'region'
    ]
    list_display = [
        "__str__",
        "session_key",
        "ip_address",
        "country_code",
        "continent_code",
        "region",
        "country_flag_image",
        "uses_vpn",
        "active",
        "ended",
    ]
    search_fields = [
        "ip_address",
    ]
    list_editable = [
        "active",
        "ended",
    ]
    actions = ["export_as_csv", "export_as_pdf"]

    def country_flag_image(self, obj):
        # Assuming you have a field named 'country_flag_link' in your model
        country_flag_link = obj.country_flag
        link = f"""<img src="{country_flag_link}" width="20" height="20" />"""
        return format_html(link)

    country_flag_image.short_description = 'Country Flag'

@admin.register(RiderParticulars)
class RiderParticularsAdmin(admin.ModelAdmin, ExportMixin):
    model = RiderParticulars
    list_per_page = 250
    empty_value_display = "-empty-"
    search_fields = [
        "id_number",
        "guarantor_phone",
    ]
    list_display = [
        "__str__",
        "user_link",
        "id_number",
        "delivery_location",
        "vehicle_type",
        "guarantor",
        "guarantor_phone",
        "guarantor_address",
        "guarantor_longitude",
        "guarantor_latitude",
        "validated",
    ]
    list_editable = [
        "id_number",
        "delivery_location",
        "vehicle_type",
        "guarantor",
        "guarantor_phone",
        "guarantor_address",
        "guarantor_longitude",
        "guarantor_latitude",
        "validated",
    ]


    def user_link(self, obj):
        url = f"/anjo-admin/users/user/{obj.user.id}/change"
        link = f"""<a href="{url}">{obj.user.name if obj.user.name else obj.user}</a>"""
        return format_html(link)

    user_link.short_description = 'User'

    actions = ["export_as_csv", "export_as_pdf"]


class SavedAddressesInline(admin.StackedInline):
    model = SavedAddresses
    extra = 1

class SaveDebitCardsInline(admin.StackedInline):
    model = SaveDebitCards
    extra = 1

@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm
    inlines = [SavedAddressesInline, SaveDebitCardsInline]
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Personal info"), {"fields": ("name", "phone", "email")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_customer",
                    "is_rider",
                    "is_vendor",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
    list_display = [
        "email",
        "name",
        "phone",
        "country",
        "ip_address",
        "currency",
        "is_active",
        "is_vendor",
        "is_rider",
        "is_staff",
        "is_superuser",
    ]
    search_fields = ["name", "phone"]
    list_filter = ["is_staff", "is_superuser", "is_active", "is_vendor", "is_rider", "is_customer", "country"]
    ordering = ["id"]
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            },
        ),
    )

admin.site.unregister(Group)
