from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import AppViewed, PageViews, ReviewRating


class AppViewedAdmin(admin.ModelAdmin):
    list_display = (
        "__str__",
        "model",
        "ip_address",
        "country_code",
        "continent_code",
        "region",
        "country_flag",
        "uses_vpn",
        "created",
    )
    list_filter = ("region", "country_code", "uses_vpn")
    search_fields = ("ip_address",)  # You can add more editable fields if needed


class ReviewRatingAdmin(admin.ModelAdmin):
    list_display = (
        "__str__",
        "user",
        "model",
        "rating",
        "review_text",
        "created",
    )
    list_filter = ("rating",)
    search_fields = ("user__username", "model__name")  # Assuming 'username' is a field in User


class PageViewAdmin(admin.ModelAdmin):
    list_display = (
        "__str__",
        "ip_address",
        "country_code",
        "continent_code",
        "region",
        "country_flag",
        "uses_vpn",
        "last_visited_date",
        "new_visit_date",
        "created",
    )
    list_filter = ("region", "country_code", "uses_vpn")
    search_fields = ("ip_address",)  # Assuming 'username' is a field in User

admin.site.register(AppViewed, AppViewedAdmin)
admin.site.register(ReviewRating, ReviewRatingAdmin)
admin.site.register(PageViews, PageViewAdmin)
