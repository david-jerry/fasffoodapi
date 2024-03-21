from django.conf import settings
from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework.routers import SimpleRouter

from chowapi.analytics.api.views import PageViewsViewSet
from chowapi.management.api.views import CompanyDetailsViewSet, DeliveryCityLocationsViewSet
from chowapi.monetize.api.views import CurrencyRatesViewSet
from chowapi.nutrition.api.views import NutritionListViewSet, NutritionStaffViewSet
from chowapi.users.api.views import (
    ActivityViewSet,
    CheckUserViewSet,
    UserViewSet,
    TokenRefreshViewset,
    PasswordResetViewset,
    PasswordResetConfirmViewset,
    PasswordChangeViewset,
    UserLoginViewset,
    LogoutViewset,
    RegisterViewset,
    RegisterVendorViewset,
    RegisterRiderViewset,
    VendorLoginViewset,
    VerifyEmailViewset,
    ResendEmailVerificationViewset,
    ResendOTPViewset,
    VerifyOTPViewset,
    email_confirm_redirect,
    password_reset_confirm_redirect,
)
from chowapi.vendors.api.views import VendorShopViewSet

router = DefaultRouter() if settings.DEBUG else SimpleRouter()


router.register("company/delivery-locations", DeliveryCityLocationsViewSet, basename="delivery_location")
router.register("company/infos", CompanyDetailsViewSet, basename="info")
router.register("analytics/page-views", PageViewsViewSet, basename="page-view-analytic")
router.register("currency/rates", CurrencyRatesViewSet, basename="rate")


router.register("vendors", VendorShopViewSet, basename="vendor")
router.register("nutritions/add-nutritions", NutritionStaffViewSet, basename="create_nutrition")
router.register("nutritions/list-nutritions", NutritionListViewSet, basename="list_nutrition")


router.register("auth/refresh-token", TokenRefreshViewset, basename="refresh_token")
router.register("auth/password/reset", PasswordResetViewset, basename="account_password_reset")
router.register("auth/password/confirm", PasswordResetConfirmViewset, basename="password_reset_confirm")
router.register("auth/password/change", PasswordChangeViewset, basename="account_password_change")
router.register("auth/login", UserLoginViewset, basename="login")
router.register("auth/vendor/login", VendorLoginViewset, basename="vendor_login")
router.register("auth/register/customer", RegisterViewset, basename="register_customer")
router.register("auth/register/vendor", RegisterVendorViewset, basename="register_vendor")
router.register("auth/register/rider", RegisterRiderViewset, basename="register_rider")
router.register("auth/email/resend-verification", ResendEmailVerificationViewset, basename="resend_email_verification")
router.register("auth/otp/resend-otp", ResendOTPViewset, basename="resend_otp")
router.register("auth/otp/verify", VerifyOTPViewset, basename="verify_otp")

router.register("validate", CheckUserViewSet)
router.register("activities", ActivityViewSet, basename="activity")
router.register("users", UserViewSet, basename="user")



app_name = "api"
urlpatterns = router.urls

urlpatterns += [
    path("auth/logout/", LogoutViewset.as_view(), name="account_logout"),
    path("auth/email/verify-email/", VerifyEmailViewset.as_view(), name="account_verify_email"),
    path("auth/email/account-confirm-email/<str:key>/", email_confirm_redirect, name="account_confirm_email"),
    path(
        "auth/password/reset/confirm/<str:uidb64>/<str:token>/",
        password_reset_confirm_redirect,
        name="password_reset_confirm",
    ),
    # path("auth/password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]
