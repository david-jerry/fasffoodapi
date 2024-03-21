from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm, PasswordResetForm
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _

from chowapi.users.api.forms import CustomAuthPasswordResetForm
from chowapi.utils.authentication_backend import PhonePinAuthBackend, VendorAuthBackend
from chowapi.utils.geolocation import CoordinateUtils
from chowapi.utils.otp import OtpManager
from chowapi.utils.validators import serializer_validate_phone, validate_credit_card
from chowapi.vendors.api.serializers import (
    VendorCategorySerializer,
    VendorShopSerializer,
)
from chowapi.vendors.models import VendorCategory, VendorShop

try:
    from allauth.account import app_settings as allauth_account_settings
    from allauth.socialaccount.models import EmailAddress
except ImportError:
    raise ImportError("allauth needs to be added to INSTALLED_APPS.")

from rest_framework import exceptions, serializers
from rest_framework.exceptions import ValidationError

if "allauth" in settings.INSTALLED_APPS:
    from dj_rest_auth.app_settings import api_settings

from dj_rest_auth.models import TokenModel


from thefuzz import fuzz


from chowapi.users.models import (
    Activities,
    RiderParticulars,
    SaveDebitCards,
    SavedAddresses,
    User,
)

User = get_user_model()
UserModel = get_user_model()


class VerifyEmailSerializer(serializers.Serializer):
    key = serializers.CharField(write_only=True)


class ResendEmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=allauth_account_settings.EMAIL_REQUIRED)


class ResendOTPSerializer(serializers.Serializer):
    phone = serializers.CharField(required=True)


class RegisterSerializer(serializers.Serializer):
    name = serializers.CharField(
        max_length=255,
        required=True,
    )
    phone = serializers.CharField(required=True, allow_blank=False)
    pin = serializers.CharField(style={"input_type": "password"})

    def validate_pin(self, pin):
        if len(pin) < 4 and len(pin) > 6:
            msg = _("Incorrect pin.")
            raise exceptions.ValidationError(msg)
        return pin

    def validate_phone(self, phone):
        if User.objects.filter(phone=phone).exists():
            raise serializers.ValidationError(
                _(
                    "Another user with this phone number is already registered on the platform"
                )
            )

        serializer_validate_phone(self, phone, serializers)

        return phone

    def validate_name(self, name):
        if len(name) < 1:
            raise serializers.ValidationError(_("This is a required field"))

        if len(name) < 5:
            raise serializers.ValidationError(
                _("Your name must include surname and be greater than 5 characters")
            )

        if "@" in name:
            raise serializers.ValidationError(_("Invalid Character in Name"))
        return name

    def get_cleaned_data(self):
        return {
            "pin": self.validated_data.get("pin", ""),
            "name": self.validated_data.get("name", ""),
            "phone": self.validated_data.get("phone", ""),
        }

    def save(self, request):
        self.cleaned_data = self.get_cleaned_data()
        if User.objects.filter(phone=self.cleaned_data["phone"]).exists():
            raise serializers.ValidationError(
                _("Another user already registered with this exact credentials")
            )

        user = User.objects.create(
            username=self.cleaned_data["phone"], is_customer=True, **self.cleaned_data
        )
        OtpManager.assign_otp(user)
        return user


class RegisterVendorSerializer(serializers.Serializer):
    name = serializers.CharField(
        max_length=255,
        required=True,
    )
    phone = serializers.CharField(required=True, allow_blank=False)
    email = serializers.CharField(required=True, allow_blank=False)
    pin = serializers.CharField(style={"input_type": "tel"})

    vendor = VendorShopSerializer()
    vendor_categories = VendorCategorySerializer(many=True)

    def validate_pin(self, pin):
        if len(pin) < 4 and len(pin) > 6:
            msg = _("Incorrect pin.")
            raise exceptions.ValidationError(msg)
        return pin

    def validate_phone(self, phone):
        if User.objects.filter(phone=phone).exists():
            raise serializers.ValidationError(
                _(
                    "Another user with this phone number is already registered on the platform"
                )
            )

        serializer_validate_phone(self, phone, serializers)

        return phone

    def validate_name(self, name):
        if len(name) < 1:
            raise serializers.ValidationError(_("This is a required field"))

        if len(name) < 5:
            raise serializers.ValidationError(
                _("Your name must include surname and be greater than 5 characters")
            )

        if "@" in name:
            raise serializers.ValidationError(_("Invalid Character in Name"))
        return name

    def get_cleaned_data(self):
        return {
            "pin": self.validated_data.get("pin", ""),
            "name": self.validated_data.get("name", ""),
            "phone": self.validated_data.get("phone", ""),
            "email": self.validated_data.get("email", ""),
            "vendor": self.validated_data.get("vendor", ""),
            "vendor_categories": self.validated_data.get("vendor_categories", ""),
        }

    def save(self, request):
        self.cleaned_data = self.get_cleaned_data()
        vendor_data = self.cleaned_data.pop('vendor')
        categories_data = self.cleaned_data.pop('vendor_categories')

        # Create or get the user
        if User.objects.filter(phone=self.cleaned_data["phone"]).exists():
            raise serializers.ValidationError(
                _("Another user already registered with this exact credentials")
            )

        if VendorShop.objects.filter(phone=vendor_data.get('phone')).exists():
            raise serializers.ValidationError(
                _("Another vendor already registered with this exact credentials")
            )

        user = User.objects.create(
            username=self.cleaned_data["phone"],
            is_vendor=True,
            is_customer=True,
            **self.cleaned_data,
        )

        categories = [VendorCategory.objects.get_or_create(name=category['name'], default={'name':category['name']}) for category in categories_data]

        vendor = VendorShop.objects.create(is_active=True, **vendor_data)
        vendor.users.add(user)
        vendor.categories.set(categories)

        # Assign OTP
        OtpManager.assign_otp(user)
        return user


class RegisterRiderSerializer(serializers.Serializer):
    name = serializers.CharField(
        max_length=255,
        required=True,
    )
    phone = serializers.CharField(required=True, allow_blank=False)
    pin = serializers.CharField(style={"input_type": "password"})

    def validate_pin(self, pin):
        if len(pin) < 4 and len(pin) > 6:
            msg = _("Incorrect pin.")
            raise exceptions.ValidationError(msg)
        return pin

    def validate_phone(self, phone):
        if User.objects.filter(phone=phone).exists():
            raise serializers.ValidationError(
                _(
                    "Another user with this phone number is already registered on the platform"
                )
            )

        serializer_validate_phone(self, phone, serializers)

        return phone

    def validate_name(self, name):
        if len(name) < 1:
            raise serializers.ValidationError(_("This is a required field"))

        if len(name) < 5:
            raise serializers.ValidationError(
                _("Your name must include surname and be greater than 5 characters")
            )

        if "@" in name:
            raise serializers.ValidationError(_("Invalid Character in Name"))
        return name

    def get_cleaned_data(self):
        return {
            "pin": self.validated_data.get("pin", ""),
            "name": self.validated_data.get("name", ""),
            "phone": self.validated_data.get("phone", ""),
        }

    def save(self, request):
        self.cleaned_data = self.get_cleaned_data()
        if User.objects.filter(phone=self.cleaned_data["phone"]).exists():
            raise serializers.ValidationError(
                _("Another user already registered with this exact credentials")
            )

        user = User.objects.create(
            username=self.cleaned_data["phone"], is_rider=True, **self.cleaned_data
        )
        OtpManager.assign_otp(user)
        return user


class VerifyOTPSerializer(serializers.Serializer):
    pin = serializers.CharField()

    def validate_pin(self, pin):
        if len(pin) < 4 and len(pin) > 6:
            msg = _("Incorrect pin.")
            raise exceptions.ValidationError(msg)
        return pin

    def get_cleaned_data(self):
        return {
            "pin": self.validated_data.get("pin", ""),
        }

    def save(self, request):
        self.cleaned_data = self.get_cleaned_data()
        user = OtpManager.verify_otp(self.cleaned_data("pin"))
        if not user:
            msg = _("Unable to verify otp. Expired or Invalid")
            raise exceptions.ValidationError(msg)
        return user


class LoginSerializer(serializers.Serializer):
    phone = serializers.CharField(required=True, allow_blank=False)
    pin = serializers.CharField(style={"input_type": "password"})

    def get_auth_user(self, phone, pin):
        """
        Retrieve the auth user from given POST payload by using phone number and pin.
        Returns the authenticated user instance if credentials are correct,
        else `None` will be returned.
        """
        user = PhonePinAuthBackend().authenticate(
            request=self.context["request"], phone=phone, pin=pin
        )
        return user

    @staticmethod
    def validate_auth_user_status(user):
        if not user.is_active:
            msg = _("User account is disabled.")
            raise exceptions.ValidationError(msg)
        return user

    # @staticmethod
    # def validate_pin(self, pin):
    #     user = self.context['request'].user
    #     if not user.check_pin(pin):
    #         msg = _("Incorrect pin.")
    #         raise exceptions.ValidationError(msg)
    #     return pin

    def validate(self, attrs):
        phone = attrs.get("phone")
        pin = attrs.get("pin")
        user = self.get_auth_user(phone, pin)

        if not user.check_pin(pin):
            msg = _("Incorrect pin.")
            raise exceptions.ValidationError(msg)

        if not user:
            msg = _("Unable to log in with provided credentials.")
            raise exceptions.ValidationError(msg)

        # Did we get back an active user?
        self.validate_auth_user_status(user)

        attrs["user"] = user
        return attrs


class LoginVendorSerializer(serializers.Serializer):
    phone = serializers.CharField(required=True, allow_blank=False)
    pin = serializers.CharField(style={"input_type": "password"})

    def get_auth_user(self, phone, pin):
        """
        Retrieve the auth user from given POST payload by using phone number and pin.
        Returns the authenticated user instance if credentials are correct,
        else `None` will be returned.
        """
        user = VendorAuthBackend().authenticate(
            request=self.context["request"], phone=phone, pin=pin
        )
        return user

    @staticmethod
    def validate_auth_user_status(vendor):
        if not vendor.is_active:
            msg = _("Vendor account is disabled.")
            raise exceptions.ValidationError(msg)
        return vendor

    # @staticmethod
    # def validate_pin(self, pin):
    #     user = self.context['request'].user
    #     if not user.check_pin(pin):
    #         msg = _("Incorrect pin.")
    #         raise exceptions.ValidationError(msg)
    #     return pin

    def validate(self, attrs):
        phone = attrs.get("phone")
        pin = attrs.get("pin")
        user = self.get_auth_user(phone, pin)

        if not user.check_pin(pin):
            msg = _("Incorrect pin.")
            raise exceptions.ValidationError(msg)

        if not user:
            msg = _("Unable to log in with provided credentials.")
            raise exceptions.ValidationError(msg)

        # Did we get back an active user?
        self.validate_auth_user_status(user)

        attrs["user"] = user
        return attrs


class TokenSerializer(serializers.ModelSerializer):
    """
    Serializer for Token model.
    """

    class Meta:
        model = TokenModel
        fields = ("key",)


class JWTSerializer(serializers.Serializer):
    """
    Serializer for JWT authentication.
    """

    access = serializers.CharField()
    refresh = serializers.CharField()
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
        """
        Required to allow using custom USER_DETAILS_SERIALIZER in
        JWTSerializer. Defining it here to avoid circular imports
        """
        JWTUserDetailsSerializer = api_settings.USER_DETAILS_SERIALIZER

        user_data = JWTUserDetailsSerializer(obj["user"], context=self.context).data
        return user_data


class JWTSerializerWithExpiration(JWTSerializer):
    """
    Serializer for JWT authentication with expiration times.
    """

    access_expiration = serializers.DateTimeField()
    refresh_expiration = serializers.DateTimeField()


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """

    email = serializers.EmailField()

    reset_form = None

    @property
    def password_reset_form_class(self):
        if "allauth" in settings.INSTALLED_APPS:
            return CustomAuthPasswordResetForm
        else:
            return PasswordResetForm

    def get_email_options(self):
        """Override this method to change default e-mail options"""
        return {}

    def validate_email(self, value):
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)

        return value

    def save(self):
        if "allauth" in settings.INSTALLED_APPS:
            from allauth.account.forms import default_token_generator
        else:
            from django.contrib.auth.tokens import default_token_generator

        request = self.context.get("request")
        # Set some values to trigger the send_email method.
        opts = {
            "use_https": request.is_secure(),
            "from_email": getattr(settings, "DEFAULT_FROM_EMAIL"),
            "request": request,
            "token_generator": default_token_generator,
        }

        opts.update(self.get_email_options())
        self.reset_form.save(**opts)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming a password reset attempt.
    """

    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    set_password_form_class = SetPasswordForm

    _errors = {}
    user = None
    set_password_form = None

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        if "allauth" in settings.INSTALLED_APPS:
            from allauth.account.forms import default_token_generator
            from allauth.account.utils import url_str_to_user_pk as uid_decoder
        else:
            from django.contrib.auth.tokens import default_token_generator
            from django.utils.http import urlsafe_base64_decode as uid_decoder

        # Decode the uidb64 (allauth use base36) to uid to get User object
        try:
            uid = force_str(uid_decoder(attrs["uid"]))
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise ValidationError({"uid": [_("Invalid value")]})

        if not default_token_generator.check_token(self.user, attrs["token"]):
            raise ValidationError({"token": [_("Invalid value")]})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user,
            data=attrs,
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)

        return attrs

    def save(self):
        return self.set_password_form.save()


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    set_password_form = None

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = api_settings.OLD_PASSWORD_FIELD_ENABLED
        self.logout_on_password_change = api_settings.LOGOUT_ON_PASSWORD_CHANGE
        super().__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop("old_password")

        self.request = self.context.get("request")
        self.user = getattr(self.request, "user", None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value),
        )

        if all(invalid_password_conditions):
            err_msg = _(
                "Your old password was entered incorrectly. Please enter it again."
            )
            raise serializers.ValidationError(err_msg)
        return value

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(
            user=self.user,
            data=attrs,
        )

        self.custom_validation(attrs)
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        self.set_password_form.save()
        if not self.logout_on_password_change:
            from django.contrib.auth import update_session_auth_hash

            update_session_auth_hash(self.request, self.user)


class RiderSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiderParticulars
        fields = [
            "id",
            "user",
            "delivery_location",
            "id_number",
            "license",
            "vehicle_type",
            "guarantor",
            "guarantor_phone",
            "guarantor_address",
            "guarantor_longitude",
            "guarantor_latitude",
            "on_a_request",
            "validated",
            "url",
        ]
        read_only_fields = [
            "guarantor_longitude",
            "guarantor_latitude",
            "on_a_request",
            "validated",
        ]
        extra_kwargs = {
            "url": {"view_name": "api:rider-detail", "lookup_field": "pk"},
        }

    def validate_guarantor_address(self, value):
        """
        Validate the address field,
        Add the longitude ad latitude to the model fields
        """
        if CoordinateUtils.get_coordinates(value) is None:
            raise serializers.ValidationError(
                "Invalid address. Please provide a valid address so we can get your accurate coordinates."
            )
        return value

    def validate_vehicle_type(self, value):
        """
        Validate the vehicle_type field.
        Ensure it only accepts valid choices: "bicycle," "autobike," or "walking."
        """
        valid_choices = [
            RiderParticulars.BIKE,
            RiderParticulars.CYCLE,
            RiderParticulars.LEGS,
        ]
        if value not in valid_choices:
            raise serializers.ValidationError(
                f"Invalid vehicle type. Choose from: {', '.join(valid_choices)}"
            )
        return value

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)

        longitude, latitude = CoordinateUtils.get_coordinates(
            instance.guarantor_address
        )
        instance.guarantor_longitude = longitude
        instance.guarantor_latitude = latitude
        instance.save(update_fields=["guarantor_longitude", "guarantor_latitude"])

        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["user"] = (
            instance.user.name
        )  # Replace 'name' with the actual field in your User model
        representation["delivery_location"] = instance.delivery_location.name
        return representation


class SavedAddressesSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedAddresses
        fields = [
            "user",
            "address",
            "address_type",
            "longitude",
            "latitude",
        ]

    def validate_address(self, value):
        """
        Validate the address field,
        Add the longitude ad latitude to the model fields
        """
        if CoordinateUtils.get_coordinates(value) is None:
            raise serializers.ValidationError(
                "Invalid address. Please provide a valid address so we can get your accurate coordinates."
            )
        return value

    def create(self, validated_data):
        """
        Custom create method to associate the authenticated user with the record.
        """
        user = self.context["request"].user
        validated_data["user"] = user
        return super().create(validated_data)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["user"] = (
            instance.user.name
        )  # Replace 'name' with the actual field in your User model
        return representation


class SaveDebitCardsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaveDebitCards
        fields = [
            "id",
            "user",
            "name",
            "card_number",
            "expiry_date",
        ]

    def validate_name(self, value):
        """
        Validate the name field by checking if it matches the authenticated user's name (case-insensitive).
        """
        user = self.context["request"].user
        if user.name:
            similarity_ratio = fuzz.ratio(value.lower(), user.name.lower())

            # Adjust the threshold as needed
            if similarity_ratio < 80:
                raise serializers.ValidationError(
                    "Name must be a close match to the authenticated user's name."
                )
        return value

    def validate_card_number(self, value):
        validate_credit_card(value, serializers)

    def create(self, validated_data):
        """
        Custom create method to associate the authenticated user with the record.
        """
        user = self.context["request"].user
        validated_data["user"] = user
        return super().create(validated_data)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["user"] = (
            instance.user.name
        )  # Replace 'name' with the actual field in your User model
        return representation


class UserSerializer(serializers.ModelSerializer[User]):
    saved_address = SavedAddressesSerializer(many=True, read_only=True)
    saved_cards = SaveDebitCardsSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "name",
            "phone",
            "pin",
            "unique_id",
            "country",
            "saved_address",
            "saved_cards",
            "ip_address",
            "currency",
            "is_vendor",
            "is_customer",
            "is_rider",
            "url",
        ]

        read_only_fields = [
            "country",
            "ip_address",
            "is_vendor",
            "is_customer",
            "is_rider",
        ]

        extra_kwargs = {
            "url": {"view_name": "api:user-detail", "lookup_field": "unique_id"},
        }

    def validate_pin(self, pin):
        if len(pin) < 4 and len(pin) > 6:
            msg = _("Incorrect pin.")
            raise exceptions.ValidationError(msg)
        return pin

    def validate_email(self, email):
        instance = self.context["request"].user

        if User.objects.exclude(id=instance.id).filter(email=email).exists():
            raise serializers.ValidationError(
                _(
                    "Another user with this email address is already registered on the platform"
                )
            )
        return email

    def validate_phone(self, phone):
        serializer_validate_phone(self, phone, serializers)

        instance = self.context["request"].user

        if User.objects.exclude(id=instance.id).filter(phone=phone).exists():
            raise serializers.ValidationError(
                _(
                    "Another user with this phone number is already registered on the platform"
                )
            )
        return phone

    def validate_name(self, name):
        if len(name) < 0:
            raise serializers.ValidationError(_("This is a required field"))

        if "@" in name:
            raise serializers.ValidationError(_("Invalid Character in Name"))
        return name

    def update(self, instance, validated_data):
        request = self.context["request"]

        if (
            instance.is_rider
            and not RiderParticulars.objects.filter(user=instance).exists()
        ):
            RiderParticulars.objects.create(user=instance)

        instance.pin = validated_data.get("pin", instance.pin)

        if "phone" in validated_data:
            instance.phone = validated_data.get("phone", instance.phone)
            OtpManager.assign_otp(instance)

        if "email" in validated_data:
            email = EmailAddress.objects.create(user=instance, email=instance.email)
            email.send_confirmation(self.context["request"])
            instance.email = validated_data.get("email", instance.email)

        instance.country = request.country_code
        instance.ip_address = request.ip
        instance.currency = validated_data.get(
            "currency", request.currency_native_short
        )
        instance.name = validated_data.get("name", instance.name)
        instance.save()
        return instance


class ActivitiesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Activities
        fields = ["id", "identity", "country", "activity_type", "created"]


class CordinateLocationSerializer(serializers.Serializer):
    longitude = serializers.FloatField()
    latitude = serializers.FloatField()
