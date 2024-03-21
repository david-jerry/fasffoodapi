from allauth.account.forms import SignupForm
from allauth.socialaccount.forms import SignupForm as SocialSignupForm
from django import forms
from django.contrib.auth import forms as admin_forms
from django.utils.translation import gettext_lazy as _

from chowapi.utils.authentication_backend import PhonePinAuthBackend
from chowapi.utils.validators import validate_phone_number_field

from .models import User

from django.contrib.admin.forms import AdminAuthenticationForm

class PhonePinAdminAuthenticationForm(AdminAuthenticationForm):
    phone = forms.CharField(max_length=16)
    pin = forms.CharField(max_length=6, widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        phone = cleaned_data.get('phone')

        # Validate phone and pin here if needed
        validate_phone_number_field(phone)

        pin = cleaned_data.get('pin')
        if phone and pin:
            user = PhonePinAuthBackend().authenticate(request=None, phone=phone, pin=pin)
            if not user:
                raise forms.ValidationError("Invalid credentials.")
            cleaned_data['user'] = user

        return cleaned_data

class UserAdminChangeForm(admin_forms.UserChangeForm):
    class Meta(admin_forms.UserChangeForm.Meta):
        model = User


class UserAdminCreationForm(admin_forms.UserCreationForm):
    """
    Form for User Creation in the Admin Area.
    To change user signup, see UserSignupForm and UserSocialSignupForm.
    """

    class Meta(admin_forms.UserCreationForm.Meta):
        model = User
        error_messages = {
            "phone": {"unique": _("This phone has already been taken.")},
            "email": {"unique": _("This email has already been taken.")},
            "username": {"unique": _("This username has already been taken.")},
        }


class UserSignupForm(SignupForm):
    """
    Form that will be rendered on a user sign up section/screen.
    Default fields will be added automatically.
    Check UserSocialSignupForm for accounts created from social.
    """


class UserSocialSignupForm(SocialSignupForm):
    """
    Renders the form when user has signed up using social accounts.
    Default fields will be added automatically.
    See UserSignupForm otherwise.
    """
