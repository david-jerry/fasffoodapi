from __future__ import annotations

import typing

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.urls import reverse

from chowapi.utils.request_context import request_context

if typing.TYPE_CHECKING:
    from allauth.socialaccount.models import SocialLogin
    from django.http import HttpRequest

    from chowapi.users.models import User


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request: HttpRequest) -> bool:
        return getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", True)

    def get_email_confirmation_url(self, request, emailconfirmation):
        host = settings.HOSTNAME

        # Construct the full URL
        full_url = f"{host}/auth/confirm-email/"
        url = full_url + emailconfirmation.key
        return url

    def send_account_already_exists_mail(self, email):
        from allauth.utils import build_absolute_uri
        host = settings.HOSTNAME

        signup_url = f"{host}/auth/register/"
        password_reset_url = f"{host}/auth/reset-password/"

        ctx = {
            "request": request_context.request,
            "current_site": host,
            "email": email,
            "signup_url": signup_url,
            "password_reset_url": password_reset_url,
        }
        self.send_mail("account/email/account_already_exists", email, ctx)

class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(
        self,
        request: HttpRequest,
        sociallogin: SocialLogin,
    ) -> bool:
        return getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", True)

    def populate_user(
        self,
        request: HttpRequest,
        sociallogin: SocialLogin,
        data: dict[str, typing.Any],
    ) -> User:
        """
        Populates user information from social provider info.

        See: https://docs.allauth.org/en/latest/socialaccount/advanced.html#creating-and-populating-user-instances
        """
        user = super().populate_user(request, sociallogin, data)
        if not user.name:
            if name := data.get("name"):
                user.name = name
            elif first_name := data.get("first_name"):
                user.name = first_name
                if last_name := data.get("last_name"):
                    user.name += f" {last_name}"
        return user
