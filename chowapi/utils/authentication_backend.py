from django.contrib.auth.backends import BaseBackend
# from django.contrib.auth.backends import ModelBackend

from chowapi.users.models import User
from chowapi.vendors.models import VendorShop

class PhonePinAuthBackend(BaseBackend):
    def authenticate(self, request, phone=None, pin=None, **kwargs):
        if phone is None or pin is None:
            return None

        try:
            user = User.objects.get(phone=phone)
            if user.check_pin(pin) and self.user_can_authenticate(user):
                return user
        except User.DoesNotExist:
            pass

        return None

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        return getattr(user, "is_active", True)


class VendorAuthBackend(BaseBackend):
    def authenticate(self, request, phone=None, pin=None, **kwargs):
        if phone is None or pin is None:
            return None

        try:
            user = VendorShop.objects.get(phone=phone)
            if user.check_pin(pin) and self.user_can_authenticate(user):
                return user
        except User.DoesNotExist:
            pass

        return None

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        return getattr(user, "is_active", True)



