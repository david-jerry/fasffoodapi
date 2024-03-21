from typing import TYPE_CHECKING

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import UserManager as DjangoUserManager

if TYPE_CHECKING:
    from chowapi.users.models import User  # noqa: F401


class UserManager(DjangoUserManager["User"]):
    """Custom manager for the User model."""

    def _create_user(self, phone: str, pin: str | None, password: str | None, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not phone:
            raise ValueError("The given phone number must be set")
        user = self.model(phone=phone, **extra_fields)
        user.set_pin(pin)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, phone: str, pin: str | None = None, password: str | None = None,  **extra_fields):  # type: ignore[override]
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_vendor", False)
        extra_fields.setdefault('is_customer', True)
        return self._create_user(phone, pin, password, **extra_fields)

    def create_vendor(self, phone: str, pin: str | None = None, password: str | None = None, **extra_fields):  # type: ignore[override]
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_rider", False)
        extra_fields.setdefault("is_vendor", True)
        extra_fields.setdefault('is_customer', False)
        return self._create_user(phone, pin, password, **extra_fields)

    def create_rider(self, phone: str, pin: str | None = None, password: str | None = None, **extra_fields):  # type: ignore[override]
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_vendor", False)
        extra_fields.setdefault("is_rider", True)
        extra_fields.setdefault('is_customer', False)
        return self._create_user(phone, pin, password, **extra_fields)

    def create_superuser(self, phone: str, pin: str | None = None, password: str | None = None, **extra_fields):  # type: ignore[override]
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_rider", True)
        extra_fields.setdefault("is_vendor", True)
        extra_fields.setdefault('is_customer', True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        if extra_fields.get("is_vendor") is not True:
            raise ValueError("Superuser must have is_vendor=True.")
        if extra_fields.get("is_rider") is not True:
            raise ValueError("Superuser must have is_rider=True.")
        if extra_fields.get("is_customer") is not True:
            raise ValueError("Superuser must have is_customer=True.")

        return self._create_user(phone, pin, password, **extra_fields)
