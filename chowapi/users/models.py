from typing import ClassVar
import uuid

from django.contrib.sessions.models import Session
from django.contrib.auth.models import AbstractUser
from django.db.models import CharField, BooleanField, ForeignKey, CASCADE, URLField, UUIDField, FileField, OneToOneField, DateField
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.utils.html import mark_safe

from model_utils.models import TimeStampedModel

from chowapi.management.models import DeliveryCityLocations
from chowapi.users.managers import UserManager
from chowapi.utils.files import FILEUPLOAD
from chowapi.utils.validators import document_validate_file_extension, validate_phone_number_field


class User(AbstractUser):
    """
    Default custom user model for chowapi.
    If adding fields that need to be filled at user signup,
    check forms.SignupForm and forms.SocialSignupForms accordingly.
    """

    # First and last name do not cover name patterns around the globe
    first_name = None  # type: ignore[assignment]
    last_name = None  # type: ignore[assignment]

    unique_id = UUIDField(unique=True, db_index=True, default=uuid.uuid4, editable=False)
    name = CharField(_("Name of User"), blank=False, max_length=255)
    phone = CharField(_("Phone Number"), unique=True, max_length=16, blank=False, validators=[validate_phone_number_field])
    pin = CharField(_("pin"), max_length=6, null=False, blank=False)

    country = CharField(max_length=10, blank=True, null=True)
    ip_address = CharField(max_length=255, blank=True, null=True)
    currency = CharField(max_length=10, blank=True, null=True)

    is_vendor = BooleanField(default=False)
    is_customer = BooleanField(default=False)
    is_rider = BooleanField(default=False)

    USERNAME_FIELD = "phone"
    REQUIRED_FIELDS = ['name', "pin"]

    objects: ClassVar[UserManager] = UserManager()

    def set_pin(self, pin):
        self.pin = pin

    def check_pin(self, pin):
        return self.pin == pin

    def get_absolute_url(self) -> str:
        """Get URL for user's detail view.

        Returns:
            str: URL for user detail.

        """
        return reverse("users:detail", kwargs={"username": self.username})


class RiderParticulars(TimeStampedModel):
    BIKE = "MOTORCYCLE"
    CYCLE = "BICYCLE"
    LEGS = "WALKING"
    VEHICLE_CHOICES = [
        (BIKE, BIKE),
        (CYCLE, CYCLE),
        (LEGS, LEGS),
    ]

    user = OneToOneField(User, on_delete=CASCADE, related_name="rider_particular")
    delivery_location = ForeignKey(DeliveryCityLocations, on_delete=CASCADE, related_name="delivery_location", blank=True, null=True)
    id_number = CharField(max_length=25, blank=True)
    license = FileField(upload_to=FILEUPLOAD.static_image_upload_path, validators=[document_validate_file_extension], blank=True, null=True)
    vehicle_type = CharField(max_length=20, choices=VEHICLE_CHOICES, default=CYCLE)
    guarantor = CharField(max_length=255, blank=True)
    guarantor_phone = CharField(max_length=14, blank=True)
    guarantor_address = CharField(max_length=500, blank=True)
    guarantor_longitude = CharField(max_length=50, blank=True)
    guarantor_latitude = CharField(max_length=50, blank=True)
    on_a_request = BooleanField(default=False)
    validated = BooleanField(default=False)

    def image_tag(self):
        return mark_safe('<img src="%s" width="100px" height="100px" />'%(self.license.url))
    image_tag.short_description = 'License Image'

    @property
    def license_image(self):
        if self.license is not None:
            return self.license.url
        return None

    def __str__(self):
        return f"Rider particulars for {self.user}"

    class Meta:
        verbose_name = "Rider Particulars"
        verbose_name_plural = "Rider Particulars"

class SavedAddresses(TimeStampedModel):
    OFFICE = "OFFICE"
    RESIDENTIAL = "RESIDENTIAL"
    PARK = "PARK"
    HOTEL = "HOTEL"
    HOSPITAL = "HOSPITAL"

    ATYPE = (
        (OFFICE, OFFICE),
        (RESIDENTIAL, RESIDENTIAL),
        (PARK, PARK),
        (HOTEL, HOTEL),
        (HOSPITAL, HOSPITAL),
    )

    user = ForeignKey(User, on_delete=CASCADE, related_name="saved_addresses")
    address_type = CharField(max_length=50, choices=ATYPE, default=OFFICE)
    address = CharField(max_length=255)
    longitude = CharField(max_length=50)
    latitude = CharField(max_length=50)

    def __str__(self):
        return f"{self.user.name or self.user.email} Address: {self.address}"

    class Meta:
        managed = True
        verbose_name = "Saved Address"
        verbose_name_plural = "Saved Addresses"

class SaveDebitCards(TimeStampedModel):
    user = ForeignKey(User, on_delete=CASCADE, related_name="saved_cards")
    name = CharField(max_length=255, blank=False,null=False)
    card_number = CharField(max_length=24)
    expiry_date = DateField(auto_now_add=False)
    active = BooleanField(default=False)

    def __str__(self):
        return f"{self.user.name or self.user.email} Saved Card [****{self.card_number[-4:]}"

    class Meta:
        managed = True
        verbose_name = "Saved Card"
        verbose_name_plural = "Saved Cards"

class UserSessions(TimeStampedModel):
    user = ForeignKey(User, on_delete=CASCADE, related_name="sessions")
    session_key = CharField(max_length=255, null=True)
    ip_address = CharField(max_length=255, null=True)
    country_code = CharField(max_length=5, blank=True, null=True, db_index=True)
    continent_code = CharField(max_length=5, blank=True, null=True, db_index=True)
    region = CharField(max_length=225, blank=True, null=True)
    country_flag = URLField(max_length=1000, blank=True, null=True)
    uses_vpn = BooleanField(default=False)
    active = BooleanField(default=True)
    ended = BooleanField(default=False)

    def end_session(self):
        session_key = self.session_key
        try:
            Session.objects.get(pk=session_key)
            self.ended = True
            self.active = False
            self.save()
        except:
            pass
        return self.ended

    def __str__(self):
        return f"{self.user.name or self.user.email} Session"

    class Meta:
        managed = True
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"







class Activities(TimeStampedModel):
    LOGIN = "LOGIN"
    SIGNUP = "SINGUP"
    STATUS = (
        (LOGIN, LOGIN),
        (SIGNUP, SIGNUP)
    )
    identity = CharField(max_length=255)
    country = CharField(max_length=255)
    activity_type = CharField(max_length=8, choices=STATUS, default=SIGNUP)

    class Meta:
        managed = True
        verbose_name = "Activity"
        verbose_name_plural = "Activities"
