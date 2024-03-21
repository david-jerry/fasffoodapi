from django.db.models import CharField, OneToOneField, CASCADE, BooleanField

from model_utils.models import TimeStampedModel

from chowapi.users.models import User
from chowapi.vendors.models import VendorShop


class OTPs(TimeStampedModel):
    user = OneToOneField(User, on_delete=CASCADE, related_name='otp')
    otp = CharField(max_length=7, db_index=True)
    expired = BooleanField(default=False)

    def __str__(self):
        return f"{self.user.name.title()} OTP: {self.otp}"

    class Meta:
        pass


class VendorOTPs(TimeStampedModel):
    user = OneToOneField(VendorShop, on_delete=CASCADE, related_name='otp')
    otp = CharField(max_length=7, db_index=True)
    expired = BooleanField(default=False)

    def __str__(self):
        return f"{self.user.name.title()} OTP: {self.otp}"

    class Meta:
        pass

