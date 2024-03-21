from django.db.models import (
    CharField,
    BooleanField,
    EmailField,
    FloatField,
    TextField,
    FileField,
    URLField,
)
from model_utils.models import TimeStampedModel

from chowapi.utils.files import FILEUPLOAD
from chowapi.utils.validators import image_validate_file_extension



# Create your models here.
class CompanyDetails(TimeStampedModel):
    website_name = CharField(max_length=255, blank=True, null=True)
    website_logo = FileField(upload_to=FILEUPLOAD.static_image_upload_path, validators=[image_validate_file_extension], blank=True, null=True)
    support_email = URLField()
    support_phone = CharField(max_length=14, blank=False)
    short_description = CharField(max_length=255, blank=True, null=True)
    brief_about = TextField(blank=True)
    mission_statement = TextField(blank=True)

    def __str__(self) -> str:
        return self.website_name

    class Meta:
        managed = True
        verbose_name = "Website Detail"
        verbose_name_plural = "Website Details"

class CompanyPercentageEarning(TimeStampedModel):
    sales_charge_percentage = FloatField(default=0.05)
    cost_per_km = FloatField(default=75.00)
    withdrawal_charge = FloatField(default=25.00)

    def __str__(self) -> str:
        return "Percentage"

    class Meta:
        managed = True
        verbose_name = "Default Setting"
        verbose_name_plural = "Default Settings"


class DeliveryCityLocations(TimeStampedModel):
    name = CharField(max_length=255, blank=False)

    def __str__(self):
        return self.name

    class Meta:
        managed=True
        verbose_name = "Delivery City"
        verbose_name_plural = "Delivery Cities"

