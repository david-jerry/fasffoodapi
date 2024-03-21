from django.db.models import (
    CharField,
    SlugField,
    TextField,
    FileField,
)

from model_utils.models import TimeStampedModel

from chowapi.utils.validators import image_validate_file_extension
from chowapi.utils.files import FILEUPLOAD

class Nutrition(TimeStampedModel):
    name = CharField(max_length=255, blank=False, unique=True)
    slug = SlugField(db_index=True, max_length=500)
    icon = FileField(upload_to=FILEUPLOAD.food_image_upload_path, validators=[image_validate_file_extension], blank=True, null=True)
    description = TextField(max_length=1000, help_text="Must be a within 1000 characters")

    @property
    def food_icon_image(self):
        if self.icon is not None:
            return self.icon.url
        return None

    def __str__(self):
        return self.name

    class Meta:
        managed = True
        verbose_name = "Nutrition"
        verbose_name_plural = "Nutritions"
