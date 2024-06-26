# Generated by Django 4.2.11 on 2024-03-18 14:12

import chowapi.utils.files
import chowapi.utils.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("nutrition", "0003_alter_nutrition_icon"),
    ]

    operations = [
        migrations.AlterField(
            model_name="nutrition",
            name="icon",
            field=models.FileField(
                blank=True,
                null=True,
                upload_to=chowapi.utils.files.FileUploader.food_image_upload_path,
                validators=[chowapi.utils.validators.image_validate_file_extension],
            ),
        ),
    ]
