# Generated by Django 4.2.11 on 2024-03-18 14:14

import chowapi.utils.files
import chowapi.utils.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0004_alter_companydetails_website_logo"),
    ]

    operations = [
        migrations.AlterField(
            model_name="companydetails",
            name="website_logo",
            field=models.FileField(
                blank=True,
                null=True,
                upload_to=chowapi.utils.files.FileUploader.static_image_upload_path,
                validators=[chowapi.utils.validators.image_validate_file_extension],
            ),
        ),
    ]
