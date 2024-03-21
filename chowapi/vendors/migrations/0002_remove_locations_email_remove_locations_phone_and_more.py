# Generated by Django 4.2.11 on 2024-03-18 12:52

import chowapi.utils.files
import chowapi.utils.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vendors", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="locations",
            name="email",
        ),
        migrations.RemoveField(
            model_name="locations",
            name="phone",
        ),
        migrations.RemoveField(
            model_name="locations",
            name="website",
        ),
        migrations.AddField(
            model_name="vendorshop",
            name="email",
            field=models.EmailField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="vendorshop",
            name="phone",
            field=models.CharField(max_length=16, null=True),
        ),
        migrations.AddField(
            model_name="vendorshop",
            name="pin",
            field=models.CharField(max_length=6, null=True),
        ),
        migrations.AddField(
            model_name="vendorshop",
            name="website",
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name="menuitemimages",
            name="file",
            field=models.FileField(
                blank=True,
                upload_to=chowapi.utils.files.FileUploader.food_image_upload_path,
                validators=[chowapi.utils.validators.image_validate_file_extension],
            ),
        ),
        migrations.AlterField(
            model_name="vendorshop",
            name="logo",
            field=models.FileField(
                blank=True,
                null=True,
                upload_to=chowapi.utils.files.FileUploader.vendor_logo_image_upload_path,
            ),
        ),
    ]
