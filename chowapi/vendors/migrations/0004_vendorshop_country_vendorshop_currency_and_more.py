# Generated by Django 4.2.11 on 2024-03-18 14:12

import chowapi.utils.files
import chowapi.utils.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vendors", "0003_vendorshop_is_active_alter_menuitemimages_file_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="vendorshop",
            name="country",
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
        migrations.AddField(
            model_name="vendorshop",
            name="currency",
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
        migrations.AddField(
            model_name="vendorshop",
            name="ip_address",
            field=models.CharField(blank=True, max_length=255, null=True),
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
