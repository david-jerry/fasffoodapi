# Generated by Django 4.2.11 on 2024-03-16 13:08

import chowapi.utils.files
import chowapi.utils.validators
from django.db import migrations, models
import django.utils.timezone
import model_utils.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="CompanyDetails",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                (
                    "website_name",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                (
                    "website_logo",
                    models.FileField(
                        blank=True,
                        null=True,
                        upload_to=chowapi.utils.files.FileUploader.static_image_upload_path,
                        validators=[
                            chowapi.utils.validators.image_validate_file_extension
                        ],
                    ),
                ),
                ("support_email", models.URLField()),
                ("support_phone", models.CharField(max_length=14)),
                (
                    "short_description",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("brief_about", models.TextField(blank=True)),
                ("mission_statement", models.TextField(blank=True)),
            ],
            options={
                "verbose_name": "Website Detail",
                "verbose_name_plural": "Website Details",
                "managed": True,
            },
        ),
        migrations.CreateModel(
            name="CompanyPercentageEarning",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                ("sales_charge_percentage", models.FloatField(default=0.05)),
                ("cost_per_km", models.FloatField(default=75.0)),
                ("withdrawal_charge", models.FloatField(default=25.0)),
            ],
            options={
                "verbose_name": "Default Setting",
                "verbose_name_plural": "Default Settings",
                "managed": True,
            },
        ),
        migrations.CreateModel(
            name="DeliveryCityLocations",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="created",
                    ),
                ),
                (
                    "modified",
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name="modified",
                    ),
                ),
                ("name", models.CharField(max_length=255)),
            ],
            options={
                "verbose_name": "Delivery City",
                "verbose_name_plural": "Delivery Cities",
                "managed": True,
            },
        ),
    ]
