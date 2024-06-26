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
            name="Nutrition",
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
                ("name", models.CharField(max_length=255, unique=True)),
                ("slug", models.SlugField(max_length=500)),
                (
                    "icon",
                    models.FileField(
                        blank=True,
                        null=True,
                        upload_to=chowapi.utils.files.FileUploader.food_image_upload_path,
                        validators=[
                            chowapi.utils.validators.image_validate_file_extension
                        ],
                    ),
                ),
                (
                    "description",
                    models.TextField(
                        help_text="Must be a within 1000 characters", max_length=1000
                    ),
                ),
            ],
            options={
                "verbose_name": "Nutrition",
                "verbose_name_plural": "Nutritions",
                "managed": True,
            },
        ),
    ]
