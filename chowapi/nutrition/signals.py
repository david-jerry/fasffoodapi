from django.db.models.signals import post_save
from django.dispatch import receiver

from chowapi.nutrition.models import Nutrition
from chowapi.utils.logger import LOGGER
from chowapi.utils.unique_generators import unique_slug_generator

@receiver(post_save, sender=Nutrition)
def create_nutrition_slug(sender, instance, created, **kwargs):
    if created:
        instance.slug = unique_slug_generator(instance)
        instance.save(update_fields=['slug'])
        LOGGER.info("""
NUTRITION SLUG CREATED
-------------------
Successfully created a slug for the nutrition object
                    """)


