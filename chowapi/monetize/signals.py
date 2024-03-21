from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import get_object_or_404

from chowapi.monetize.models import BankAccount
from chowapi.users.models import User

from chowapi.utils.banking import get_bank_id
from chowapi.utils.paystack import PAYSTACK
from chowapi.vendors.models import VendorShop

@receiver(post_save, sender=BankAccount)
def create_user_relationship(sender, instance, created, **kwargs):
    if created:
        instance.bank_id = get_bank_id(instance.bank_name)
        instance.save()
        user_model = ContentType.objects.get_for_model(User)
        if instance.model == user_model:
            user = get_object_or_404(User, id=instance.model_object_id)
            PAYSTACK.create_rider_transfer_recipient(instance, user)
        else:
            vendor = get_object_or_404(VendorShop, id=instance.model_object_id)
            PAYSTACK.create_vendor_transfer_recipient(instance, vendor)
