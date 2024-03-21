from django.contrib.auth import get_user_model
from django.db.models.signals import post_save,pre_save
from django.dispatch import receiver
from django.utils.timezone import datetime as now
from django.contrib.contenttypes.models import ContentType

from chowapi.monetize.models import TransactionHistory
from chowapi.vendors.models import MenuItemOrder, MenuItems, VendorShop, VendorsEarnings

from chowapi.utils.logger import LOGGER
from chowapi.utils.unique_generators import order_id_generator, unique_slug_generator, unique_id_generator

today = now.today()
User = get_user_model()


@receiver(post_save, sender=VendorShop)
def create_vendor_slug(sender, instance, created, **kwargs):
    if created:
        VendorsEarnings.objects.create(vendor=instance)
        instance.slug = unique_slug_generator(instance)
        instance.save()
        LOGGER.info("""
VENDOR SLUG CREATED
-------------------
Successfully created a slug for the vendor object as well as the earning relationship
                    """)

@receiver(post_save, sender=MenuItems)
def create_menu_item_unique_id(sender, instance, created, **kwargs):
    if created:
        instance.unique_id = unique_id_generator(instance)
        instance.save(update_fields=['unique_id'])
        LOGGER.info("""
MENU ITEM CREATED
-------------------
Successfully created a menu item and attached a unique id
                    """)

@receiver(post_save, sender=MenuItemOrder)
def create_unique_order_id(sender, instance, created, **kwargs):
    user_model = ContentType.objects.get_for_model(User)
    vendor_model = ContentType.objects.get_for_model(VendorShop)
    if created:
        instance.order_id = order_id_generator(instance)
        instance.save(update_fields=['order_id'])
        TransactionHistory.objects.create(
            transaction_id=instance.order_id,
            status=TransactionHistory.PENDING,
            amount=instance.amount,
            model=user_model,
            model_object_id=instance.user.id,
        )
        TransactionHistory.objects.create(
            transaction_id=instance.order_id,
            status=TransactionHistory.PENDING,
            amount=instance.amount,
            model=vendor_model,
            model_object_id=instance.vendor.id,
        )
        LOGGER.info("""
MENU ITEM ORDER CREATED
-------------------
Successfully created an order and attached a unique order-id
                    """)

    if instance.paid:
        TransactionHistory.objects.filter(order_id=instance.order_id, model=user_model).update(status=TransactionHistory.COMPLETE)
        TransactionHistory.objects.filter(order_id=instance.order_id, model=vendor_model).update(status=TransactionHistory.COMPLETE)

    if instance.failed:
        TransactionHistory.objects.filter(order_id=instance.order_id, model=user_model).update(status=TransactionHistory.FAILED)
        TransactionHistory.objects.filter(order_id=instance.order_id, model=vendor_model).update(status=TransactionHistory.FAILED)


