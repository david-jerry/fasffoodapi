from decimal import Decimal
from django.utils.timezone import datetime, timedelta, now
from django.db.models import (
    CharField,
    EmailField,
    TimeField,
    SlugField,
    ManyToManyField,
    DateTimeField,
    TextField,
    IntegerField,
    DecimalField,
    FloatField,
    BooleanField,
    OneToOneField,
    DateField,
    ForeignKey,
    FileField,
    CASCADE,
    URLField,
)
from django.contrib.auth import get_user_model

from model_utils.models import TimeStampedModel
from chowapi.management.models import CompanyPercentageEarning
from chowapi.nutrition.models import Nutrition

from chowapi.users.models import User
from chowapi.utils.files import FILEUPLOAD
from chowapi.utils.validators import image_validate_file_extension



# Create your models here.
class VendorCategory(TimeStampedModel):
    name = CharField(max_length=255, blank=False, null=False, unique=True)

    class Meta:
        managed = True
        verbose_name = "Vendor Category"
        verbose_name_plural = "Vendor Categroies"

class VendorShop(TimeStampedModel):
    users = ManyToManyField(User, related_name="representatives")
    categories = ManyToManyField(VendorCategory, related_name="vendor_categories")
    slug = SlugField(blank=True)
    name = CharField(max_length=255, unique=True)
    phone = CharField(max_length=16, blank=False, null=True)
    email = EmailField(max_length=255, blank=True, null=True)
    website = URLField(max_length=500, blank=True, null=True)
    pin = CharField(max_length=6, null=True, blank=False)
    logo = FileField(
        upload_to=FILEUPLOAD.vendor_logo_image_upload_path,
        blank=True,
        null=True,
    )

    is_active = BooleanField(default=False)

    def set_pin(self, pin):
        self.pin = pin
        self.save(update_fields=['pin'])

    def check_pin(self, pin):
        return self.pin == pin

    def __str__(self) -> str:
        return self.name

    @property
    def logo_image(self):
        if self.logo is not None:
            return self.logo.url
        return None

    class Meta:
        managed = True
        verbose_name = "Vendor Store"
        verbose_name_plural = "Vendor Stores"


class Locations(TimeStampedModel):
    vendor = ForeignKey(VendorShop, on_delete=CASCADE, related_name="locations")
    address = CharField(max_length=255)
    longitude = CharField(max_length=50)
    latitude = CharField(max_length=50)

    def __str__(self) -> str:
        return f"{self.vendor.name} - {self.address}"

    class Meta:
        managed = True
        verbose_name = "Vendor Location"
        verbose_name_plural = "Vendor Locations"


class OpenHours(TimeStampedModel):
    vendor = ForeignKey(VendorShop, on_delete=CASCADE, related_name="open_hours")
    day = CharField(max_length=255)
    open = TimeField(auto_now=False, auto_now_add=False)
    close = TimeField(auto_now=False, auto_now_add=False)

    def __str__(self) -> str:
        return f"{self.vendor.name} opens: {self.open} and closes: {self.close} on {self.day}"

    class Meta:
        managed = True
        verbose_name = "Vendor Service Hour"
        verbose_name_plural = "Vendor Service Hours"


class MenuItems(TimeStampedModel):
    vendor = ForeignKey(VendorShop, on_delete=CASCADE, related_name="menu_items")
    name = CharField(max_length=255)
    unique_id = CharField(max_length=255, unique=True)
    description = TextField(max_length=420)
    quantity = IntegerField(default=0)
    price = DecimalField(
        max_digits=20,
        decimal_places=2,
        default=0.00,
        help_text="Currency is in USD. Set the value in USD and we would do the conversion to other currencies",
    )


    def __str__(self):
        return f"{self.name.title} from {self.vendor.name.title()}"

    class Meta:
        managed = True
        verbose_name = "Food Menu Item"
        verbose_name_plural = "Food Menu Items"


class MenuNutritionalValue(TimeStampedModel):
    menu_item = ForeignKey(MenuItems, on_delete=CASCADE, related_name="nutrition")
    nutrient = ForeignKey(Nutrition, on_delete=CASCADE, related_name="nutrition")
    calories = FloatField(default=0)

    def __str__(self) -> str:
        return f"{self.menu_item.name} contains {self.calories} or {self.nutrient.name}"

    class Meta:
        managed = True
        verbose_name = "Nutritional Value"
        verbose_name_plural = "Nutritional Values"


class MenuItemImages(TimeStampedModel):
    menu_item = ForeignKey(MenuItems, on_delete=CASCADE, related_name="menu_images")
    caption = CharField(max_length=255, blank=False, null=False)
    file = FileField(
        upload_to=FILEUPLOAD.food_image_upload_path,
        validators=[image_validate_file_extension],
        blank=True,
    )
    featured = BooleanField(default=False)

    @property
    def food_image_link(self):
        if self.file is not None:
            return self.file.url
        return None

    def __str__(self) -> str:
        return self.caption

    class Meta:
        managed = True
        verbose_name = "Food Image"
        verbose_name_plural = "Food Images"


class VendorsEarnings(TimeStampedModel):
    MONTHLY = 1
    QUARTERLY = 4
    YEARLY = 12
    TIMING = (
        ("MONTHLY", MONTHLY),
        ("QUARTERLY", QUARTERLY),
        ("YEARLY", YEARLY),
    )

    vendor = OneToOneField(VendorShop, on_delete=CASCADE, related_name="earning")
    balance = DecimalField(max_digits=20, decimal_places=2, default=0.00)
    payout = IntegerField(choices=TIMING, default=MONTHLY)
    payout_date = DateField(blank=True, null=True)

    def __str__(self):
        return f"{self.vendor.name.title()} Earning"

    def add_earning(self, amount: float):
        company = CompanyPercentageEarning.objects.first()
        if amount > 0:
            deducted_amount = amount * company.sales_charge_percentage
            amount -= deducted_amount
            self.balance += Decimal(amount)
            self.save(update_fields=["balance"])
            return amount
        else:
            raise ValueError("Invalid Amount")

    def withdraw_earning(self, amount: float):
        company = CompanyPercentageEarning.objects.first()
        if self.payout_date > datetime.today():
            if amount > 0 and self.balance >= Decimal(amount + company.withdrawal_charge):
                amount += company.withdrawal_charge
                self.balance -= Decimal(amount)
                self.payout_date = now.date() + timedelta(days=30 * self.payout)
                self.save(update_fields=["balance", "payout_date"])
                return amount
            else:
                raise ValueError("Insufficent Balance")
        else:
            raise ValueError("Not an approved time to withdraw")

    class Meta:
        managed = True
        verbose_name = "Vendor Earning"
        verbose_name_plural = "Vendor Earnings"


class MenuItemOrder(TimeStampedModel):
    user = ForeignKey(User, on_delete=CASCADE, related_name="user_order")
    delivery_lat = CharField(max_length=50, blank=True)
    delivery_lon = CharField(max_length=50, blank=True)
    delivery_address = CharField(max_length=500, blank=True)
    order_id = CharField(max_length=225, blank=True, unique=True, db_index=True)
    amount = DecimalField(max_digits=20, decimal_places=2, default=0.00)
    quantity = IntegerField(default=0, blank=True, null=True)
    paid = BooleanField(default=False)
    failed = BooleanField(default=False)

    def __str__(self) -> str:
        return f"{self.user.name} Order ID: {self.order_id}"

    class Meta:
        managed = True
        verbose_name = "Order"
        verbose_name_plural = "Orders"

class MenuItemOrderPickupLocations(TimeStampedModel):
    order = ForeignKey(MenuItemOrder, on_delete=CASCADE, related_name="order")
    meals = ForeignKey(MenuItems, on_delete=CASCADE, related_name="order_item")
    location = ForeignKey(Locations, on_delete=CASCADE, related_name="pickup_location")

    def __str__(self) -> str:
        return f"{self.order.user.name} Order ID: {self.order_id} - Pickup Location: {self.location.address}"

    class Meta:
        managed = True
        verbose_name = "Order Location"
        verbose_name_plural = "Order Locations"


class DeliveryDetails(TimeStampedModel):
    rider = ForeignKey(User, on_delete=CASCADE, related_name="rider_delivery_detail")
    order = OneToOneField(MenuItemOrder, on_delete=CASCADE, related_name="delivery_detail")
    eta = DateTimeField(auto_now=False, auto_now_add=False, null=True, blank=True) # in minutes
    distance_to_arrival = FloatField(default=1.0) # in km
    delivered = BooleanField(default=False)

    def __str__(self):
        return f"{self.rider.name} Delivering: {self.order.quantity} Items to {self.order.user.name} in {self.order.delivery_address} on {self.created.date()}."

    class Meta:
        managed = True
        verbose_name = "Delivery Detail"
        verbose_name_plural = "Deliveries Detail"



