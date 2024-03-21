import re
from django.contrib.auth import get_user_model

from rest_framework import serializers
from chowapi.users.models import RiderParticulars
from chowapi.utils.geolocation import CoordinateUtils
from chowapi.utils.logger import LOGGER
from chowapi.utils.converters import convert_amount

from chowapi.vendors.models import (
    DeliveryDetails,
    Locations,
    MenuItemOrder,
    MenuItemOrderPickupLocations,
    OpenHours,
    VendorCategory,
    VendorShop,
    MenuItems,
    MenuNutritionalValue,
    MenuItemImages,
    VendorsEarnings,
)

User = get_user_model()


class VendorsEarningsSerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorsEarnings
        fields = ["balance", "payout", "payout_date"]


class LocationsSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = Locations
        fields = [
            "id",
            "vendor",
            "address",
            "longitude",
            "latitude",
            "url",
        ]
        read_only_fields = ["longitude", "latitude"]

    def validate_address(self, value):
        if CoordinateUtils.get_coordinates(value) is None:
            raise serializers.ValidationError("Please input a valid address. We can not find this on the api index.")
        return value

    def get_url(self, instance):
        request = self.context.get("request")
        # Get protocol (http or https)
        protocol = request.scheme  # 'http' or 'https'

        # Get domain name
        domain = request.get_host()
        hostname = f"{protocol}://{domain}"
        # Construct the custom URL using f-string format
        return f"{hostname}/api/v1/vendors/{instance.vendor.slug}/locations/{instance.id}/"

    def create(self, validated_data):
        # this would accept the return value from the google map api and extract
        # the longitude and latitude of the selected address and pass as a
        # validated data to this endpoint
        vendor = self.context.get("vendor")
        request = self.context.get("request")
        instance = Locations.objects.create(vendor=vendor, **validated_data)

        coord = CoordinateUtils(request=request)
        if not instance.longitude and not instance.latitude:
            longitude, latitude = CoordinateUtils.get_coordinates(instance.address)
            instance.longitude = longitude
            instance.latitude = latitude
            instance.save(update_fields=["longitude", "latitude"])
        location = {
            "longitude": instance.longitude,
            "latitude": instance.latitude,
        }
        coord.store_vendor_in_geospatial_db(instance.vendor.slug, instance.id, location)
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["vendor"] = instance.vendor.name  # Replace 'name' with the actual field in your User model
        return representation


class OpenHoursSerializer(serializers.ModelSerializer):
    class Meta:
        model = OpenHours
        fields = ["id", "day", "open", "close"]


class MenuNutritionalValueSerializer(serializers.ModelSerializer):

    class Meta:
        model = MenuNutritionalValue
        fields = [
            "id",
            "nutrient",
            "calories",
        ]

    def create(self, validated_data):
        food = self.context.get("instance")
        instance = MenuNutritionalValue.objects.create(menu_item=food, **validated_data)
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["nutrient"] = instance.nutrient.name  # Replace 'name' with the actual field in your User model
        return representation


class MenuItemImagesSerializer(serializers.ModelSerializer):
    class Meta:
        model = MenuItemImages
        fields = [
            "id",
            "caption",
            "file",
            "featured",
        ]

    def create(self, validated_data):
        food = self.context.get("instance")
        instance = MenuItemImages.objects.create(menu_item=food, **validated_data)
        return instance


class MenuItemCartAddSerializer(serializers.Serializer):
    PRODUCT_QUANTITY_CHOICES = [(i, str(i)) for i in range(1, 21)]
    quantity = serializers.ChoiceField(choices=PRODUCT_QUANTITY_CHOICES, default=1)
    override = serializers.BooleanField(required=False, initial=False)

    def __init__(self, *args, **kwargs):
        # Get the vendor_shop_instance from the context
        context = kwargs.get('context', {})
        url_path = context.get('request').path

        # Define a regular expression pattern to extract the word between 'vendors/' and 'meals/'
        pattern = r"/vendors/(.*?)/meals/"

        # Use re.search to find the match
        match = re.search(pattern, url_path)

        # Extract the word
        if match:
            extracted_word = match.group(1)
            print(f"Extracted word: {extracted_word}")
        else:
            extracted_word = None
            print("No match found.")



        vendor_shop = VendorShop.objects.get(slug=extracted_word)


        # Call the parent constructor
        super(MenuItemCartAddSerializer, self).__init__(*args, **kwargs)

        # Check if vendor_shop is not None and has a slug
        if vendor_shop and vendor_shop.slug:
            try:
                # Filter the location field based on the vendor_shop_instance
                self.fields['location'] = serializers.PrimaryKeyRelatedField(
                    queryset=Locations.objects.filter(vendor=vendor_shop)
                )
            except Locations.DoesNotExist:
                # Handle the case where the Location for the given VendorShop does not exist
                LOGGER.warning("Location for VendorShop does not exist")
        else:
            # Handle the case where vendor_shop is None or does not have a slug
            LOGGER.warning("VendorShop is None or missing slug")

class MenuItemsSerializer(serializers.ModelSerializer):
    nutrition = MenuNutritionalValueSerializer(many=True, read_only=True)
    menu_images = MenuItemImagesSerializer(many=True, read_only=True)
    actual_price = serializers.SerializerMethodField(read_only=True, required=False)
    url = serializers.SerializerMethodField()

    class Meta:
        model = MenuItems
        fields = [
            "vendor",
            "name",
            "unique_id",
            "nutrition",
            "menu_images",
            "description",
            "quantity",
            "price",
            "actual_price",
            "url",
        ]  # Include all fields from the model
        read_only_fields = ["vendor", "unique_id"]

    def get_url(self, obj) -> str:
        request = self.context.get("request")
        # Get protocol (http or https)
        protocol = request.scheme  # 'http' or 'https'

        # Get domain name
        domain = request.get_host()
        hostname = f"{protocol}://{domain}"
        # Construct the custom URL using f-string format
        return f"{hostname}/api/v1/vendors/{obj.vendor.slug}/meals/{obj.unique_id}/"

    def create(self, validated_data):
        menu_item = MenuItems.objects.create(**validated_data)
        return menu_item

    def get_actual_price(self, obj) -> float:
        try:
            # Assuming obj.price is in USD, and you want to convert it to another currency (e.g., CNY)
            target_currency = self.context["request"].user.currency  # Replace with your desired target currency code
            converted_price = convert_amount(obj.price, target_currency)
            return float(converted_price) or 0.00
        except Exception as e:
            LOGGER.info(str(e))
            converted_price = convert_amount(obj.price, "NGN")
            return float(converted_price) or 0.00

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["vendor"] = instance.vendor.name  # Replace 'name' with the actual field in your User model
        return representation


class MenuItemOrderSerializer(serializers.ModelSerializer):

    class Meta:
        model = MenuItemOrder
        fields = [
            "user",
            "delivery_lat",
            "delivery_lon",
            "delivery_address",
            "order_id",
            "amount",
            "quantity",
            "paid",
            "failed",
        ]
        read_only_fields = [
            "user",
            "delivery_lat",
            "delivery_lon",
            "order_id",
            "amount",
            "quantity",
            "paid",
            "failed",
        ]

    def create(self, validated_data):
        user = self.context.get("user")
        vendor = self.context.get("vendor")
        amount = self.context.get("amount")
        quantity = self.context.get("quantity")
        request = self.context.get("request")
        cood = CoordinateUtils(request)
        order = MenuItemOrder.objects.create(
            user=user, vendor=vendor, amount=amount, quantity=quantity, **validated_data
        )
        location = {}
        if validated_data.get("pick_up_location_id") is not None:
            location: Locations = Locations.objects.get(id=int(validated_data.get("pick_up_location_id")))
        else:
            return order

        vendor_location = {"longitude": location.longitude, "latitude": location.latitude}
        if cood.get_distance_to_closest_rider(vendor_location) is not None:
            rider_id, distance = cood.get_distance_to_closest_rider(vendor_location)
            rider = RiderParticulars.objects.get(id=rider_id)
            speed = (
                80
                if rider.vehicle_type == RiderParticulars.BIKE
                else 24 if rider.vehicle_type == RiderParticulars.CYCLE else 4
            )
            eta = cood.estimated_time_of_arrival(distance, speed)
            DeliveryDetails.objects.create(
                rider=rider,
                order=order,
                distance_to_arrival=distance,
                eta=eta,
            )
        return order

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["user"] = instance.user.email  # Replace 'name' with the actual field in your User model
        representation["vendor"] = instance.vendor.name  # Replace 'name' with the actual field in your User model
        return representation


class DeliveryItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeliveryDetails
        fields = [
            "rider",
            "order",
            "distance_to_arrival",
            "eta",
        ]

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["rider"] = instance.rider.user.email  # Replace 'name' with the actual field in your User model
        return representation

class VendorCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VendorCategory
        fields = ['name']

class VendorShopSerializer(serializers.ModelSerializer):
    open_hours = OpenHoursSerializer(many=True, read_only=True)
    locations = LocationsSerializer(many=True, read_only=True)
    menu_items = MenuItemsSerializer(many=True, read_only=True)
    vendor_categories = VendorCategorySerializer(many=True, read_only=True)

    class Meta:
        model = VendorShop
        fields = [
            "users",
            "vendor_categories",
            "slug",
            "name",
            "phone",
            "email",
            "website",
            "pin",
            "logo",
            "open_hours",
            "locations",
            "menu_items",
            "url",
        ]
        read_only_fields = [
            "users",
            "slug",
        ]
        extra_kwargs = {
            "url": {"view_name": "api:vendor-detail", "lookup_field": "slug"},
        }

    def validate_name(self, value):
        """
        Validate the name field
        Ensure it is not empty or a single alphabet
        """

        if len(value) < 5:
            raise serializers.ValidationError("Name must be greater than 4 characters")
        return value

    def _get_user_from_emails(self, email_list):
        """
        Retrieve user IDs based on a list of emails.
        """
        email_list = [email.strip() for email in email_list.split(",") if email.strip()]
        users = User.objects.filter(email__in=email_list)
        return users

    def update(self, instance, validated_data):
        # Update the VendorShop instance
        instance.name = validated_data.get("name", instance.name)
        instance.logo = validated_data.get("logo", instance.logo)

        user_emails = self.context.get("emails_data")
        if user_emails is not None:
            users = self._get_user_from_emails(user_emails)
            for user in users:
                if not user in instance.users:
                    instance.users.add(user)

        instance.save()
        return instance

    def create(self, validated_data):
        LOGGER.info(validated_data)
        user = self.context.get("request").user
        vendor = VendorShop.objects.create(**validated_data)
        vendor.users.add(user)
        vendor.save()

        # Create OpenHours instances for each day of the week
        days_of_week = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        for day in days_of_week:
            OpenHours.objects.create(vendor=vendor, day=day, open="09:00", close="18:00")
        return vendor

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["logo"] = (
            instance.logo.url
        )  # Replace 'name' with the actual field in your User model
        return representation
