from rest_framework import serializers

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType

from chowapi.users.api.serializers import UserSerializer
from chowapi.utils.converters import convert_amount
from chowapi.utils.validators import validate_bank_name
from chowapi.vendors.api.serializers import VendorShopSerializer

from chowapi.vendors.models import VendorShop
from ..models import CurrencyRates, TransactionHistory, BankAccount

from generic_relations.relations import GenericRelatedField

User = get_user_model()


class CurrencyRatesSerializer(serializers.ModelSerializer):
    class Meta:
        model = CurrencyRates
        fields = [
            "currency_code",
            "amount",
        ]


class TransactionHistorySerializer(serializers.ModelSerializer):
    model_object = GenericRelatedField({User: UserSerializer(), VendorShop: VendorShopSerializer()})
    actual_price = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = TransactionHistory
        fields = [
            "transaction_id",
            "status",
            "amount",
            "model_object",
            "created",
            "modified",
            "url",
            "actual_price",
        ]
        extra_kwargs = {
            "url": {"view_name": "api:transaction-detail", "lookup_field": "transaction_id"},
        }

    def get_actual_price(self, obj) -> float:
        try:
            # Assuming obj.price is in USD, and you want to convert it to another currency (e.g., CNY)
            target_currency = self.context["request"].user.currency  # Replace with your desired target currency code
            converted_price = convert_amount(obj.amount, target_currency)
            return float(converted_price) or 0.00
        except Exception as e:
            converted_price = convert_amount(obj.amount, "NGN")
            return float(converted_price) or 0.00


class BankAccountSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = BankAccount
        fields = [
            "bank_id",
            "account_number",
            "account_name",
            "bank_name",
            "url",
        ]
        read_only_fields = ['bank_id']

    def get_url(self, obj):
        vendor_model = ContentType.objects.get_for_model(VendorShop)
        rider_model = ContentType.objects.get_for_model(User)

        model = self.context.get("model")
        instance = self.context.get('instance')

        request = self.context.get("request")
        # Get protocol (http or https)
        protocol = request.scheme  # 'http' or 'https'

        # Get domain name
        domain = request.get_host()
        hostname = f"{protocol}://{domain}"

        if model == vendor_model:
            return f"{hostname}/api/v1/vendors/{instance.slug}/banks/{obj.account_number}"
        elif model == rider_model:
            return f"{hostname}/api/v1/users/{instance.id}/banks/{obj.account_number}"

    def validate_bank_name(self, value):
        exists = validate_bank_name(value)
        if not exists:
            raise serializers.ValidationError("The specified bank name is not yet supported. Please check back later.")
        return value

    def create(self, validated_data):
        model = self.context.get("model")
        instance = self.context.get('instance')
        instance = BankAccount.objects.create(model=model, model_object_id=instance.id, **validated_data)
        return instance
