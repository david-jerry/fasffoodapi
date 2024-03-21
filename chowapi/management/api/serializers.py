import re
from rest_framework import serializers

from chowapi.management.models import CompanyDetails, DeliveryCityLocations

class DeliveryCityLocationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeliveryCityLocations
        fields = ['id', 'name']

    def validate_name(self, value):
        if re.match("^[0-9]+$", value):
            raise serializers.ValidationError("Numbers are not allowed in this location name")
        return value

class CompanyDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyDetails
        fields = [
            "id",
            "website_name",
            "website_logo",
            "support_email",
            "support_phone",
            "short_description",
            "brief_about",
            "mission_statement",
        ]
