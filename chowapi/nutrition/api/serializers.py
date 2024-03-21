from rest_framework import serializers
from ..models import Nutrition

class NutritionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Nutrition
        fields = [
            "name",
            "slug",
            "icon",
            "description",
        ]
        read_only_fields = ['slug']

    def validate_name(self, value):
        # Example: Ensure the name is at least 3 characters long
        if len(value) < 3:
            raise serializers.ValidationError("Name must be at least 3 characters long.")
        return value

    def validate_description(self, value):
        # Example: Ensure the description length is within a specific range
        max_length = 1000
        if len(value) > max_length:
            raise serializers.ValidationError(f"Description must be within {max_length} characters.")
        return value

    def create(self, validated_data):
        instance = Nutrition.objects.filter(name=validated_data.get('name')).first()
        if Nutrition.objects.filter(name=validated_data.get('name')).exists():
            return instance

        instance = Nutrition.objects.create(**validated_data)
        return instance


