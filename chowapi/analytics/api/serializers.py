from rest_framework import serializers

from django.contrib.auth import get_user_model

from chowapi.analytics.models import AppViewed, PageViews, ReviewRating

User = get_user_model()

class AppViewedSerializer(serializers.ModelSerializer):

    class Meta:
        model = AppViewed
        fields = (
            "id",
            "ip_address",
            "country_code",
            "continent_code",
            "region",
            "country_flag",
            "uses_vpn",
            "created",
            "modified",
        )


class PageViewsSerializer(serializers.ModelSerializer):
    """Serializer for the PageViews model, providing various formatting options and flexibility."""

    class Meta:
        model = PageViews
        fields = (
            "id",
            "page_link",
            "ip_address",
            "country_code",
            "continent_code",
            "region",
            "country_flag",
            "uses_vpn",
            "created",
            "modified",
            "last_visited_date",
            "new_visit_date",
        )
        read_only_fields = [
            "ip_address",
            "country_code",
            "continent_code",
            "region",
            "country_flag",
            "uses_vpn",
            "created",
            "modified",
            "last_visited_date",
            "new_visit_date",
        ]

    def create(self, validated_data):
        request = self.context.get('request')
        instance = PageViews.track_visit(
            request,
            validated_data.get("page_link"),
        )
        return instance


class ReviewRatingSerializer(serializers.ModelSerializer):
    PRODUCT_QUANTITY_CHOICES = [(i, str(i)) for i in range(1, 6)]
    rating = serializers.ChoiceField(choices=PRODUCT_QUANTITY_CHOICES, default=1)
    class Meta:
        model = ReviewRating
        fields = [
            'user',  # Display user email
            'rating',
            'review_text',
        ]
        read_only_fields = ['user']

    def create(self, validated_data):
        model = self.context.get("model")
        instance_id = self.context.get('model_id')
        user = self.context.get('request').user
        instance = ReviewRating.objects.create(user=user, model=model, model_object_id = instance_id, **validated_data)
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = instance.user.email  # Replace 'name' with the actual field in your User model
        # model_object = instance.model_object
        # if model_object:
        #     # Assuming 'model_object' has a 'name' field (you can adjust this based on your actual model)
        #     representation['model_object'] = model_object.name
        # else:
        #     representation['model_object'] = None
        return representation
