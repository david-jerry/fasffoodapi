from django.db import models
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, Avg

from chowapi.vendors.models import VendorShop, MenuItems

class ReviewRatingManager(models.Manager):
    """
    Review Rating Manager

    Functions:
    1. Get first 5 top rated vendors
    2. Get first 5 top rated food
    3. Get first 5 top rated riders
    """
    def get_top_rated_vendors(self, limit=5):
        # Get the top-rated objects based on average rating for the specified model type
        model_type = ContentType.objects.get_for_model(VendorShop)
        top_rated_objects = self.filter(model=model_type) \
            .values('model_object') \
            .annotate(avg_rating=Avg('rating')) \
            .order_by('-avg_rating')[:limit]
        return top_rated_objects

    def get_top_rated_food(self, limit=5):
        # Get the top-rated objects based on average rating for the specified model type
        model_type = ContentType.objects.get_for_model(MenuItems)
        top_rated_objects = self.filter(model=model_type) \
            .values('model_object') \
            .annotate(avg_rating=Avg('rating')) \
            .order_by('-avg_rating')[:limit]

        return top_rated_objects



class AppViewedManager(models.Manager):
    def daily_views_sum(self, app_model, month=None):
        queryset = self.filter(model=app_model)

        if month:
            queryset = queryset.filter(created__month=month)

        # Annotate each object with the day of creation and count views for each day
        queryset = queryset.annotate(day=models.functions.TruncDay('created')).values('day').annotate(views_sum=Count('id'))

        return queryset
