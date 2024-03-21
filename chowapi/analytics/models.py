from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model

from model_utils.models import TimeStampedModel



User = get_user_model()

class AppViewed(TimeStampedModel):
    ip_address = models.GenericIPAddressField(db_index=True)
    country_code = models.CharField(max_length=5, blank=True, null=True)
    continent_code = models.CharField(max_length=5, blank=True, null=True)
    region = models.CharField(max_length=225, blank=True, null=True)
    country_flag = models.URLField(max_length=1000, blank=True, null=True)
    uses_vpn = models.BooleanField(default=False)

    model = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="views")
    model_object_id = models.PositiveBigIntegerField()
    model_object = GenericForeignKey("model", "model_object_id")

    @classmethod
    def get_total_views_per_day(cls):
        """
        Method to get the total views per day for a given app or model.

        Returns:
            QuerySet: A queryset containing daily views with 'day' and 'total_views' fields.
        """
        # Group views by day and count the occurrences
        views_per_day = cls.objects.annotate(day=models.functions.TruncMonth('created')).values('month').annotate(total_views=models.Count('id')).order_by('month')

        return views_per_day

    def __str__(self):
        return f"{self.model} viewed with IP:{self.ip_address} on {self.created.date()}"

    class Meta:
        verbose_name = "App Viewed"
        verbose_name_plural = "Apps Viewed"



class ReviewRating(TimeStampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reviews")
    rating = models.IntegerField(default=1)
    review_text = models.TextField(max_length=420)
    model = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="reviews")
    model_object_id = models.PositiveBigIntegerField()
    model_object = GenericForeignKey("model", "model_object_id")


    def __str__(self):
        return f"{self.user.name or self.user.email} Reviewed: {self.model} - {self.created.date}"

    class Meta:
        verbose_name = "App Review"
        verbose_name_plural = "Apps Review"

class PageViews(TimeStampedModel):
    page_link = models.URLField()
    ip_address = models.GenericIPAddressField(db_index=True)
    country_code = models.CharField(max_length=5, blank=True, null=True, db_index=True)
    continent_code = models.CharField(max_length=5, blank=True, null=True, db_index=True)
    region = models.CharField(max_length=225, blank=True, null=True)
    country_flag = models.URLField(max_length=1000, blank=True, null=True)
    uses_vpn = models.BooleanField(default=False)

    last_visited_date = models.DateField(null=True, blank=True)
    new_visit_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.ip_address} - {self.page_link} - Last Visited: {self.last_visited_date} - New Visit: {self.new_visit_date}"

    @classmethod
    def track_visit(cls, request, page_link):
        client_ip = request.ip
        current_date = timezone.now().date()

        # Avoid redundant lookups
        try:
            page_view = cls.objects.get(ip_address=client_ip, page_link=page_link)
        except cls.DoesNotExist:
            page_view = cls.objects.create(
                ip_address=client_ip,
                page_link=page_link,
                country_code=request.country_code,
                continent_code=request.continent_code,
                region=request.region,
                country_flag=request.country_flag,
                uses_vpn=request.uses_vpn,
                last_visited_date=current_date,
                new_visit_date=current_date,
            )
        else:
            if page_view.last_visited_date != current_date or page_view.new_visit_date is not None:
                page_view.last_visited_date = page_view.new_visit_date
                page_view.new_visit_date = current_date
                page_view.save()
            elif page_view.new_visit_date is None:
                page_view.last_visited_date = current_date
                page_view.new_visit_date = current_date
                page_view.save()

        return page_view

    @classmethod
    def get_total_views_per_day(cls, page_link):
        """
        Method to get the total views per day for a given page.

        Args:
            page_link (str): The link or identifier of the page to filter views.

        Returns:
            QuerySet: A queryset containing daily views with 'day' and 'total_views' fields.
        """
        # Filter views by page_link, group by day, and count the occurrences
        views_per_day = cls.objects.filter(page_link=page_link).annotate(month=models.functions.TruncMonth('created')).values('month').annotate(total_views=models.Count('id')).order_by('month')

        return views_per_day

    class Meta:
        verbose_name = "Page Viewed"
        verbose_name_plural = "Pages Viewed"


