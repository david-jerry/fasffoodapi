from django.dispatch import Signal
from django.contrib.contenttypes.models import ContentType

from chowapi.analytics.models import AppViewed, PageViews

# signal sent anytime an object or page is viewed to store the records
object_viewed_signal = Signal(['instance', 'request']) # used: object_viewed_signal.send(ModelClass, instance=object_instance, request=request)
page_viewed_signal = Signal(["url", 'request']) # used: page_viewed_signal.send(ModelClass, instance=object_instance, request=request)

def app_viewed_reciever(sender, instance, request, *args, **kwargs):
    c_type = ContentType.objects.get_for_model(sender) # Gives us the instance class name ie. instance.__class__

    AppViewed.objects.create(
        ip_address=request.ip,
        country_code=request.country_code,
        continent_code=request.continent_code,
        region=request.region,
        country_flag=request.country_flag,
        uses_vpn=request.uses_vpn,

        model=c_type,
        model_object_id=instance.id,
    )

object_viewed_signal.connect(app_viewed_reciever)

def page_viewed_reciever(sender, url, request, *args, **kwargs):
    PageViews.track_visit(request, url)
page_viewed_signal.connect(page_viewed_reciever)
