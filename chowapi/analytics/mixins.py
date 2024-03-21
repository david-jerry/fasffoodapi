from rest_framework.views import APIView

from django.utils.timezone import datetime

from chowapi.analytics.models import AppViewed
from .signals import object_viewed_signal, page_viewed_signal

class ObjectViewedMixin(object):
    def get_context_data(self, **kwargs):
        context = super(ObjectViewedMixin, self).get_context_data(**kwargs)
        request = self.request
        instance = context['object']
        if instance:
            object_viewed_signal.send(instance.__class__, instance=instance, request=request)
        return context

class ObjectViewedMixin(APIView):
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        instance = self.get_object()  # Implement this method to get the object
        if instance:
            object_viewed_signal.send(instance.__class__, instance=instance, request=request)
        return response

def object_viewed_handler(instance, request):
    """
    Handle object viewed event by sending a signal.
    :param instance: The object instance being viewed.
    :param request: The request associated with the view.
    """

    if instance and not AppViewed.objects.filter(model_object_id=instance.id, ip_address=request.ip, country_code=request.country_code, created__date=datetime.today()).exists():
        object_viewed_signal.send(instance.__class__, instance=instance, request=request)


class PageViewedMixin(object):
    def get_context_data(self, **kwargs):
        context = super(PageViewedMixin, self).get_context_data(**kwargs)
        request = self.request

        is_secure = request.is_secure()  # True if HTTPS, False if HTTP
        domain = request.get_host()  # E.g., 'example.com' or 'localhost:8000'
        path = request.path  # E.g., '/my-page/'

        # Construct the full URL
        protocol = 'https' if is_secure else 'http'
        full_url = f"{protocol}://{domain}{path}"

        page_viewed_signal.send(self.__class__, url=full_url, request=request)
        return context
