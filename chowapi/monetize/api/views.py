from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.viewsets import GenericViewSet
from rest_framework.permissions import AllowAny
from rest_framework.throttling import UserRateThrottle
from rest_framework.decorators import action
from rest_framework import filters
from chowapi.monetize.api.serializers import CurrencyRatesSerializer
from chowapi.monetize.models import CurrencyRates

from chowapi.utils.pagination import CustomPagination

class CurrencyRatesViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    serializer_class = CurrencyRatesSerializer
    queryset = CurrencyRates.objects.all()
    lookup_field = "pk"
    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]
    permission_classes = [AllowAny]
