from rest_framework.decorators import action
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin, DestroyModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import UserRateThrottle
from rest_framework import status

from django.contrib.contenttypes.models import ContentType

from chowapi.utils.pagination import CustomPagination

from .serializers import PageViewsSerializer
from ..models import PageViews

class PageViewsViewSet(CreateModelMixin, RetrieveModelMixin, ListModelMixin, GenericViewSet):
    serializer_class = PageViewsSerializer
    queryset = PageViews.objects.all()
    lookup_field = "ip_address"
    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]
    permission_classes = [AllowAny]

