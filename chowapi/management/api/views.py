from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.viewsets import GenericViewSet
from rest_framework.permissions import AllowAny
from rest_framework.throttling import UserRateThrottle
from rest_framework import status
from rest_framework.response import Response

from chowapi.utils.pagination import CustomPagination

from .serializers import DeliveryCityLocationsSerializer, CompanyDetailsSerializer
from ..models import DeliveryCityLocations, CompanyDetails

class DeliveryCityLocationsViewSet(ListModelMixin, RetrieveModelMixin, GenericViewSet):
    serializer_class = DeliveryCityLocationsSerializer
    queryset = DeliveryCityLocations.objects.all()
    lookup_field = "id"
    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]
    permission_classes = [AllowAny]

class CompanyDetailsViewSet(ListModelMixin, RetrieveModelMixin, GenericViewSet):
    serializer_class = CompanyDetailsSerializer
    queryset = CompanyDetails.objects.all()
    lookup_field = "id"
    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]
    permission_classes = [AllowAny]

    @action(detail=False, methods=["GET"], url_path="active-info")
    def info(self, request, *args, **kwargs):
        if len(CompanyDetails.objects.all()) > 0:
            first = CompanyDetails.objects.first()
            info_serializer = self.serializer_class(first, many=False, context={"request": request})
            return Response(info_serializer.data, status=status.HTTP_200_OK)
        return Response({"detail": "No content"}, status=status.HTTP_204_NO_CONTENT)
