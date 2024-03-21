from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.exceptions import APIException

from chowapi.nutrition.models import Nutrition
from chowapi.utils.exceptions import UnauthorizedObjectException
from chowapi.utils.permissions import IsStaffPermission

from .serializers import NutritionSerializer



class NutritionStaffViewSet(CreateModelMixin, UpdateModelMixin, GenericViewSet):
    serializer_class = NutritionSerializer
    queryset = Nutrition.objects.all()
    lookup_field = "slug"
    permission_classes = [IsAuthenticated, IsStaffPermission]

    def get_queryset(self, *args, **kwargs):
        """
        Get the queryset for nutrition records.

        Returns:
            QuerySet: All nutrition records.
        """
        return self.queryset

    def create(self, request, *args, **kwargs):
        if not request.user.is_staff:
            raise UnauthorizedObjectException()

        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            raise APIException(detail=f"Error creating nutrition record: {str(e)}")

    def update(self, request, *args, **kwargs):
        if not request.user.is_staff:
            raise UnauthorizedObjectException()

        try:
            return super().update(request, *args, **kwargs)
        except Exception as e:
            raise APIException(detail=f"Error updating nutrition record: {str(e)}")

class NutritionListViewSet(ListModelMixin, GenericViewSet):
    serializer_class = NutritionSerializer
    queryset = Nutrition.objects.all()
    lookup_field = "slug"
    permission_classes = [AllowAny]

    def get_queryset(self, *args, **kwargs):
        """
        Get the queryset for nutrition records.

        Returns:
            QuerySet: All nutrition records.
        """
        assert isinstance(self.request.user.is_authenticated, bool)
        return self.queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response({"results": serializer.data, "detail": "Nutrition records retrieved successfully."})
