import csv
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.db.models import Avg
from django.contrib.contenttypes.models import ContentType

from django_filters.rest_framework import DjangoFilterBackend

from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.decorators import action
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import UserRateThrottle
from rest_framework import status

from chowapi.analytics.api.serializers import ReviewRatingSerializer
from chowapi.analytics.mixins import object_viewed_handler
from chowapi.analytics.models import ReviewRating
from chowapi.monetize.models import BankAccount, TransactionHistory
from chowapi.monetize.api.serializers import BankAccountSerializer, TransactionHistorySerializer
from chowapi.utils.logger import LOGGER
from chowapi.vendors.carts import Cart
from chowapi.vendors.models import (
    Locations,
    MenuItemImages,
    MenuItemOrder,
    MenuNutritionalValue,
    OpenHours,
    VendorShop,
    MenuItems,
    VendorsEarnings,
)
from chowapi.vendors.api.serializers import (
    LocationsSerializer,
    MenuItemCartAddSerializer,
    MenuItemImagesSerializer,
    MenuItemOrderSerializer,
    MenuNutritionalValueSerializer,
    OpenHoursSerializer,
    VendorShopSerializer,
    MenuItemsSerializer,
    VendorsEarningsSerializer,
)
from chowapi.utils.exceptions import ObjectNotFoundException, UnauthorizedException, UnauthorizedObjectException
from chowapi.utils.pagination import CustomPagination


class VendorShopViewSet(CreateModelMixin, RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet):
    serializer_class = VendorShopSerializer
    queryset = VendorShop.objects.all()
    lookup_field = "slug"
    pagination_class = CustomPagination
    throttle_classes = [UserRateThrottle]
    permission_classes = [AllowAny]

    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filter_fields = ['name', 'categories__name']
    search_fields = ['^name', "=email", "^website"]
    ordering_fields = ['name', 'phone']
    ordering = ['name']

    def list(self, request):
        # from django.db.models import Q
        # query_param = request.query_params.get("q", None)

        queryset = self.queryset

        # if query_param is not None:
        #     queryset = self.queryset.filter(Q(name__icontains=query_param) | Q(categories__name__icontains=query_param))

        page = self.paginate_queryset(queryset)

        serializer = VendorShopSerializer(queryset, many=True, context={"request": request})
        if page is not None:
            serializer = VendorShopSerializer(page, many=True, context={"request": request})
            result = self.get_paginated_response(serializer.data)
            return Response(data=result.data, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_200_OK, data=serializer.data)

    def get_serializer_class(self):
        if self.action in [
            "get_or_update_payout_bank",
            "create_payout_bank",
        ]:
            return BankAccountSerializer
        elif self.action in [
            "rate_the_vendor",
            "rate_the_meal",
        ]:
            return ReviewRatingSerializer
        elif self.action in [
            "create_location",
            "get_or_update_location",
        ]:
            return LocationsSerializer
        elif self.action in [
            "create_food",
            "get_or_update_food",
        ]:
            return MenuItemsSerializer
        elif self.action == "add_food_nutrition":
            return MenuNutritionalValueSerializer
        elif self.action == "add_food_images":
            return MenuItemImagesSerializer
        elif self.action == "update_open_hours":
            return OpenHoursSerializer
        elif self.action == "add_to_cart":
            return MenuItemCartAddSerializer
        elif self.action == "create_order":
            return MenuItemOrderSerializer
        return self.serializer_class

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
            "Expected view %s to be called with a URL keyword argument "
            'named "%s". Fix your URL conf, or set the `.lookup_field` '
            "attribute on the view correctly." % (self.__class__.__name__, lookup_url_kwarg)
        )

        filter_kwargs = {self.lookup_field: self.kwargs[lookup_url_kwarg]}
        obj = get_object_or_404(queryset, **filter_kwargs)
        object_viewed_handler(obj, self.request)

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj

    def update(self, request, *args, **kwargs):
        """
        Update a vendor shop.
        """
        instance = self.get_object()

        # Extract 'emails' field without passing for validation
        emails_data = request.data.pop("emails", None)

        # Update the instance with the remaining data
        serializer = self.get_serializer(
            instance, data=request.data, partial=True, context={"request": request, "emails_data": emails_data}
        )
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def perform_update(self, serializer):
        serializer.save()

    @action(detail=True, methods=["GET"], url_path="export-vendors-menu-csv")
    def export_vendors_menu_csv(self, request):
        """
        Export all waiters records as a CSV file.
        Example usage: /api/users/export-csv/
        """
        vendor_shop = self.get_object()
        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        queryset = MenuItems.objects.filter(vendor=vendor_shop)  # Assuming waiters are staff members

        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = f'attachment; filename="{vendor_shop.slug}.csv"'

        # Create a CSV writer and write the header
        csv_writer = csv.writer(response)
        csv_writer.writerow(
            ["ID", "NAME", "LOCATIONS", "AMOUNT", "UNIQUE ID"]
        )  # Add other fields as needed

        # Write user data to the CSV file
        for user in queryset:
            csv_writer.writerow(
                [user.id, user.name, user.vendor.locations.all().count(), user.price, user.unique_id]
            )  # Add other field values as needed

        return response


    @action(detail=True, methods=["POST", "GET"], url_path="rate")
    def rate_the_vendor(self, request, slug):
        vendor_shop = self.get_object()
        model = ContentType.objects.get_for_model(VendorShop)
        user = request.user

        if user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        context = {"request": request, "model": model, "model_id": vendor_shop.id}

        if request.method == "GET":
            ratings = ReviewRating.objects.filter(model=model, model_object_id=vendor_shop.id)
            average = ratings.aggregate(Avg("rating"))["rating__avg"] or 0.0
            return Response(data={"average_rating": average}, status=status.HTTP_200_OK)

        rating_serializer = ReviewRatingSerializer(data=request.data, context=context)

        if rating_serializer.is_valid():
            rating_serializer.save()
            return Response(rating_serializer.data, status=status.HTTP_201_CREATED)
        return Response(rating_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["POST", "GET"], url_path=r"meals/(?P<unique_id>[^/.]+)/rate")
    def rate_the_meal(self, request, slug, unique_id):
        vendor_shop = self.get_object()
        food = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)
        model = ContentType.objects.get_for_model(MenuItems)
        user = request.user

        if user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        context = {"request": request, "model": model, "model_id": food.id}

        if request.method == "GET":
            ratings = ReviewRating.objects.filter(model=model, model_object_id=food.id)
            average = ratings.aggregate(Avg("rating"))["rating__avg"] or 0.0
            return Response(
                data={
                    "vendor_name": f"{vendor_shop.name.title()}",
                    "meal": f"{food.name.title}",
                    "average_rating": average,
                },
                status=status.HTTP_200_OK,
            )

        rating_serializer = ReviewRatingSerializer(data=request.data, context=context)

        if rating_serializer.is_valid():
            rating_serializer.save()
            return Response(rating_serializer.data, status=status.HTTP_201_CREATED)
        return Response(rating_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["GET"], url_path="transactions")
    def get_transactions(self, request, slug):
        vendor_shop = self.get_object()
        model = ContentType.objects.get_for_model(VendorShop)

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        transactions = TransactionHistory.objects.filter(model_object_id=vendor_shop.id, model=model)

        page = self.paginate_queryset(transactions)
        if page is not None:
            transactions_serializer = TransactionHistorySerializer(page, many=True)
            result = self.get_paginated_response(transactions_serializer.data)
            return Response(result.data, status=status.HTTP_200_OK)

        transactions_serializer = TransactionHistorySerializer(instance=transactions, many=True)
        return Response(transactions_serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["POST", "GET"], url_path="banks")
    def create_payout_bank(self, request, slug):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()
        model = ContentType.objects.get_for_model(VendorShop)

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        if request.method == "GET":
            bank = get_object_or_404(BankAccount, model=model, model_object_id=vendor_shop.id)
            serializer = BankAccountSerializer(
                instance=bank, many=False, context={"request": request, "model": model, "instance": vendor_shop}
            )
            return Response(serializer.data, status=status.HTTP_200_OK)

        # Create the location associated with the vendor_shop
        bank_serializer = BankAccountSerializer(
            data=request.data, context={"request": request, "model": model, "instance": vendor_shop}
        )

        if bank_serializer.is_valid():
            bank_serializer.save()
            return Response(bank_serializer.data, status=status.HTTP_201_CREATED)
        return Response(bank_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["PUT", "GET"], url_path=r"banks/(?P<account_number>\d+)")
    def get_or_update_payout_bank(self, request, slug, account_number):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()
        model = ContentType.objects.get_for_model(VendorShop)

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        if request.method == "GET":
            try:
                bank = get_object_or_404(
                    BankAccount, account_number=account_number, model_object_id=vendor_shop.id, model=model
                )
                serializer = BankAccountSerializer(
                    bank, many=False, context={"request": request, "model": model, "instance": vendor_shop}
                )
                return Response(serializer.data, status=status.HTTP_200_OK)
            except BankAccount.DoesNotExist:
                raise ObjectNotFoundException()

        # Retrieve the location instance
        bank = get_object_or_404(
            BankAccount, account_number=account_number, model_object_id=vendor_shop.id, model=model
        )

        # Update the location
        bank_serializer = BankAccountSerializer(
            bank, data=request.data, partial=True, many=False, context={"request": request}
        )
        if bank_serializer.is_valid():
            bank_serializer.save()
            return Response(bank_serializer.data, status=status.HTTP_200_OK)
        return Response(bank_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["GET"], url_path="get-earning")
    def get_balance(self, request, slug):
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        try:
            earnings = VendorsEarnings.objects.get(vendor=vendor_shop)
            earning_serializer = VendorsEarningsSerializer(instance=earnings, many=False)
            return Response(earning_serializer.data, status=status.HTTP_200_OK)
        except VendorsEarnings.DoesNotExist:
            raise ObjectNotFoundException

    @action(detail=True, methods=["POST", "GET"], url_path="locations")
    def create_location(self, request, slug):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        if request.method == "GET":
            locations = Locations.objects.filter(vendor=vendor_shop)

            page = self.paginate_queryset(locations)
            if page is not None:
                transactions_serializer = LocationsSerializer(page, many=True)
                result = self.get_paginated_response(transactions_serializer.data)
                return Response(result.data, status=status.HTTP_200_OK)

            # Create the location associated with the vendor_shop
            location_serializer = LocationsSerializer(
                locations, many=True, context={"request": request, "vendor": vendor_shop}
            )
            return Response(location_serializer.data, status=status.HTTP_200_OK)

        # Create the location associated with the vendor_shop
        location_serializer = LocationsSerializer(
            data=request.data, context={"request": request, "vendor": vendor_shop}
        )

        if location_serializer.is_valid():
            location_serializer.save()
            return Response(location_serializer.data, status=status.HTTP_201_CREATED)
        return Response(location_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["PUT", "GET"], url_path=r"locations/(?P<location_id>\d+)")
    def get_or_update_location(self, request, slug, location_id):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        # Retrieve the location instance
        location = get_object_or_404(Locations, id=location_id, vendor=vendor_shop)
        if request.method == "GET":
            location_serializer = LocationsSerializer(
                location, many=False, context={"request": request, "vendor": vendor_shop}
            )
            return Response(location_serializer.data, status=status.HTTP_200_OK)

        # Update the location
        location_serializer = LocationsSerializer(
            location, data=request.data, partial=True, context={"request": request, "vendor": vendor_shop}
        )
        if location_serializer.is_valid():
            location_serializer.save()
            return Response(location_serializer.data, status=status.HTTP_200_OK)
        return Response(location_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=["GET"], url_path="query-meals")
    def search_all_meals(self, request):
        from django.db.models import Q

        query_param = self.request.query_params.get("q", None)
        meals = MenuItems.objects.all()
        if query_param is not None:
            meals = MenuItems.objects.filter(Q(name__icontains=query_param) | Q(vendor__name=query_param))

        page = self.paginate_queryset(meals)
        if page is not None:
            transactions_serializer = MenuItemsSerializer(page, many=True, context={"request": request})
            result = self.get_paginated_response(transactions_serializer.data)
            return Response(result.data, status=status.HTTP_200_OK)

        serializer = MenuItemsSerializer(meals, many=True, context={"request": request})
        return Response(
            serializer.data, status=status.HTTP_200_OK
        )

    @action(detail=True, methods=["POST", "GET"], url_path="meals")
    def create_meal(self, request, slug):
        from django.db.models import Q

        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        if request.method == "GET":
            query_param = self.request.query_params.get("q", None)
            meals = MenuItems.objects.filter(vendor=vendor_shop)
            if query_param is not None:
                meals = MenuItems.objects.filter(vendor=vendor_shop).filter(Q(name__icontains=query_param))

            page = self.paginate_queryset(meals)
            if page is not None:
                transactions_serializer = MenuItemsSerializer(page, many=True, context={"request": request})
                result = self.get_paginated_response(transactions_serializer.data)
                return Response(result.data, status=status.HTTP_200_OK)

            serializer = MenuItemsSerializer(meals, many=True, context={"request": request})
            return Response(
                serializer.data, status=status.HTTP_200_OK
            )

        # Create the location associated with the vendor_shop
        menu_serializer = MenuItemsSerializer(data=request.data, context={"request": request})

        if menu_serializer.is_valid():
            menu_serializer.save(vendor=vendor_shop)
            return Response(menu_serializer.data, status=status.HTTP_201_CREATED)
        return Response(menu_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["PUT", "GET"], url_path=r"meals/(?P<unique_id>[^/.]+)")
    def get_or_update_food(self, request, slug, unique_id):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        # Retrieve the location instance
        food = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)
        if request.method == "GET":
            menuitem_serializer = MenuItemsSerializer(
                food, many=False, context={"request": request, "vendor": vendor_shop}
            )
            return Response(menuitem_serializer.data, status=status.HTTP_200_OK)

        # Update the location
        menuitem_serializer = MenuItemsSerializer(food, data=request.data, partial=True, context={"request": request})

        if menuitem_serializer.is_valid():
            menuitem_serializer.save()
            return Response(menuitem_serializer.data, status=status.HTTP_200_OK)
        return Response(menuitem_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["POST", "GET"], url_path=r"meals/(?P<unique_id>[^/.]+)/nutrition")
    def add_food_nutrition(self, request, slug, unique_id):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        # Retrieve the location instance
        food = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)

        # Update the location
        nutrition_serializer = MenuNutritionalValueSerializer(
            data=request.data, context={"request": request, "instance": food}
        )

        if nutrition_serializer.is_valid():
            nutrition_serializer.save()
            return Response(nutrition_serializer.data, status=status.HTTP_201_CREATED)
        return Response(nutrition_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["POST", "GET"], url_path=r"meals/(?P<unique_id>[^/.]+)/images")
    def add_food_images(self, request, slug, unique_id):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        # Retrieve the location instance
        food = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)

        # Update the location
        image_serializer = MenuItemImagesSerializer(data=request.data, context={"request": request, "instance": food})

        if image_serializer.is_valid():
            image_serializer.save()
            return Response(image_serializer.data, status=status.HTTP_201_CREATED)
        return Response(image_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(
        detail=True,
        methods=["POST", "GET"],
        url_path=r"meals/(?P<unique_id>[^/.]+)/nutrition/(?P<nutrition_id>\d+)/remove",
    )
    def remove_food_nutrition(self, request, slug, unique_id, nutrition_id):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        # Retrieve the location instance
        food = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)
        nutrition = get_object_or_404(MenuNutritionalValue, menu_item=food, id=nutrition_id)
        nutrition.delete()

        # Update the location
        nutrition_serializer = MenuItemsSerializer(food, many=False, context={"request": request, "instance": food})

        return Response(nutrition_serializer.data, status=status.HTTP_200_ok)

    @action(
        detail=True, methods=["POST", "GET"], url_path=r"meals/(?P<unique_id>[^/.]+)/images/(?P<image_id>\d+)/remove"
    )
    def remove_food_images(self, request, slug, unique_id, image_id):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        # Retrieve the location instance
        food = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)
        image = get_object_or_404(MenuItemImages, menu_item=food, id=image_id)
        image.delete()

        # Update the location
        image_serializer = MenuItemsSerializer(food, many=False, context={"request": request, "instance": food})

        return Response(image_serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["GET"], url_path=r"view-cart")
    def view_cart(self, request):
        cart = Cart(request)

        if not request.user.is_authenticated:
            raise UnauthorizedException()

        return Response(
            {"data": list(cart.__iter__()), "total_cost": cart.get_total_price(), "total_items": cart.__len__()},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["POST", "GET"], url_path=r"meals/(?P<unique_id>[^/.]+)/add-to-cart")
    def add_to_cart(self, request, slug, unique_id):
        vendor_shop = self.get_object()
        cart = Cart(request)

        if not request.user.is_authenticated:
            raise UnauthorizedException()

        if request.method == "GET":
            MenuItemCartAddSerializer(context={"request": request, "instance": vendor_shop})
            return Response(
                {
                    "data": list(cart.__iter__()),
                    "total_cost": cart.get_total_price(),
                    "total_items": cart.__len__(),
                    "pickup_locations": cart.get_locations(),
                },
                status=status.HTTP_200_OK,
            )

        # Retrieve the location instance
        product = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)
        product_data = MenuItemsSerializer(product, many=False, context={"request": request}).data

        cart_serializer = MenuItemCartAddSerializer(
            data=request.data, context={"request": request, "instance": vendor_shop}
        )

        if cart_serializer.is_valid():
            LOGGER.info("Serializer is valid")
            LOGGER.debug(product_data)
            cart.add(
                product=product_data,
                location=cart_serializer.data.get("location"),
                quantity=cart_serializer.data.get("quantity"),
                overide_quantity=cart_serializer.data.get("override"),
            )
            return Response(
                {
                    "data": list(cart.__iter__()),
                    "total_cost": cart.get_total_price(),
                    "total_items": cart.__len__(),
                    "pickup_locations": cart.get_locations(),
                },
                status=status.HTTP_202_ACCEPTED,
            )
        return Response(cart_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["GET"], url_path=r"meals/(?P<unique_id>[^/.]+)/remove-cart")
    def remove_cart(self, request, slug, unique_id):
        vendor_shop = self.get_object()

        if not request.user.is_authenticated:
            raise UnauthorizedException()

        # Retrieve the location instance
        product = get_object_or_404(MenuItems, unique_id=unique_id, vendor=vendor_shop)
        product_data = MenuItemsSerializer(product, many=False, context={"request": request}).data

        cart = Cart(request)

        cart.remove(product=product_data)
        return Response(
            {
                "data": list(cart.__iter__()),
                "total_cost": cart.get_total_price(),
                "total_items": cart.__len__(),
                "pickup_locations": cart.get_locations(),
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["GET"], url_path="clear-cart")
    def clear_cart(self, request, slug):

        vendor_shop = self.get_object()

        if not request.user.is_authenticated:
            raise UnauthorizedException()

        meals = MenuItems.objects.filter(vendor=vendor_shop)
        meals_serializer = MenuItemsSerializer(meals, many=True, context={"request": request})

        cart = Cart(request)

        cart.clear()
        return Response(meals_serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["POST", "GET"], url_path="create-order")
    def create_order(self, request, slug):
        if not request.user.is_authenticated:
            raise UnauthorizedException()

        cart = Cart(request)
        product = []
        vendor_shop = self.get_object()
        user = request.user
        if request.method == "GET":
            orders = MenuItemOrder.objects.filter(vendor=vendor_shop, user=user)
            order_serializer = MenuItemOrderSerializer(
                orders,
                many=True,
                context={
                    "request": request,
                    "user": user,
                    "vendor": vendor_shop,
                    "meals": product,
                    "amount": 0.00,
                    "quantity": 0,
                },
            )

        amount = cart.get_total_price()
        quantity = cart.__len__()
        items = list(cart.__iter__())
        locations = list(cart.get_locations())
        for item in items:
            LOGGER.info(item)
            product.append(item["product"])

        order_serializer = MenuItemOrderSerializer(
            data=request.data,
            context={
                "request": request,
                "user": user,
                "vendor": vendor_shop,
                "meals": product,
                "amount": amount,
                "quantity": quantity,
            },
        )

        if order_serializer.is_valid():
            order_serializer.save()
            cart.clear()
            return Response(order_serializer.data, status=status.HTTP_201_CREATED)
        return Response(order_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=["PUT", "GET"], url_path=r"hours/(?P<hours_id>\d+)")
    def update_open_hours(self, request, slug, hours_id):
        # Retrieve the VendorShop instance based on the slug
        vendor_shop = self.get_object()

        if not request.user in vendor_shop.users.all():
            raise UnauthorizedObjectException()

        # Retrieve the location instance
        hours = get_object_or_404(OpenHours, id=hours_id, vendor=vendor_shop)

        # Update the location
        openhours_serializer = OpenHoursSerializer(hours, data=request.data, partial=True)
        if openhours_serializer.is_valid():
            openhours_serializer.save()
            return Response(openhours_serializer.data, status=status.HTTP_200_OK)
        return Response(openhours_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
