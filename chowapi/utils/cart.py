from decimal import Decimal
from typing import DefaultDict

from django.conf import settings
from chowapi.utils.logger import LOGGER

from chowapi.vendors.api.serializers import LocationsSerializer, MenuItemsSerializer
from chowapi.vendors.models import Locations, MenuItems

class Cart:
    def __init__(self, request):
        """
        initialize the cart
        """
        self.session = request.session
        self.request = request
        cart = self.session.get(settings.CART_SESSION_ID)
        if not cart:
            # save an empty cart in session
            cart = self.session[settings.CART_SESSION_ID] = {}
        self.cart = cart

    def save(self):
        self.session.modified = True

    def add(self, product, location=None, quantity=1, overide_quantity=False):
        """
        Add product to the cart or update its quantity
        """

        product_id = str(product["unique_id"])
        if product_id not in self.cart:
            self.cart[product_id] = {
                "quantity": 0,
                "price": str(product["actual_price"])
            }

        if location:
            self.cart[product_id]['pickup_location'] = location
        if overide_quantity:
            self.cart[product_id]["quantity"] = quantity
        else:
            self.cart[product_id]["quantity"] += quantity
        self.save()

    def remove(self, product):
        """
        Remove a product from the cart
        """
        product_id = str(product["unique_id"])

        if product_id in self.cart:
            del self.cart[product_id]
            self.save()

    def __iter__(self):
        """
        Loop through cart items and fetch the products from the database
        """
        product_ids = self.cart.keys()
        products = MenuItems.objects.filter(unique_id__in=product_ids)
        cart = self.cart.copy()

        # Group products by store
        products_by_store = DefaultDict(list)
        for product in products:
            p = MenuItemsSerializer(product, context={'request': self.request}).data
            LOGGER.info(p)
            cart[str(product.unique_id)]["product"] = p
            products_by_store[product.vendor.name].append(cart[str(product.unique_id)])

        # Clear location information and yield product information
        for store_name, products_in_store in products_by_store.items():
            yield {
                'store_name': store_name,
                'products': [
                    {
                        'product': item['product'],
                        'quantity': item['quantity'],
                        'price': float(item['price']),
                        'total_price': float(item['price']) * item['quantity'],
                    }
                    for item in products_in_store
                ]
            }

    def get_locations(self):
        """
        Get a list of locations with store names and location information
        """
        location_ids = {item['pickup_location'] for item in self.cart.values() if 'pickup_location' in item}
        locations = Locations.objects.filter(id__in=location_ids)
        locations_data = LocationsSerializer(locations, many=True, context={'request': self.request}).data
        rt_data = []
        for data in locations_data:
            dt = {
                'store_name': data['vendor'],
                'store_address': data['address'],
                'store_phone': data['phone'],
                'longitude': data['longitude'],
                'latitude': data['latitude'],
            }
            rt_data.append(dt)
        return rt_data


    def __len__(self):
        """
        Count all items in the cart
        """
        return sum(item["quantity"] for item in self.cart.values())

    def get_total_price(self):
        return float(sum(float(item["price"]) * item["quantity"] for item in self.cart.values()))

    def clear(self):
        # remove cart from session
        del self.session[settings.CART_SESSION_ID]
        self.save()
