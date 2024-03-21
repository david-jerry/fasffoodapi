import requests
import redis
from django.conf import settings
from django.utils.timezone import datetime, timedelta

from chowapi.utils.logger import LOGGER

redis_conn = redis.StrictRedis()


class CoordinateUtils:
    def __init__(self, request, redis_url=settings.REDIS_URL):
        """
        Initialize the coordinates and Redis instance for distance and ETA calculations.
        """
        self.request = request
        self.redis_client = redis.from_url(redis_url)
        self.user = None
        if request.user.is_authetnicated:
            if request.user.is_rider and not request.user.rider_particular.on_a_request:
                self.user = request.user

    def get_ip_geolocation_info(ip):
        url = "https://ip-reputation-geoip-and-detect-vpn.p.rapidapi.com/"

        querystring = {"ip": str(ip)}

        headers = {
            "X-RapidAPI-Key": settings.RAPIDAPI_KEY,
            "X-RapidAPI-Host": "ip-reputation-geoip-and-detect-vpn.p.rapidapi.com",
        }

        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            LOGGER.info(response.json())
            return response.json()



    def get_coordinates(name: str) -> dict | None:
        nominatim_url = "https://nominatim.openstreetmap.org/search"
        params = {"format": "json", "q": name}

        response = requests.get(nominatim_url, params=params)

        if response.status_code == 200:
            data = response.json()
            LOGGER.info(len(data))
            LOGGER.info(data)
            if data and isinstance(data, list) and len(data) > 0:
                latitude = data[0]["lat"]
                longitude = data[0]["lon"]
                return {"lon": longitude, "lat": latitude}
            else:
                return None
        return None

    def create_geodata_instance(
        self, key: str, member_name: str | int, location: dict[str, float]
    ) -> None:
        """
        Create a Redis instance with the given key and store the user's location.
        """
        r = self.redis_client
        r.geoadd(key, (location["longitude"], location["latitude"], member_name))

    def store_rider_in_geospatial_db(
        self, rider_email: str, location: dict[str, float]
    ) -> str | None:
        """
        Store rider's location in the Redis geospatial database.
        """
        if self.user is not None:
            key = "riders"
            self.create_redis_instance(key, rider_email, location)
            return "rider coordinates created"
        return None

    def store_vendor_in_geospatial_db(
        self, vendor_slug: str, vendor_location_id: int, location: dict[str, float]
    ) -> str | None:
        """
        Store vendor's location in the Redis geospatial database.
        """
        try:
            key = f"vendors:{vendor_slug}"
            self.create_redis_instance(key, vendor_location_id, location)
            return "rider coordinates created"
        except Exception as e:
            LOGGER.info(str(e))
            return None

    def get_closest_riders(
        self, vendor_location: dict[str, float], limit: int = 10
    ) -> list[list]:
        """
        Get the closest riders to the provided coordinates from the Redis geospatial database.
        """

        key = "riders"  # Adjust the pattern based on your key naming convention
        closest_riders = self.redis_client.georadius(
            key,
            vendor_location["longitude"],
            vendor_location["latitude"],
            unit="km",
            radius=100,
            withdist=True,
            sort="ASC",
            count=limit,
        )
        return closest_riders

    def get_closest_vendors_location(
        self, user_location: dict[str, float], limit: int = 10
    ) -> list[list]:
        """
        Get the closest riders to the provided coordinates from the Redis geospatial database.
        """

        key = "vendors:*"  # Adjust the pattern based on your key naming convention
        closest_vendors = self.redis_client.georadius(
            key,
            user_location["longitude"],
            user_location["latitude"],
            unit="km",
            radius=100,
            withdist=True,
            sort="ASC",
            count=limit,
        )
        return closest_vendors

    def get_distance_to_closest_vendor(self, user_location: dict[str, float]):
        """
        Determine the distance from the provided coordinates to the closest vendor in the geospatial database.
        """
        closest_vendor = self.get_closest_riders(user_location, limit=1)
        if closest_vendor:
            location_id, distance = closest_vendor[0]
            return {"location_id": location_id, "distance": distance}
        return None

    def get_distance_to_closest_rider(self, current_location: dict[str, float]):
        """
        Determine the distance from the provided coordinates to the closest rider in the geospatial database.
        """
        closest_rider = self.get_closest_riders(current_location, limit=1)
        if closest_rider:
            rider_id, distance = closest_rider[0]
            return rider_id, distance
        return None

    def calculate_estimated_time(distance: float, speed: float):
        """
        Calculate the estimated time to arrive at a location.

        Parameters:
        - distance: Distance to travel (in the same unit as the speed, e.g., kilometers)
        - speed: Speed of travel (in the same unit as the distance per unit of time, e.g., kilometers per hour)

        Returns:
        - Estimated time to arrive (in the unit of time, e.g., hours)
        """
        if speed == 0:
            return (
                datetime.now()
            )  # Speed is zero, return infinity to represent infinite time

        estimated_time = distance / speed
        return estimated_time

    def estimated_time_of_arrival(distance: float, speed: float):
        """
        Calculate the estimated time to arrive at a location.

        Parameters:
        - distance: Distance to travel (in the same unit as the speed, e.g., kilometers)
        - speed: Speed of travel (in the same unit as the distance per unit of time, e.g., kilometers per hour)

        Returns:
        - Estimated time to arrive
        """
        if speed == 0:
            return (
                datetime.now()
            )  # Speed is zero, return infinity to represent infinite time

        estimated_time = distance / speed
        minutes = estimated_time * 60
        actual_time = datetime.now() + timedelta(minutes=minutes)
        return actual_time


