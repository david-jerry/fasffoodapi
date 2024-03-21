from django.core.cache import cache
from allauth.account.adapter import get_adapter

from chowapi.utils.geolocation import CoordinateUtils

from ..utils.logger import LOGGER
from ..utils.exceptions import VPNDetectedException

class DomainMiddleware:
    """
    Middleware for extracting and storing the domain from the incoming request.

    This middleware retrieves the domain from the request and adds it to the request object.
    Additionally, if the user is authenticated, it saves the domain in the user's profile.

    Usage:
    1. Include this middleware in your Django project settings.
    2. Access the domain in your views or other parts of the application using `request.domain`.

    Example:
    In your Django project settings (settings.py):

    ```python
    MIDDLEWARE = [
        # ... other middlewares
        'path.to.DomainMiddleware',
        # ... other middlewares
    ]
    ```

    In your views or other parts of the application:

    ```python
    def some_view(request):
        # Access the domain from the request
        domain = request.domain
        # ... your logic here
    ```

    Attributes:
        get_response (callable): The next middleware or view function in the Django processing pipeline.
    """

    def __init__(self, get_response):
        """
        Initializes the middleware.

        Args:
            get_response (callable): The next middleware or view function in the Django processing pipeline.
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Handles the processing of the request.

        Args:
            request (HttpRequest): The incoming HTTP request.

        Returns:
            HttpResponse: The HTTP response after processing.
        """
        # Get the domain from the request
        adapter = get_adapter(request)
        user_ip = adapter.get_client_ip(request)
        LOGGER.info(f"MiddleWare Get USerIP: {user_ip}")

        if not cache.has_key(str(user_ip)) and not str(user_ip) == "127.0.0.1":
            GEOLOCATION = CoordinateUtils(request=request)
            response = GEOLOCATION.get_ip_geolocation_info(user_ip)

            # Add the domain to the request
            request.ip = user_ip
            request.country = response['country']
            request.country_code = response['country_code']
            request.continent = response['continent']
            request.continent_code = response['continent_code']
            request.region = response['region']
            request.currency = response['currency_code']
            request.currency_native_short = response['currency_native_short']
            request.country_flag = response['flag_image']
            request.time_zone = response['time_zone']
            request.is_abusive = response['is_abusive']
            request.is_malicious = response['is_malicious']
            request.is_government = response['is_government']
            request.uses_vpn = response['is_vpn_proxy']

            data = {
                "ip":request.ip,
                "country":request.country,
                "country_code":request.country_code,
                "continent":request.continent,
                "continent_code":request.continent_code,
                "region":request.region,
                "currency":request.currency,
                "currency_native_short":request.currency_native_short,
                "country_flag":request.country_flag,
                "time_zone":request.time_zone,
                "is_abusive":request.is_abusive,
                "is_malicious":request.is_malicious,
                "is_government":request.is_government,
                "uses_vpn":request.uses_vpn,
            }
            cache.set(str(request.ip), data, timeout=60*60*4)
        elif not str(user_ip) == "127.0.0.1":
            response = cache.get(str(user_ip))
            request.ip = response['ip']
            request.country = response['country']
            request.country_code = response['country_code']
            request.continent = response['continent']
            request.continent_code = response['continent_code']
            request.region = response['region']
            request.currency = response['currency']
            request.currency_native_short = response['currency_native_short']
            request.country_flag = response['country_flag']
            request.time_zone = response['time_zone']
            request.is_abusive = response['is_abusive']
            request.is_malicious = response['is_malicious']
            request.is_government = response['is_government']
            request.uses_vpn = response['uses_vpn']
        else:
            request.ip = user_ip
            request.country = "Nigeria"
            request.country_code = "NG"
            request.continent = "Africa"
            request.continent_code = "AF"
            request.region = "West Africa"
            request.currency = "Naira"
            request.currency_native_short = "NGN"
            request.country_flag = "https://uxwing.com/wp-content/themes/uxwing/download/flags-landmarks/nigeria-flag-icon.png"
            request.time_zone = "Africa/Lagos"
            request.is_abusive = False
            request.is_malicious = False
            request.is_government = False
            request.uses_vpn = False


        # Check if the ip is from a vpn or not
        if request.uses_vpn:
            raise VPNDetectedException()


        res = self.get_response(request)
        return res
