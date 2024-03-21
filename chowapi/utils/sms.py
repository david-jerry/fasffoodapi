from twilio.http.async_http_client import AsyncTwilioHttpClient
from twilio.rest import Client
from django.conf import settings

from chowapi.utils.logger import LOGGER


class SMSSender:
    """
    # SMS Sender
    A synchronous utility class for sending SMS messages.

    ## Usage Examples:
    ```python
    sender = SMSSender()

    ### Send OTP
    sender.send_otp("+1234567890", "123456")

    ### Send location
    sender.send_location("+1234567890", "123 Main St, City, Country", 40.7128, -74.0060)

    ### Sample usage within a Django REST Framework viewset:

    class UserViewSet(viewsets.ModelViewSet):
        queryset = User.objects.all()
        serializer_class = UserSerializer  # Replace with your serializer

        @action(detail=True, methods=['post'])
        def send_sms(self, request, pk=None):
            user = self.get_object()
            sender = SMSSender()

            # Example: Sending an OTP
            sender.send_otp(user.phone_number, "123456")

            # Example: Sending a location
            sender.send_location(user.phone_number, "123 Main St, City, Country", 40.7128, -74.0060)

            # You can add more logic here as needed

            return Response({"message": "SMS sent successfully"})
    ```
    """

    def __init__(self):
        self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

    def send_otp(self, to: str, otp: str) -> bool:
        """
        Sends an OTP (One-Time Password) to the specified phone number.

        Args:
            `to (str)`: The recipient's phone number.
            `otp (str)`: The OTP code to be sent.

        Example:
        ```python
            sender.send_otp("+1234567890", "123456")
        ```
        """
        message = f"""Your OTP is:

    [ {otp} ]

-------------------------
OTP expired in 5mins
"""
        self.send_sms(to, message)
        return True

    def send_location(self, to: str, address: str, latitude: float, longitude: float) -> bool:
        """
        Sends a location address along with latitude and longitude to the specified phone number.

        Args:
            `to (str)`: The recipient's phone number.
            `address (str)`: The address to be sent.
            `latitude (float)`: The latitude of the location.
            `longitude (float)`: The longitude of the location.

        Example:
        ```python
            sender.send_location("+1234567890", "123 Main St, City, Country", 40.7128, -74.0060)
        ```
        """
        message = f"""
Delivery Details
Address: {address}.
Latitude: {latitude},
Longitude: {longitude},
            """
        self.send_sms(to, message)
        return True

    def send_sms(self, to: str, message: str) -> None | bool:
        """
        Sends an SMS message to the specified phone number.

        Args:
            `to (str)`: The recipient's phone number.
            `message (str)`: The message content.

        Example:
        ```python
            sender.send_sms("+1234567890", "Hello, world!")
        ```
        """
        try:
            self.client.messages.create(
                to=to, from_=settings.TWILIO_PHONE_NUMBER, body=message
            )
        except Exception as e:
            LOGGER.error(str(e))
            return False


class AsyncSMSSender:
    """
    # Async SMS Sender
    A Asynchronous utility class for sending SMS messages and generating TOTP codes asynchronously.

    ## Usage Examples:
    ```python
    sender = AsyncSMSSender()

    ### Send OTP
    await sender.send_otp("+1234567890", "123456")

    ### Send location
    await sender.send_location("+1234567890", "123 Main St, City, Country", 40.7128, -74.0060)

    ### Sample usage within a Django REST Framework viewset:

    class UserViewSet(viewsets.ModelViewSet):
        queryset = User.objects.all()
        serializer_class = UserSerializer  # Replace with your serializer

        @action(detail=True, methods=['post'])
        async def send_sms(self, request, pk=None):
            user = self.get_object()
            sender = AsyncSMSSender()

            # Example: Sending an OTP
            await sender.send_otp(user.phone_number, "123456")

            # Example: Sending a location
            await sender.send_location(user.phone_number, "123 Main St, City, Country", 40.7128, -74.0060)

            # You can add more logic here as needed

            return Response({"message": "SMS sent successfully"})
    ```
    """

    def __init__(self):
        http_client = AsyncTwilioHttpClient()
        self.client = Client(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN,
            http_client=http_client,
        )

    async def send_otp(self, to, otp):
        """
        Sends an OTP (One-Time Password) to the specified phone number asynchronously.

        Args:
            to (str): The recipient's phone number.
            otp (str): The OTP code to be sent.

        Example:
        ```python
            await sender.send_otp("+1234567890", "123456")
        ```
        """
        message = f"Your OTP is: {otp}"
        await self.send_sms(to, message)

    async def send_location(self, to, address, latitude, longitude):
        """
        Sends a location address along with latitude and longitude to the specified phone number asynchronously.

        Args:
            to (str): The recipient's phone number.
            address (str): The address to be sent.
            latitude (float): The latitude of the location.
            longitude (float): The longitude of the location.

        Example:
        ```python
            await sender.send_location("+1234567890", "123 Main St, City, Country", 40.7128, -74.0060)
        ```
        """
        message = (
            f"Your address is: {address}. Latitude: {latitude}, Longitude: {longitude}"
        )
        await self.send_sms(to, message)

    async def send_sms(self, to, message):
        """
        Sends an SMS message to the specified phone number asynchronously.

        Args:
            to (str): The recipient's phone number.
            message (str): The message content.

        Example:
        ```python
            await sender.send_sms("+1234567890", "Hello, world!")
        ```
        """
        await self.client.messages.create_async(
            to=to, from_=settings.TWILIO_PHONE_NUMBER, body=message
        )


SMS_SENDER = SMSSender()
