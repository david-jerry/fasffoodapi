import pyotp
from chowapi.otp.models import OTPs, VendorOTPs
from chowapi.users.models import User
from chowapi.utils.sms import SMS_SENDER
from chowapi.vendors.models import VendorShop

class OTPManager:
    """
    # OTP Manager
    A utility class for managing One-Time Passwords (OTPs).

    Attributes:
        `totp (pyotp.TOTP)`: The Time-based One-Time Password (TOTP) generator.


    ## Example Usage:
    ```python
    # Initialize the OTPManager
    otp_manager = OTPManager()

    # Generate a TOTP code
    totp_code = otp_manager.generate_totp()

    # Assign the OTP to a user
    user = User.objects.get(id=1)
    otp_manager.assign_otp(user, totp_code)

    # Verify the OTP
    is_verified = otp_manager.verify_otp(totp_code)
    ```

    """

    def __init__(self) -> None:
        """
        Initializes the OTPManager with a TOTP generator using the Django secret key.
        """
        secrets = pyotp.random_base32()
        self.totp = pyotp.TOTP(secrets)

    def generate_totp(self) -> str:
        """
        Generates a Time-based One-Time Password (TOTP) code using the TOTP generator.

        Returns:
            `otp (str)`: The TOTP code.
        """
        return self.totp.now()

    def assign_otp(self, user: User) -> None:
        """
        Assigns an OTP to a user.

        Args:
            `user (User)`: The user object.
            `otp (str)`: The OTP code to assign to the user.
        """
        otp = self.generate_totp()
        OTPs.objects.update_or_create(user=user, defaults={'user': user, 'otp': otp, 'expired': False})
        SMS_SENDER.send_otp(user.phone, otp)
        return None

    def assign_vendor_otp(self, user: VendorShop):
        """
        Assigns an OTP to a vendor.

        Args:
            `user (User)`: The vendor object.
            `otp (str)`: The OTP code to assign to the vendor.
        """
        otp = self.generate_totp()
        VendorOTPs.objects.update_or_create(user=user, defaults={'user': user, 'otp': otp, 'expired': False})
        SMS_SENDER.send_otp(user.phone, otp)
        return None

    def verify_otp(self, otp: str) -> (User | None):
        """
        Verifies an OTP code.

        Args:
            `otp (str)`: The OTP code to verify.

        Returns:
            `bool`: True if the OTP is verified, False otherwise.
        """
        if self.totp.verify(otp):
            try:
                obj = OTPs.objects.get(otp=otp)
                if not obj.user.is_active:
                    obj.user.is_active = True
                    obj.user.save(update_fields=['is_active'])
                    obj.expired = True
                    obj.save()
                return obj.user
            except OTPs.DoesNotExist:
                return None
        return None

    def verify_vendor_otp(self, otp: str) -> (VendorShop | None):
        """
        Verifies an OTP code.

        Args:
            `otp (str)`: The OTP code to verify.

        Returns:
            `bool`: True if the OTP is verified, False otherwise.
        """
        if self.totp.verify(otp):
            try:
                obj = VendorOTPs.objects.get(otp=otp)
                if not obj.user.is_active:
                    obj.user.is_active = True
                    obj.user.save(update_fields=['is_active'])
                    obj.expired = True
                    obj.save()
                return obj.user
            except VendorOTPs.DoesNotExist:
                return None
        return None

OtpManager = OTPManager()
