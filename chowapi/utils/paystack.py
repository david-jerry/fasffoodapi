from __future__ import absolute_import

import requests
from decimal import Decimal
from pprint import pprint

from django.conf import settings
from django.core.cache import cache

from chowapi.utils.generators import GENERATOR
from chowapi.utils.logger import LOGGER


class PayStackManager:
    def __init__(self):
        pass

    def create_rider_transfer_recipient(self, bank, user):
        """
        Creates a paystack recipient object for the rider whenever they add a new bank account

        Args:
            bank (BankAccount): BankAccount Instance
            user (User): User instance
        """
        if user.is_rider:
            url = "https://api.paystack.co/transferrecipient"
            headers = {
                "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
            }
            data = {
                "type": "nuban",
                "name": bank.account_name,
                "account_number": bank.account_number,
                "bank_code": bank.bank_id,
                "currency": user.currency,
            }

            res = requests.request("POST", url, headers=headers, data=data)
            res = res.json()
            pp = pprint.PrettyPrinter(indent=4)
            LOGGER.info(pp.pprint(res))

            if res["status"]:
                try:
                    data = {
                        "id": res["data"]["id"],
                        "name": res["data"]["name"],
                        "recipient_code": res["data"]["recipient_code"],
                        "account_number": res["data"]["details"]["account_number"],
                        "bank_code": res["data"]["details"]["bank_code"],
                        "bank_name": res["data"]["details"]["bank_name"],
                    }

                    if not cache.has_key(user.email):
                        cache.set(user.email, data, timeout=None)
                    LOGGER.info(f"Successfully added recipient")
                except Exception as e:
                    LOGGER.error(e)
            else:
                LOGGER.error("Recipient Not Created")

    def create_vendor_transfer_recipient(self, bank, vendor):
        """
        Creates a paystack recipient object for the vendors whenever they add a new bank account

        Args:
            bank (BankAccount): BankAccount Instance
            vendor (VendorShop): VendorShop instance
        """
        url = "https://api.paystack.co/transferrecipient"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }
        data = {
            "type": "nuban",
            "name": bank.account_name,
            "account_number": bank.account_number,
            "bank_code": bank.bank_id,
            "currency": "NGN",
        }

        res = requests.request("POST", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            try:
                data = {
                    "id": res["data"]["id"],
                    "name": res["data"]["name"],
                    "recipient_code": res["data"]["recipient_code"],
                    "account_number": res["data"]["details"]["account_number"],
                    "bank_code": res["data"]["details"]["bank_code"],
                    "bank_name": res["data"]["details"]["bank_name"],
                }

                if not cache.has_key(vendor.slug):
                    cache.set(vendor.slug, data, timeout=None)
                LOGGER.info(f"Successfully added recipient")
            except Exception as e:
                LOGGER.error(e)
        else:
            LOGGER.error("Recipient Not Created")

    def get_recipient_data(self, key: str) -> dict:
        """
        Returns a dictionary of cached recipient information:

        "id": int,
        "name": str,
        "recipient_code": str,
        "account_number": str,
        "bank_code": str,
        "bank_name": str,

        """
        if cache.has_key(key):
            data: dict = cache.get(key)
            return data

    def disable_otp(self):
        """
        Disables otp for transferring money to customers or vendors or riders
        """
        url = "https://api.paystack.co/transfer/disable_otp"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }

        res = requests.request("POST", url, headers=headers)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            return res["message"]
        else:
            LOGGER.error("Disabling OTP has failed")
            return "Disabling OTP has failed"

    def complete_disabling_otp(self, code):
        """
        Complete the otp disabling process by passing the sms code sent to a designated phone number
        """
        url = "https://api.paystack.co/transfer/disable_otp_finalize"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }
        data = {
            "otp": str(code),
        }

        res = requests.request("POST", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            return res["message"]
        else:
            LOGGER.error("Disabling OTP has failed")
            return "Disabling OTP has failed"

    def enable_otp(self):
        """
        Enable otp to ensure customers get otp before sending to them
        """
        url = "https://api.paystack.co/transfer/enable_otp"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }
        res = requests.request("POST", url, headers=headers)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            return res["message"]
        else:
            LOGGER.error("nabling OTP has failed")
            return "Enabling OTP has failed"

    def transfer_to_recipient(self, recipient_code: str, amount: int, reason: str):
        """
        Make transfers to recipient from their account balance.

        If the transfer status is 'otp', then open a new page to accept the otp code from the user
        then complete or finalize the transfer
        """
        reference = f"PO_{GENERATOR.random_string_generator(size=36)}"
        url = "https://api.paystack.co/transfer"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }
        data = {
            "source": "balance",
            "reason": reason,
            "amount": amount,
            "recipient": recipient_code,
            "reference": reference,
        }
        res = requests.request("POST", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            data = {
                "amount": amount,
                "currency": res["data"]["currency"],
                "reason": res["data"]["reason"],
                "status": res["data"]["status"],
                "transaction_code": res["data"]["transfer_code"],
                "transfer_reference": reference,
            }
            return data
        else:
            LOGGER.error("Payout Unsuccessful")
            return None

    def verify_transfer_status(self, reference: str):
        """
        Verify the transfer status
        """
        url = f"https://api.paystack.co/transfer/{reference}"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }
        res = requests.request("GET", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            data = {
                "amount": res["data"]["amount"],
                "currency": res["data"]["currency"],
                "reason": res["data"]["reason"],
                "status": res["data"]["status"],
                "transaction_code": res["data"]["transfer_code"],
                "transfer_reference": res["data"]["reference"],
            }
            return data
        else:
            LOGGER.error("Payout Unsuccessful")
            return None

    def verify_transaction(self, reference: str):
        """
        Verify the transaction status
        """
        url = f"https://api.paystack.co/transfer/{reference}"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }
        res = requests.request("GET", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        if res["status"]:
            data = {
                "amount": res["data"]["amount"],
                "currency": res["data"]["currency"],
                "status": res["data"]["status"],
                "transaction_code": res["data"]["transfer_code"],
                "transfer_reference": res["data"]["reference"],
            }
            return data
        else:
            LOGGER.error("Verifying transaction Unsuccessful")
            return None


PAYSTACK = PayStackManager()
