from decimal import Decimal
from django.conf import settings
import requests

from django.core.cache import cache

from thefuzz import fuzz

from chowapi.utils.logger import LOGGER


def get_all_rates(code: str):
    url = "https://currency-converter241.p.rapidapi.com/convert"

    querystring = {"amount": "1", "from": "USD", "to": code.upper()}

    headers = {"X-RapidAPI-Key": settings.RAPIDAPI_KEY, "X-RapidAPI-Host": "currency-converter241.p.rapidapi.com"}

    response = requests.get(url, headers=headers, params=querystring)
    LOGGER.info(response.json())
    return response.json()

def get_bank_id(bank_name) -> str | None:
    """
    Retrieves the cached paystack bank code

    Args:
        bankname (str): Name of the bank

    Returns:
        code (str): Paystack Bank Identifying Code
        or None
    """

    # Retrieve the cached bank list
    cached_banks = cache.get("banks")

    # Check if the bank name exists in the cached list
    if cached_banks:
        for bank in cached_banks:
            similarity_ratio = fuzz.ratio(bank["name"].lower(), bank_name.lower())

            # Adjust the threshold as needed
            if similarity_ratio > 80:
                return bank["code"]

    return None


