from __future__ import absolute_import

import requests

from django.core.exceptions import ValidationError
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache

from thefuzz import fuzz


import stdnum.us.tin
import stdnum.at.tin

import stdnum.us.ssn
import stdnum.at.vnr

from chowapi.utils.logger import LOGGER

import re
from django.core.exceptions import ValidationError

def validate_phone_number_field(value):
    """
    Validate phone number format using regex.
    """
    # Define the regex pattern for phone numbers.
    # This pattern assumes phone numbers are in international format.
    pattern = r'^\+\d{1,3}\d{9,15}$'

    # Compile the regex pattern.
    regex = re.compile(pattern)

    # Check if the value matches the pattern.
    if len(value) > 16:
        raise ValidationError('Invalid phone number format. Must be in this format +234 7064857582')

    if not regex.match(value):
        raise ValidationError('Invalid phone number format. Must be in this format +234 7064857582')
    return value

def validate_bank_name(bank_name) -> bool:
    """
    Validates the bank name checking if there is a match above 70%

    Args:
        bank_name (str): Name of the bank typed in by the user

    Returns:
        bool: True or False if the user matched or not
    """
    # Retrieve the cached bank list
    cached_banks = cache.get("banks")

    # Check if the bank name exists in the cached list
    if cached_banks:
        for bank in cached_banks:
            similarity_ratio = fuzz.ratio(bank["name"].lower(), bank_name.lower())

            # Adjust the threshold as needed
            if similarity_ratio > 80:
                return True

    return False

def validate_ssn(value):
    # Implement your validation logic here, potentially using a regular expression
    # Example:
    if not stdnum.at.vnr.is_valid(value) or not stdnum.us.ssn.is_valid(value):
        raise ValidationError(_("Invalid Social Security Number"))


def validate_tin(value):
    if not stdnum.at.tin.is_valid(value) or not stdnum.us.tin.is_valid(value):
        raise ValidationError(_("Invalid Tas Identification Number"))


def serializer_validate_phone(self, phone, serializers):
    if "+" in phone:
        return phone

    if "+" not in phone:
        raise serializers.ValidationError(_("Must start with +<country_code>. eg: +1"))

    if "@" in phone:
        raise serializers.ValidationError(_("Invalid Character in phone"))
    return phone


def image_validate_file_extension(value):
    LOGGER.info(value)
    valid_extensions: list[str] = [".jpeg", ".jpg", ".png", ".svg"]
    file_extension: str = value.name.split(".")[-1].lower()

    LOGGER.info(file_extension)

    if f".{file_extension}" in valid_extensions:
        return value
    raise ValidationError(_("File type is not supported. Supported file types are: .jpeg, .jpg, .png, .svg"))


def document_validate_file_extension(value):
    valid_extensions: list[str] = [".pdf", ".doc", ".txt"]
    file_extension: str = value.name.split(".")[-1].lower()

    if f".{file_extension}" in valid_extensions:
        return value
    raise ValidationError(_("File type is not supported. Supported file types are: .pdf, .doc, .docx"))


def video_validate_file_extension(value):
    valid_extensions: list[str] = [".mp4", ".mov", ".webm"]
    file_extension: str = value.name.split(".")[-1].lower()

    if f".{file_extension}" in valid_extensions:
        return value
    raise ValidationError(_("File type is not supported. Supported file types are: .mp4, .mov, .webm"))


def validate_credit_card(value, serializers):
    url = "https://check-credit-card.p.rapidapi.com/detect"

    payload = value
    headers = {
        "content-type": "application/json",
        "X-RapidAPI-Key": settings.RAPID_API_KEY,
        "X-RapidAPI-Host": "check-credit-card.p.rapidapi.com",
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        res = response.json()
        if not res["valid"]:
            raise serializers.ValidationError(_("Invalid credit card"))
        return value
