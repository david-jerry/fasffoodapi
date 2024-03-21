from django.core.management.base import BaseCommand
import requests

from chowapi.monetize.models import CurrencyRates
from chowapi.utils.logger import LOGGER
from chowapi.utils.banking import get_all_rates


def update_rates(code, rates) -> None:
    CurrencyRates.objects.update_or_create(
        currency_code=code.upper(),
        defaults= {
            "currency_code": code.upper(),
            "amount": round(rates, 2)
        }
    )
    return None

class Command(BaseCommand):
    help = "Fetch currency rates from RapidAPI and store them in the database."

    def handle(self, *args, **options):
        currencies = [
            "gbp",
            "chf",
            "cad",
            "eur",
            "jpy",
            "ngn",
            "ghs",
        ]
        try:
            for c in currencies:
                response_data = get_all_rates(c)
                LOGGER.info(response_data)
                rate = response_data['rate']

                try:
                    update_rates(code=c.upper(), rates=rate)
                    # Save the rate to your model
                    self.stdout.write(self.style.SUCCESS(f"Currency rate updated"))
                except Exception as e:
                    self.stderr.write(f"Error saving current rates: {e}")
        except requests.RequestException as e:
            self.stderr.write(f"Error fetching currency rate: {e}")
