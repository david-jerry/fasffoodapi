

from decimal import Decimal


def convert_amount(amount, currency):
    from chowapi.monetize.models import CurrencyRates

    if currency == "USD":
        return round(amount, 2)
    # Retrieve the exchange rates from the database
    to_rate: CurrencyRates = CurrencyRates.objects.get(currency_code=currency)

    # Perform the conversion
    converted_amount = Decimal(amount) * to_rate.amount

    return round(converted_amount, 2)
