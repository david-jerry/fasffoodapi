from __future__ import annotations

import pprint

import requests
from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.utils.translation import gettext_lazy as _

# from requests_html import HTMLSession
from ....utils.logger import LOGGER

class Command(BaseCommand):
    """
    Retreives all operational banks in Nigeria
    """

    help = _("Adds or Updates all existing bank names in Nigeria")

    def handle(self, *args, **kwargs):
        url = "https://api.paystack.co/bank"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET}",
        }
        data = {"country": "nigeria", "use_cursor": True, "perPage": 100}

        res = requests.request("GET", url, headers=headers, data=data)
        res = res.json()
        pp = pprint.PrettyPrinter(indent=4)
        LOGGER.info(pp.pprint(res))

        banks = []

        if res["status"]:
            for response in res["data"]:
                try:
                    data = {
                        "name": response['name'],
                        "slug":response["slug"],
                        "lcode":response["longcode"],
                        "code":response["code"],
                        "country_iso":"NG",
                    }
                    banks.append(data)
                    LOGGER.info(f"Successfully added {response['name']}")
                except Exception as e:
                    LOGGER.error(e)

            if not cache.has_key("banks"):
                cache.set("banks", banks, timeout=None)
        else:
            LOGGER.error("Nigerian Banks Not Updated")

        self.stdout.write("Got all Nigeria Bank Details")

