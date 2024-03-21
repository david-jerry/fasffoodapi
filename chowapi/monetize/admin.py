from django.contrib import admin
from .models import (
    CurrencyRates,
    TransactionHistory,
    BankAccount,
)
# Register your models here.
admin.site.register(CurrencyRates)
admin.site.register(TransactionHistory)
admin.site.register(BankAccount)
