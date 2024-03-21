from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType

from model_utils.models import TimeStampedModel


# Create your models here.
class CurrencyRates(TimeStampedModel):
    currency_code = models.CharField(max_length=6, default="USD")
    amount = models.DecimalField(max_digits=20, decimal_places=2, default=1.00)

    def __str__(self):
        return f"{self.currency_code} - {self.amount}"

    class Meta:
        managed = True
        verbose_name = "Current Rates"
        verbose_name_plural = "Current Rates"


class TransactionHistory(TimeStampedModel):
    PENDING = "Pending"
    COMPLETE = "Complete"
    FAILED = "Failed"
    STATUS = (
        (PENDING, PENDING),
        (COMPLETE, COMPLETE),
        (FAILED, FAILED),
    )

    transaction_id = models.CharField(max_length=100, blank=False, db_index=True)
    status = models.CharField(max_length=25, choices=STATUS, default=PENDING)
    amount = models.DecimalField(max_digits=20, decimal_places=2, default=0.00)
    model = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="transactions")
    model_object_id = models.PositiveBigIntegerField()
    model_object = GenericForeignKey("model", "model_object_id")

    def __str__(self):
        return self.transaction_id

    class Meta:
        managed = True
        verbose_name = "Transaction"
        verbose_name_plural = "Transactions"

class BankAccount(TimeStampedModel):
    model = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="bank_account")
    model_object_id = models.PositiveBigIntegerField()
    model_object = GenericForeignKey("model", "model_object_id")
    bank_id = models.IntegerField(blank=True, null=True)
    account_number = models.CharField(max_length=16)
    account_name = models.CharField(max_length=255)
    bank_name = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.account_name.title()} Bank Account"

    class Meta:
        managed = True
        verbose_name = "Bank Account"
        verbose_name_plural = "Bank Accounts"
