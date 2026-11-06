from datetime import datetime

from pydantic import ConfigDict, Field, field_validator

from backend.common.schema import SchemaBase
from backend.core.conf import settings


class CheckoutParam(SchemaBase):
    pack: str = Field(max_length=32)
    # Mobile Money number that pays; defaults to the account's phone.
    phone: str | None = None
    # Promo code (affiliate program) typed at checkout.
    promo_code: str | None = Field(default=None, max_length=16)

    @field_validator('phone')
    @classmethod
    def _digits(cls, v: str | None) -> str | None:
        if not v or not v.strip():
            return None
        raw = v.strip()
        digits = ''.join(ch for ch in raw if ch.isdigit())
        if not raw.startswith('+') and digits.startswith('00'):
            digits = digits[2:]
        elif not raw.startswith('+') and digits.startswith('0'):
            digits = settings.PHONE_DEFAULT_COUNTRY_CODE + digits
        if not (8 <= len(digits) <= 15):
            raise ValueError('Numéro Mobile Money invalide.')
        return digits


class GetPayment(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    x_id: str
    pack: str
    amount: int
    list_price: int | None = None
    promo_code: str | None = None
    credits: int
    validity_days: int | None = None
    status: str
    paid_at: datetime | None = None
    created_time: datetime


class GetCheckout(GetPayment):
    checkout_url: str
