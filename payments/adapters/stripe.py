"""Stripe payment gateway adapter implementation."""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any

import stripe

from payments.adapters.base import (
    PaymentCaptureResult,
    PaymentGatewayAdapter,
    PaymentIntentResult,
)

logger = logging.getLogger(__name__)

# Currencies where Stripe uses zero decimal places (e.g., 100 JPY = 100, not 10000)
ZERO_DECIMAL_CURRENCIES = {
    "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA",
    "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
}


def to_stripe_amount(amount: Decimal, currency: str) -> int:
    """Convert Decimal amount to Stripe's smallest currency unit (e.g. cents)."""
    curr = (currency or "USD").upper()
    if curr in ZERO_DECIMAL_CURRENCIES:
        return int(round(amount))
    return int(round(amount * 100))


def from_stripe_amount(amount_int: int, currency: str) -> Decimal:
    """Convert Stripe smallest currency unit back to Decimal."""
    curr = (currency or "USD").upper()
    if curr in ZERO_DECIMAL_CURRENCIES:
        return Decimal(amount_int)
    return Decimal(amount_int) / Decimal(100)


def _get_stripe_credentials() -> tuple[str, str, str]:
    """
    Retrieve Stripe credentials.
    Priority: SiteSettings database model -> django.conf.settings -> defaults.
    Returns: (publishable_key, secret_key, webhook_secret)
    """
    pub_key = ""
    sec_key = ""
    wh_secret = ""
    try:
        from core.services import get_site_settings
        site_settings = get_site_settings()
        pub_key = getattr(site_settings, "stripe_publishable_key", "") or ""
        sec_key = getattr(site_settings, "stripe_secret_key", "") or ""
        wh_secret = getattr(site_settings, "stripe_webhook_secret", "") or ""
    except Exception:
        pass

    from django.conf import settings
    if not pub_key:
        pub_key = getattr(settings, "STRIPE_PUBLIC_KEY", "")
    if not sec_key:
        sec_key = getattr(settings, "STRIPE_SECRET_KEY", "")
    if not wh_secret:
        wh_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", "")

    return pub_key.strip(), sec_key.strip(), wh_secret.strip()


class StripePaymentAdapter(PaymentGatewayAdapter):
    """
    Modern Stripe Payment Intent adapter.
    Supports Credit/Debit Cards, Apple Pay, Google Pay, and asynchronous 3D-Secure.
    """

    key = "stripe"
    display_name = "Credit / Debit Card"
    is_async = True

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any] | None = None,
    ) -> PaymentIntentResult:
        """Create a Stripe PaymentIntent with automatic payment methods enabled."""
        pub_key, sec_key, _ = _get_stripe_credentials()
        if not sec_key:
            raise ValueError("Stripe Secret Key is not configured. Please set it in Site Settings or .env.")

        metadata = dict(metadata or {})
        currency_code = (currency or "USD").lower()
        stripe_amount = to_stripe_amount(amount, currency_code)

        intent_params: dict[str, Any] = {
            "amount": stripe_amount,
            "currency": currency_code,
            "metadata": {
                "order_id": str(metadata.get("order_id", "")),
                "order_number": str(metadata.get("order_number", "")),
            },
            "automatic_payment_methods": {"enabled": True},
        }

        #optional customer email for Stripe automatic receipt
        customer_email = metadata.get("customer_email") or metadata.get("email")
        if customer_email:
            intent_params["receipt_email"] = str(customer_email)

        try:
            intent = stripe.PaymentIntent.create(
                api_key=sec_key,
                **intent_params,
            )
            return PaymentIntentResult(
                intent_id=intent.id,
                client_secret=intent.client_secret or "",
                requires_webhook=True,
                metadata={
                    "client_secret": intent.client_secret or "",
                    "publishable_key": pub_key,
                    "amount": str(amount),
                    "currency": currency_code.upper(),
                    **metadata,
                },
            )
        except stripe.StripeError as e:
            logger.exception("Stripe create_payment_intent failed: %s", str(e))
            raise ValueError(f"Stripe payment initiation error: {str(e)}") from e

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        """
        Verify incoming webhook signature using the configured signing secret.
        Returns the parsed event dictionary.
        """
        _, _, wh_secret = _get_stripe_credentials()
        if not wh_secret:
            raise ValueError("Stripe Webhook Secret is not configured.")

        try:
            event = stripe.Webhook.construct_event(
                payload=payload,
                sig_header=signature,
                secret=wh_secret,
            )
            #convert stripe event to standard dict for consistency
            if hasattr(event, "to_dict"):
                return event.to_dict()
            return dict(event)
        except stripe.SignatureVerificationError as e:
            logger.warning("Stripe webhook signature verification failed: %s", str(e))
            raise ValueError("Invalid Stripe webhook signature.") from e
        except Exception as e:
            logger.exception("Failed to parse Stripe webhook payload: %s", str(e))
            raise ValueError(f"Malformed Stripe webhook: {str(e)}") from e

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        """Capture or verify an existing PaymentIntent."""
        _, sec_key, _ = _get_stripe_credentials()
        try:
            intent = stripe.PaymentIntent.retrieve(intent_id, api_key=sec_key)
            if intent.status == "requires_capture":
                intent = stripe.PaymentIntent.capture(intent_id, api_key=sec_key)

            success = intent.status in ("succeeded", "processing")
            return PaymentCaptureResult(
                success=success,
                transaction_id=intent.id,
                metadata={"status": intent.status, "currency": intent.currency},
            )
        except stripe.StripeError as e:
            logger.exception("Stripe capture failed for intent %s: %s", intent_id, str(e))
            return PaymentCaptureResult(
                success=False,
                transaction_id=intent_id,
                metadata={"error": str(e)},
            )

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        """Issue full or partial refund for a captured Stripe PaymentIntent."""
        _, sec_key, _ = _get_stripe_credentials()
        try:
            #transaction_id is the payment_intent id (pi_...)
            refund_params: dict[str, Any] = {
                "payment_intent": transaction_id,
            }
            if amount > Decimal("0"):
                #retrieve intent to know its currency for unit conversion
                intent = stripe.PaymentIntent.retrieve(transaction_id, api_key=sec_key)
                refund_params["amount"] = to_stripe_amount(amount, intent.currency)

            refund_obj = stripe.Refund.create(api_key=sec_key, **refund_params)
            success = refund_obj.status in ("succeeded", "pending")
            return PaymentCaptureResult(
                success=success,
                transaction_id=refund_obj.id,
                metadata={"refund_status": refund_obj.status},
            )
        except stripe.StripeError as e:
            logger.exception("Stripe refund failed for %s: %s", transaction_id, str(e))
            return PaymentCaptureResult(
                success=False,
                transaction_id=transaction_id,
                metadata={"error": str(e)},
            )
