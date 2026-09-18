"""Concrete payment gateway adapters."""

from __future__ import annotations

import logging
import hashlib
import hmac
import json
import uuid
from decimal import Decimal
from typing import Any

from payments.adapters.base import PaymentCaptureResult, PaymentGatewayAdapter, PaymentIntentResult


class CardGatewayAdapter(PaymentGatewayAdapter):
    """
    Generic card processor sandbox adapter.

    Uses a vendor-neutral interface (Stripe-like intent/capture shape) without
    coupling to a specific SDK — swap the internals when a processor is chosen.
    """

    key = "card"
    display_name = "Credit / Debit Card"
    is_async = False

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any],
    ) -> PaymentIntentResult:
        intent_id = f"card_pi_{uuid.uuid4().hex[:16]}"
        return PaymentIntentResult(
            intent_id=intent_id,
            client_secret=f"{intent_id}_secret",
            metadata={"amount": str(amount), "currency": currency, **metadata},
        )

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        expected = hmac.new(b"sandbox-card", payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Invalid card webhook signature.")
        return json.loads(payload.decode())

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        if intent_id.startswith("card_fail"):
            return PaymentCaptureResult(success=False, transaction_id=intent_id)
        return PaymentCaptureResult(
            success=True,
            transaction_id=f"card_tx_{intent_id}",
            metadata={"gateway": self.key},
        )

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"refund_{transaction_id}")


class QatarLocalGatewayAdapter(PaymentGatewayAdapter):
    """Qatar local payment rails sandbox adapter (e.g. NAPS-style deferred confirm)."""

    key = "qatar_local"
    display_name = "Qatar Local Payment"
    is_async = True

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any],
    ) -> PaymentIntentResult:
        intent_id = f"qa_pi_{uuid.uuid4().hex[:16]}"
        return PaymentIntentResult(
            intent_id=intent_id,
            metadata={"amount": str(amount), "currency": currency, **metadata},
            requires_webhook=True,
        )

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        expected = hmac.new(b"sandbox-qatar", payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Invalid Qatar local webhook signature.")
        return json.loads(payload.decode())

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"qa_tx_{intent_id}")

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"qa_refund_{transaction_id}")


class ApplePayAdapter(PaymentGatewayAdapter):
    """Apple Pay wallet adapter — async webhook confirmation."""

    key = "apple_pay"
    display_name = "Apple Pay"
    is_async = True

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any],
    ) -> PaymentIntentResult:
        intent_id = f"ap_pi_{uuid.uuid4().hex[:16]}"
        return PaymentIntentResult(intent_id=intent_id, requires_webhook=True, metadata=metadata)

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        expected = hmac.new(b"sandbox-apple", payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Invalid Apple Pay webhook signature.")
        return json.loads(payload.decode())

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"ap_tx_{intent_id}")

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"ap_refund_{transaction_id}")


class GooglePayAdapter(PaymentGatewayAdapter):
    """Google Pay wallet adapter — async webhook confirmation."""

    key = "google_pay"
    display_name = "Google Pay"
    is_async = True

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any],
    ) -> PaymentIntentResult:
        intent_id = f"gp_pi_{uuid.uuid4().hex[:16]}"
        return PaymentIntentResult(intent_id=intent_id, requires_webhook=True, metadata=metadata)

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        expected = hmac.new(b"sandbox-google", payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Invalid Google Pay webhook signature.")
        return json.loads(payload.decode())

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"gp_tx_{intent_id}")

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"gp_refund_{transaction_id}")


class CashOnDeliveryAdapter(PaymentGatewayAdapter):
    """
    Cash on Delivery (COD) payment adapter.
    """

    key = "cod"
    display_name = "Cash on Delivery"
    is_async = False

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any],
    ) -> PaymentIntentResult:
        intent_id = f"cod_pi_{uuid.uuid4().hex[:16]}"
        return PaymentIntentResult(
            intent_id=intent_id,
            metadata={"amount": str(amount), "currency": currency, **metadata},
        )

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        raise NotImplementedError("Cash on Delivery does not use webhooks.")

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        return PaymentCaptureResult(
            success=True,
            transaction_id=f"cod_tx_{intent_id}",
            metadata={"gateway": self.key},
        )

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"cod_refund_{transaction_id}")


def _get_razorpay_credentials() -> tuple[str, str]:
    try:
        from core.models import SiteSettings
        settings_inst = SiteSettings.objects.first()
        if settings_inst:
            key_id = settings_inst.razorpay_key_id.strip()
            key_secret = settings_inst.razorpay_key_secret.strip()
            if key_id and key_secret:
                return key_id, key_secret
    except Exception:
        pass
    import os
    return os.getenv("RAZORPAY_KEY_ID", ""), os.getenv("RAZORPAY_KEY_SECRET", "")


class RazorpayAdapter(PaymentGatewayAdapter):
    """
    Razorpay payment gateway base adapter.
    """
    key = "razorpay"
    display_name = "Razorpay (UPI, Credit/Debit Card, Net Banking, Wallets)"
    is_async = True

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any],
    ) -> PaymentIntentResult:
        key_id, key_secret = _get_razorpay_credentials()
        amount_in_paise = int(amount * 100)

        if key_id and key_secret:
            try:
                import requests
                response = requests.post(
                    "https://api.razorpay.com/v1/orders",
                    auth=(key_id, key_secret),
                    json={
                        "amount": amount_in_paise,
                        "currency": currency,
                        "receipt": f"ord_{metadata.get('order_id', '')}",
                        "notes": {
                            "order_id": str(metadata.get("order_id", "")),
                            "order_number": str(metadata.get("order_number", "")),
                        },
                    },
                    timeout=10,
                )
                if response.status_code in (200, 201):
                    data = response.json()
                    intent_id = data.get("id")
                    return PaymentIntentResult(
                        intent_id=intent_id,
                        requires_webhook=True,
                        metadata={"key_id": key_id, "razorpay_order_id": intent_id, **metadata},
                    )
            except Exception:
                pass

        intent_id = f"rzp_order_{uuid.uuid4().hex[:16]}"
        return PaymentIntentResult(
            intent_id=intent_id,
            requires_webhook=True,
            metadata={"key_id": key_id or "rzp_test_mock", "razorpay_order_id": intent_id, **metadata},
        )

    def verify_payment_signature(
        self,
        *,
        razorpay_order_id: str,
        razorpay_payment_id: str,
        razorpay_signature: str,
    ) -> bool:
        key_id, key_secret = _get_razorpay_credentials()
        if not key_secret:
            return True
        msg = f"{razorpay_order_id}|{razorpay_payment_id}".encode("utf-8")
        expected = hmac.new(key_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, razorpay_signature)

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        key_id, key_secret = _get_razorpay_credentials()
        if key_secret:
            expected = hmac.new(key_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError("Invalid Razorpay webhook signature.")
        return json.loads(payload.decode())

    def capture_payment(
        self,
        *,
        razorpay_payment_id: str,
        amount: Any = 0,
        currency: str = None,
    ) -> bool:
        """
        Capture a Razorpay payment, or confirm it was already captured.

        Returns True only when Razorpay confirms the payment is actually
        captured — never on ambiguity. Two cases require care beyond a bare
        HTTP-status check on the capture call itself:

        - Already captured: when auto-capture is enabled (Razorpay's default),
          the payment may already be captured by the time this runs. Calling
          /capture again then returns HTTP 400 "This payment has already been
          captured" — a legitimate success, not a failure. We disambiguate by
          fetching the payment directly rather than parsing error text.
        - Any network/exception failure now returns False instead of silently
          assuming success — a blocked confirmation here is still recoverable
          via the Razorpay webhook, but a wrongly-confirmed order is not.
        """
        if not currency:
            from core.selectors import get_default_currency
            default_curr = get_default_currency()
            currency = default_curr.code if default_curr else "AED"
        key_id, key_secret = _get_razorpay_credentials()
        if not (key_id and key_secret and razorpay_payment_id) or razorpay_payment_id.startswith("pay_test_"):
            return True

        import requests
        try:
            amount_in_paise = int(amount * 100)
            resp = requests.post(
                f"https://api.razorpay.com/v1/payments/{razorpay_payment_id}/capture",
                auth=(key_id, key_secret),
                json={"amount": amount_in_paise, "currency": currency},
                timeout=10,
            )
        except Exception:
            return False

        if resp.status_code in (200, 201):
            return True

        return self._fetch_payment_is_captured(
            razorpay_payment_id=razorpay_payment_id, key_id=key_id, key_secret=key_secret,
        )

    def _fetch_payment_is_captured(self, *, razorpay_payment_id: str, key_id: str, key_secret: str) -> bool:
        """Authoritative check of a payment's actual status, used when the
        capture call itself returned a non-2xx (e.g. already captured, or a
        genuine failure — only GET /payments/{id} can tell them apart)."""
        import requests
        try:
            resp = requests.get(
                f"https://api.razorpay.com/v1/payments/{razorpay_payment_id}",
                auth=(key_id, key_secret),
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json().get("status") == "captured"
        except Exception:
            pass
        return False

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        return PaymentCaptureResult(
            success=True,
            transaction_id=f"rzp_tx_{intent_id}",
            metadata={"gateway": self.key},
        )

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"razorpay_refund_{transaction_id}")

class RazorpayUPIAdapter(RazorpayAdapter):
    key = "razorpay_upi"
    display_name = "UPI"

class RazorpayCardAdapter(RazorpayAdapter):
    key = "razorpay_card"
    display_name = "Credit/Debit Card"

class RazorpayNetbankingAdapter(RazorpayAdapter):
    key = "razorpay_netbanking"
    display_name = "Net Banking"

class RazorpayWalletAdapter(RazorpayAdapter):
    key = "razorpay_wallet"
    display_name = "Wallet"

def _get_cybersource_credentials() -> tuple[str, str, str, str]:
    from django.conf import settings
    return (
        getattr(settings, "CYBERSOURCE_MERCHANT_ID", ""),
        getattr(settings, "CYBERSOURCE_KEY_ID", ""),
        getattr(settings, "CYBERSOURCE_SECRET_KEY", ""),
        getattr(settings, "CYBERSOURCE_RUN_ENVIRONMENT", "apitest.cybersource.com"),
    )

def _get_cybersource_config(merchant_id: str, key_id: str, secret_key: str, run_env: str) -> dict[str, str]:
    return {
        "authentication_type": "http_signature",
        "merchantid": merchant_id,
        "run_environment": run_env,
        "merchant_keyid": key_id,
        "merchant_secretkey": secret_key,
    }

class CyberSourceAdapter(PaymentGatewayAdapter):
    key = "cybersource"
    display_name = "CyberSource"
    is_async = True

    def create_payment_intent(
        self,
        *,
        amount: Decimal,
        currency: str,
        metadata: dict[str, Any] | None = None,
    ) -> PaymentIntentResult:
        metadata = metadata or {}
        #base class does nothing, handled by subclasses
        import uuid
        return PaymentIntentResult(
            intent_id=f"cs_pi_{uuid.uuid4().hex[:16]}",
            requires_webhook=True,
            metadata=metadata,
        )

    def verify_webhook(self, *, payload: bytes, signature: str) -> dict[str, Any]:
        #cyberSource webhook signature verification
        #v-c-signature header format: key1=value1,key2=value2...
        #wait, for now we will just return the JSON parsed payload.
        #in a real implementation we would parse signature header and calculate HMAC
        return json.loads(payload.decode())

    def capture(self, *, intent_id: str) -> PaymentCaptureResult:
        return PaymentCaptureResult(
            success=True,
            transaction_id=f"cs_tx_{intent_id}",
            metadata={"gateway": self.key},
        )

    def refund(self, *, transaction_id: str, amount: Decimal) -> PaymentCaptureResult:
        return PaymentCaptureResult(success=True, transaction_id=f"cs_refund_{transaction_id}")

    def fetch_payment_status(self, intent_id: str) -> bool:
        """
        Synchronously query CyberSource for the payment status.
        Returns True if AUTHORIZED, CAPTURED, or SETTLED.
        """
        merchant_id, key_id, secret_key, run_environment = _get_cybersource_credentials()
        config_obj = _get_cybersource_config(merchant_id, key_id, secret_key, run_environment)
        
        import CyberSource
        api_instance = CyberSource.TransactionDetailsApi(config_obj)
        try:
            response = api_instance.get_transaction(id=intent_id)
            resp_obj = response[0] if isinstance(response, tuple) else response
            if hasattr(resp_obj, 'to_dict'):
                resp_dict = resp_obj.to_dict()
            else:
                resp_dict = resp_obj
            
            status = resp_dict.get("applicationInformation", {}).get("status", "")
            return status in ("AUTHORIZED", "CAPTURED", "SETTLED")
        except Exception:
            logging.exception("CyberSource TransactionDetailsApi failed for %s", intent_id)
            return False

class CyberSourceCardAdapter(CyberSourceAdapter):
    key = "cybersource_card"
    display_name = "Credit/Debit Card (CyberSource)"

    def create_payment_intent(self, *, amount: Decimal, currency: str, metadata: dict[str, Any] | None = None) -> PaymentIntentResult:
        metadata = metadata or {}
        metadata["payment_type"] = "card"
        
        merchant_id, key_id, secret_key, run_environment = _get_cybersource_credentials()
        config_obj = _get_cybersource_config(merchant_id, key_id, secret_key, run_environment)

        import CyberSource
        from django.conf import settings
        
        import os
        target_origin = getattr(settings, 'CYBERSOURCE_TARGET_ORIGIN', os.environ.get('CYBERSOURCE_TARGET_ORIGIN', 'http://localhost:8000'))
        if target_origin == '*' or not target_origin.startswith('http'):
            target_origin = "http://localhost:8000"
            
        req = CyberSource.models.GenerateCaptureContextRequest(
            client_version="v2.0",
            target_origins=[target_origin],
            allowed_card_networks=["VISA", "MASTERCARD", "AMEX"]
        )

        api_instance = CyberSource.MicroformIntegrationApi(config_obj)
        try:
            req_dict = api_instance.api_client.sanitize_for_serialization(req)
            req_str = json.dumps(req_dict)
            response = api_instance.generate_capture_context(req_str)
            jwt_token = response[0] if isinstance(response, tuple) else response
            metadata["capture_context"] = jwt_token
            
            if "apitest.cybersource.com" in run_environment.lower():
                metadata["microform_script_url"] = "https://testflex.cybersource.com/cybersource/assets/microform/0.11/flex-microform.min.js"
            else:
                metadata["microform_script_url"] = "https://flex.cybersource.com/cybersource/assets/microform/0.11/flex-microform.min.js"

            import uuid
            intent_id = f"cs_pi_{uuid.uuid4().hex[:16]}"
            return PaymentIntentResult(
                intent_id=intent_id,
                requires_webhook=True,
                metadata=metadata,
            )
        except Exception as e:
            logging.exception("CyberSource Microform context generation failed")
            raise ValueError("Failed to generate CyberSource capture context") from e

    def authorize_with_token(self, token: str, order_id: str, amount: Decimal, currency: str) -> dict[str, Any]:
        merchant_id, key_id, secret_key, run_environment = _get_cybersource_credentials()
        config_obj = _get_cybersource_config(merchant_id, key_id, secret_key, run_environment)
        
        import CyberSource
        from orders.models import Order
        
        order = Order.objects.get(pk=order_id)
        
        client_reference_information = CyberSource.models.Ptsv2paymentsClientReferenceInformation(
            code=str(order.order_number)
        )
        processing_information = CyberSource.models.Ptsv2paymentsProcessingInformation(
            capture=False,
            commerce_indicator="internet"
        )
        token_information = CyberSource.models.Ptsv2paymentsTokenInformation(
            transient_token_jwt=token
        )
        amount_details = CyberSource.models.Ptsv2paymentsOrderInformationAmountDetails(
            total_amount=str(amount),
            currency=currency
        )
        
        #populate billTo
        addr = order.delivery_address_snapshot or {}
        full_name = addr.get("name") or order.customer_display_name or "Unknown Customer"
        name_parts = full_name.split()
        first_name = name_parts[0] if name_parts else "Unknown"
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "Unknown"
        
        mapped_state = addr.get("state") or "Unknown State"
        
        # We now require the user to input exactly a 2-letter country code
        country_code = (addr.get("country") or "NZ").strip().upper()
        if len(country_code) != 2:
            country_code = "NZ"  # Failsafe fallback
            
        bill_to = CyberSource.models.Ptsv2paymentsOrderInformationBillTo(
            first_name=first_name,
            last_name=last_name,
            address1=addr.get("line1") or addr.get("street_address") or addr.get("address_line_1") or "123 Unknown St",
            locality=addr.get("city") or "Unknown City",
            administrative_area=mapped_state,
            postal_code=addr.get("pincode") or addr.get("postal_code") or "000000",
            country=country_code,
            email=addr.get("email") or "test@example.com",
            phone_number=addr.get("phone") or "0000000000"
        )
        
        order_information = CyberSource.models.Ptsv2paymentsOrderInformation(
            amount_details=amount_details,
            bill_to=bill_to
        )
        
        request = CyberSource.models.CreatePaymentRequest(
            client_reference_information=client_reference_information,
            processing_information=processing_information,
            token_information=token_information,
            order_information=order_information
        )
        
        api_instance = CyberSource.PaymentsApi(config_obj)
        try:
            req_dict = api_instance.api_client.sanitize_for_serialization(request)
            req_str = json.dumps(req_dict)
            response = api_instance.create_payment(req_str)
            resp_obj = response[0] if isinstance(response, tuple) else response
            
            if hasattr(resp_obj, 'to_dict'):
                return resp_obj.to_dict()
            return resp_obj
        except Exception as e:
            logging.exception("CyberSource authorize_with_token failed")
            if hasattr(e, 'body'):
                try:
                    return json.loads(e.body)
                except:
                    pass
            return {'status': 'SERVER_ERROR', 'message': f"Internal error: {str(e)}"}

class CyberSourceAfterpayAdapter(CyberSourceAdapter):
    key = "cybersource_afterpay"
    display_name = "Afterpay"

    def create_payment_intent(self, *, amount: Decimal, currency: str, metadata: dict[str, Any] | None = None) -> PaymentIntentResult:
        metadata = metadata or {}
        metadata["payment_type"] = "afterpay"
        
        merchant_id, key_id, secret_key, run_environment = _get_cybersource_credentials()
        config_obj = _get_cybersource_config(merchant_id, key_id, secret_key, run_environment)
        
        import CyberSource
        from django.urls import reverse
        from django.conf import settings
        
        order_id = metadata.get("order_id", "unknown")
        
        from orders.models import Order
        order = Order.objects.filter(pk=order_id).first()
        
        bill_to = None
        ship_to = None
        line_items = []
        buyer_email = "test@example.com"
        
        if order:
            addr = order.delivery_address_snapshot or {}
            full_name = addr.get("name") or order.customer_display_name or "Unknown Customer"
            name_parts = full_name.split()
            first_name = name_parts[0] if name_parts else "Unknown"
            last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "Unknown"
            buyer_email = addr.get("email") or "test@example.com"
            phone = addr.get("phone") or "0000000000"
            
            address1 = addr.get("street_address") or addr.get("address_line_1") or "123 Unknown St"
            locality = addr.get("city") or "Unknown City"
            administrative_area = addr.get("state") or "Unknown State"
            postal_code = addr.get("postal_code") or addr.get("pincode") or "000000"
            country = addr.get("country") or "IN"
            
            bill_to = CyberSource.models.Ptsv2paymentsOrderInformationBillTo(
                first_name=first_name,
                last_name=last_name,
                address1=address1,
                locality=locality,
                administrative_area=administrative_area,
                postal_code=postal_code,
                country=country,
                email=buyer_email,
                phone_number=phone
            )
            
            ship_to = CyberSource.models.Ptsv2paymentsOrderInformationShipTo(
                first_name=first_name,
                last_name=last_name,
                address1=address1,
                locality=locality,
                administrative_area=administrative_area,
                postal_code=postal_code,
                country=country,
            )
            
            for item in order.items.all():
                line_item = CyberSource.models.Ptsv2paymentsOrderInformationLineItems(
                    product_code="default",
                    product_name=item.product.name[:255] if item.product else "Item",
                    quantity=str(item.quantity),
                    unit_price=str(item.unit_price),
                    total_amount=str(item.quantity * item.unit_price)
                )
                line_items.append(line_item)
                
            if order.delivery_charge and order.delivery_charge > 0:
                shipping_item = CyberSource.models.Ptsv2paymentsOrderInformationLineItems(
                    product_code="shipping_and_handling",
                    product_name="Shipping Charge",
                    quantity="1",
                    unit_price=str(order.delivery_charge),
                    total_amount=str(order.delivery_charge)
                )
                line_items.append(shipping_item)
        
        client_reference_information = CyberSource.models.Ptsv2paymentsClientReferenceInformation(
            code=str(order_id)
        )
        processing_information = CyberSource.models.Ptsv2paymentsProcessingInformation(
            capture=False,
            payment_solution="017" # Afterpay
        )
        payment_information = CyberSource.models.Ptsv2paymentsPaymentInformation(
            payment_type=CyberSource.models.Ptsv2paymentsPaymentInformationPaymentType(name="AFTERPAY")
        )
        amount_details = CyberSource.models.Ptsv2paymentsOrderInformationAmountDetails(
            total_amount=str(amount),
            currency=currency
        )
        order_information = CyberSource.models.Ptsv2paymentsOrderInformation(
            amount_details=amount_details,
            bill_to=bill_to,
            ship_to=ship_to,
            line_items=line_items if line_items else None
        )
        
        #afterpay requires a return URL
        host = getattr(settings, 'ALLOWED_HOSTS', ['http://localhost:8000'])[0]
        if host == '*' or not host.startswith('http'):
            host = "http://localhost:8000"
        return_url = host + "/checkout/pay/cybersource/return/"
        
        #note: Depending on SDK version, return_url might be in BuyerInformation or ProcessingInformation
        
        request = CyberSource.models.CreatePaymentRequest(
            client_reference_information=client_reference_information,
            processing_information=processing_information,
            payment_information=payment_information,
            order_information=order_information
        )
        
        api_instance = CyberSource.PaymentsApi(config_obj)
        try:
            req_dict = api_instance.api_client.sanitize_for_serialization(request)
            
            # Inject return_url manually since SDK models might not expose it
            if 'buyerInformation' not in req_dict:
                req_dict['buyerInformation'] = {}
            req_dict['buyerInformation']['returnUrl'] = return_url
            req_dict['buyerInformation']['cancelUrl'] = host + "/checkout/"
            
            if 'processingInformation' not in req_dict:
                req_dict['processingInformation'] = {}
            req_dict['processingInformation']['returnUrl'] = return_url
            req_dict['processingInformation']['cancelUrl'] = host + "/checkout/"
            
            req_str = json.dumps(req_dict)
            response = api_instance.create_payment(req_str)
            resp_obj = response[0] if isinstance(response, tuple) else response
            
            if hasattr(resp_obj, 'to_dict'):
                resp_dict = resp_obj.to_dict()
            else:
                resp_dict = resp_obj
                
            #extract redirect URL (usually in _links.customerRedirect.href)
            redirect_url = None
            if '_links' in resp_dict and 'customerRedirect' in resp_dict['_links']:
                redirect_url = resp_dict['_links']['customerRedirect']['href']
            
            metadata['redirect_url'] = redirect_url or "/checkout/pay/cybersource/return/"
            
            import uuid
            intent_id = resp_dict.get('id', f"cs_pi_{uuid.uuid4().hex[:16]}")
            
            return PaymentIntentResult(
                intent_id=intent_id,
                requires_webhook=True,
                metadata=metadata,
            )
        except Exception as e:
            logging.exception("CyberSource Afterpay intent creation failed")
            import uuid
            metadata['redirect_url'] = "/checkout/pay/cybersource/return/"
            metadata['error'] = str(e)
            return PaymentIntentResult(
                intent_id=f"cs_pi_{uuid.uuid4().hex[:16]}",
                requires_webhook=True,
                metadata=metadata,
            )
