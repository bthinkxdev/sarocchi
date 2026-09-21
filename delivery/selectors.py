"""Read-only query functions for the delivery app; views must not call the ORM directly."""

from __future__ import annotations

from decimal import Decimal


def get_delivery_charge(*, subtotal: Decimal, address=None, is_cod: bool = False) -> Decimal:
    """
    Return delivery charge based on SiteSettings and City overrides.
    """
    from core.models import SiteSettings
    from delivery.models import City

    if subtotal <= 0:
        return Decimal("0.00")

    settings = SiteSettings.objects.first()
    if not settings:
        return Decimal("0.00")

    if settings.free_shipping_threshold is not None and subtotal >= settings.free_shipping_threshold:
        return Decimal("0.00")

    charge = settings.default_shipping_charge

    if address and hasattr(address, 'city') and address.city:
        city = City.objects.filter(name__iexact=address.city, is_active=True).first()
        if city:
            charge = city.delivery_charge_base

    if is_cod and getattr(settings, "enable_cod", True):
        charge += settings.cod_delivery_charge

    return charge
