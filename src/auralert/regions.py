"""Regional reporting configurations, helplines, and portal guidance."""

import json
from pathlib import Path
from typing import Any

DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "regions.json"


def load_regions() -> dict[str, Any]:
    """Load regional data from data/regions.json."""
    if DATA_PATH.exists():
        try:
            with open(DATA_PATH, encoding="utf-8") as f:
                data = json.load(f)
                return data.get("regions", {})
        except (OSError, json.JSONDecodeError):
            pass
    return {}


REGIONS_CACHE = load_regions()


def get_region_data(region_code: str = "IN") -> dict[str, Any]:
    """Get region guidance data with fallback to India (IN)."""
    regions = REGIONS_CACHE or load_regions()
    code = (region_code or "IN").upper().strip()
    return regions.get(code, regions.get("IN", {}))


def get_official_portal_url(region_code: str = "IN") -> str:
    """Get official cybercrime reporting URL."""
    reg = get_region_data(region_code)
    return reg.get("portal_url", "https://cybercrime.gov.in")


def get_helpline_number(region_code: str = "IN") -> str:
    """Get primary emergency cyber helpline number."""
    reg = get_region_data(region_code)
    return reg.get("helpline", "1930")


def get_payment_steps(
    region_code: str = "IN",
    payment_method: str = "none",
) -> list[dict[str, Any]]:
    """Retrieve prioritized remediation checklist for a payment method and region."""
    reg = get_region_data(region_code)
    guidance = reg.get("payment_guidance", {})
    method = (payment_method or "none").lower().strip()
    return guidance.get(method, guidance.get("none", []))
