"""ScamShield detection package."""

from scamshield.detection.call_guard import (
    DEMO_SCENARIOS,
    LiveCallSession,
    call_guard_registry,
)
from scamshield.detection.hindi_support import (
    get_hindi_guidance,
    is_hindi_or_hinglish,
)
from scamshield.detection.link_checker import check_link
from scamshield.detection.message_analyzer import analyze_message

__all__ = [
    "DEMO_SCENARIOS",
    "LiveCallSession",
    "analyze_message",
    "call_guard_registry",
    "check_link",
    "get_hindi_guidance",
    "is_hindi_or_hinglish",
]
