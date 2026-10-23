"""AURALERT detection package."""

from auralert.detection.call_guard import (
    DEMO_SCENARIOS,
    LiveCallSession,
    call_guard_registry,
)
from auralert.detection.hindi_support import (
    get_hindi_guidance,
    is_hindi_or_hinglish,
)
from auralert.detection.link_checker import check_link
from auralert.detection.message_analyzer import analyze_message

__all__ = [
    "DEMO_SCENARIOS",
    "LiveCallSession",
    "analyze_message",
    "call_guard_registry",
    "check_link",
    "get_hindi_guidance",
    "is_hindi_or_hinglish",
]
