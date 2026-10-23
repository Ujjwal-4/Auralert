"""AURALERT MCP Server definition (Streamable HTTP, MCP spec 2025-11-25).

Exposes 10 defensive cybersecurity tools for analyzing suspicious messages,
evaluating links statically, tracking incident case files, recommending next steps,
compiling ready-to-file cybercrime reports, notifying family members, and
conducting interactive elder scam training drills.
"""

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from auralert.cases import (
    add_evidence_service,
    check_repeat_offender_service,
    export_threat_intel_service,
    get_case_service,
    next_steps_service,
    notify_family_service,
    open_case_service,
    set_safe_word_service,
    verify_safe_word_service,
)
from auralert.cases.report_ai import generate_dynamic_report
from auralert.detection import analyze_message as run_analyze_message
from auralert.detection import call_guard_registry
from auralert.detection import check_link as run_check_link
from auralert.drill import score_drill_response as run_score_drill_response
from auralert.drill import start_drill as run_start_drill

# Provide FastMCP alias for compatibility with MCP documentation
FastMCP = MCPServer

# Initialize MCPServer
mcp_server = MCPServer(
    name="AURALERT",
    version="0.1.0",
    instructions=(
        "AURALERT is an expert defensive cybersecurity assistant. "
        "It analyzes suspicious communications, inspects links statically without fetching, "
        "tracks case evidence, prioritizes emergency remedial actions, and drafts official reports."
    ),
)


@mcp_server.tool(
    name="analyze_message",
    description=(
        "Analyze a suspicious message, email, call transcript, or communication for fraud, "
        "urgency tactics, and impersonation. Returns risk score, red flags, and voice-ready guidance."
    ),
)
def analyze_message(
    text: str,
    channel: Literal["sms", "call", "email", "whatsapp", "other"] = "other",
    region: str = "IN",
) -> dict[str, Any]:
    """Analyze suspicious communication for scam patterns.

    Args:
        text: The text content of the message, email, or call transcript.
        channel: Delivery channel (sms, call, email, whatsapp, other).
        region: ISO country code (default 'IN').

    Returns:
        Structured verdict, risk_score (0-100), category, red_flags, and speak.
    """
    return run_analyze_message(text=text, channel=channel, region=region)


@mcp_server.tool(
    name="check_link",
    description=(
        "Perform safe, static analysis of a suspicious URL without fetching or visiting the domain. "
        "Checks for lookalike domains, punycode, IP hosts, URL shorteners, and credential paths."
    ),
)
def check_link(url: str) -> dict[str, Any]:
    """Statically inspect a URL for phishing or spoofing signals without outbound requests.

    Args:
        url: The URL to evaluate statically.

    Returns:
        Structured verdict, risk_score, signals, normalized_domain, and speak.
    """
    return run_check_link(url=url)


@mcp_server.tool(
    name="open_case",
    description=(
        "Create a new scam investigation case file with a short, voice-friendly case ID "
        "to track evidence, payments, and emergency next steps."
    ),
)
def open_case(
    title: str | None = None,
    region: str = "IN",
) -> dict[str, Any]:
    """Create a new stateful incident case file.

    Args:
        title: Optional brief title for the incident.
        region: ISO country code for jurisdiction (default 'IN').

    Returns:
        New case_id and speak confirmation.
    """
    return open_case_service(title=title, region=region)


@mcp_server.tool(
    name="add_evidence",
    description=(
        "Attach a piece of evidence (message text, link, phone call notes, or payment record) "
        "to an existing case file and auto-run security analysis."
    ),
)
def add_evidence(
    case_id: str,
    kind: Literal["message", "link", "call_note", "payment"],
    content: str,
) -> dict[str, Any]:
    """Add evidence to an ongoing case file.

    Args:
        case_id: The identifier of the existing case.
        kind: The type of evidence (message, link, call_note, payment).
        content: The text content, link, or transaction details.

    Returns:
        evidence_id, analysis if applicable, and speak confirmation.
    """
    return add_evidence_service(case_id=case_id, kind=kind, content=content)


@mcp_server.tool(
    name="get_case",
    description=(
        "Retrieve the full incident case file by ID, including logged evidence items, "
        "risk analyses, and chronological incident timeline."
    ),
)
def get_case(case_id: str) -> dict[str, Any]:
    """Retrieve full details of an incident case file.

    Args:
        case_id: The identifier of the case.

    Returns:
        Full case record with evidence list and timeline.
    """
    return get_case_service(case_id=case_id)


@mcp_server.tool(
    name="next_steps",
    description=(
        "Generate prioritized, emergency remedial steps and official reporting helplines "
        "adapted to whether money was lost and the payment mechanism used."
    ),
)
def next_steps(
    case_id: str,
    lost_money: bool = False,
    payment_method: Literal["upi", "card", "bank_transfer", "crypto", "gift_card", "none"] = "none",
) -> dict[str, Any]:
    """Compute prioritized action items based on financial exposure.

    Args:
        case_id: The identifier of the case.
        lost_money: Whether money or sensitive credentials were transferred.
        payment_method: Payment channel if funds were transferred.

    Returns:
        Urgency level, ordered steps with rationales and official channels, and speak.
    """
    return next_steps_service(
        case_id=case_id,
        lost_money=lost_money,
        payment_method=payment_method,
    )


@mcp_server.tool(
    name="generate_report",
    description=(
        "Compile a formal, complaint-ready incident summary in Markdown that the victim "
        "can copy and submit to official national cybercrime portals."
    ),
)
async def generate_report(case_id: str) -> dict[str, Any]:
    """Generate a complaint-ready markdown summary for portal submission.

    Args:
        case_id: The identifier of the case to summarize.

    Returns:
        Markdown complaint text and speak summary.
    """
    return await generate_dynamic_report(case_id=case_id)


@mcp_server.tool(
    name="notify_family",
    description=(
        "Prepare an alert for a trusted family member or caregiver when a dangerous scam or financial "
        "threat is detected. Demo build: the alert is logged to the case file and NOT actually sent."
    ),
)
def notify_family(
    case_id: str | None = None,
    contact_name: str = "your trusted contact",
    relationship: str = "Son",
    alert_channel: Literal["whatsapp", "sms", "alexa_announcement"] = "whatsapp",
    custom_message: str | None = None,
) -> dict[str, Any]:
    """Dispatch an emergency notification to family members.

    Args:
        case_id: Optional case identifier to link the alert to.
        contact_name: Name of trusted family contact.
        relationship: Relation to victim (Son, Daughter, Spouse, Caregiver).
        alert_channel: Channel to send alert (whatsapp, sms, alexa_announcement).
        custom_message: Optional custom message text override.

    Returns:
        Confirmation with alert_id, status, recipient, message, and speak summary.
    """
    return notify_family_service(
        case_id=case_id,
        contact_name=contact_name,
        relationship=relationship,
        alert_channel=alert_channel,
        custom_message=custom_message,
    )


@mcp_server.tool(
    name="start_drill",
    description=(
        "Initiate an interactive scam training drill for elders and family members. "
        "Returns a simulated scenario (electricity cut, digital arrest, bank KYC, courier detention) "
        "and a voice-first challenge."
    ),
)
def start_drill(
    scenario: Literal[
        "electricity_bill", "digital_arrest", "bank_kyc_otp", "courier_customs", "random"
    ] = "random",
    region: str = "IN",
) -> dict[str, Any]:
    """Start an interactive scam training drill.

    Args:
        scenario: Specific scenario key or 'random'.
        region: ISO country code (default 'IN').

    Returns:
        Structured drill payload including drill_id, scenario title, and speak challenge.
    """
    return run_start_drill(scenario=scenario, region=region)


@mcp_server.tool(
    name="score_drill_response",
    description=(
        "Evaluate and score an elder's spoken or typed response to an active scam drill. "
        "Checks whether they safely refused OTP, refused payment, or hung up, providing constructive feedback."
    ),
)
def score_drill_response(
    drill_id: str,
    user_reply: str,
) -> dict[str, Any]:
    """Score a user's response to an active scam drill.

    Args:
        drill_id: Identifier of the active drill.
        user_reply: Spoken or typed response from the user.

    Returns:
        Score (0-100), verdict (PASSED/NEEDS_IMPROVEMENT), feedback, and speak.
    """
    return run_score_drill_response(drill_id=drill_id, user_reply=user_reply)


# ============================================================================
# LIVE CALL GUARD MCP TOOLS
# ============================================================================


@mcp_server.tool(
    name="start_call_guard",
    description=(
        "Initialize a real-time Live Call Guard monitoring session when the user puts a suspicious "
        "speakerphone call on speaker. Tracks cumulative risk across incoming rolling dialogue chunks."
    ),
)
def start_call_guard(
    region: str = "IN",
    language: Literal["en", "hi"] = "en",
) -> dict[str, Any]:
    """Start a real-time live call guard session.

    Args:
        region: ISO country code (default 'IN').
        language: Interaction language ('en' or 'hi').

    Returns:
        Structured session object with call_id and speak confirmation.
    """
    sess = call_guard_registry.start_session(region=region, language=language)
    if language == "hi":
        speak = (
            f"लाइव कॉल गार्ड सत्र {sess.call_id} शुरू हो गया है। "
            "संदिग्ध कॉल को स्पीकर पर रखें, मैं हर वाक्य की निगरानी करूँगा।"
        )
    else:
        speak = (
            f"Live Call Guard session {sess.call_id} is active. "
            "Keep the call on speakerphone; I will monitor in rolling chunks and interrupt if danger is detected."
        )

    return {
        "call_id": sess.call_id,
        "region": sess.region,
        "language": sess.language,
        "cumulative_risk_score": 0,
        "status": "listening",
        "speak": speak,
    }


@mcp_server.tool(
    name="guard_call_chunk",
    description=(
        "Stream a rolling audio transcript chunk into an active Live Call Guard session. "
        "Accumulates risk across chunks and returns immediate interruptive warnings "
        "(e.g., 'They just asked for an OTP, hang up now') when scam patterns are detected."
    ),
)
def guard_call_chunk(
    call_id: str,
    chunk_text: str,
    speaker: Literal["caller", "victim"] = "caller",
    language: Literal["en", "hi"] = "en",
) -> dict[str, Any]:
    """Process an incoming audio chunk from a speakerphone call.

    Args:
        call_id: Identifier of the active Live Call Guard session.
        chunk_text: Spoken words transcribed in this chunk.
        speaker: Who spoke this chunk ('caller' or 'victim').
        language: Spoken language ('en' or 'hi').

    Returns:
        Cumulative risk score (0-100), verdict, urgent warnings, hang_up_recommended, and speak.
    """
    return call_guard_registry.process_chunk(
        call_id=call_id,
        chunk_text=chunk_text,
        speaker=speaker,
        language=language,
    )


@mcp_server.tool(
    name="end_call_guard",
    description=(
        "Conclude an active Live Call Guard session and optionally synthesize all logged chunks "
        "into a permanent AURALERT case file with emergency remedial steps."
    ),
)
def end_call_guard(
    call_id: str,
    create_case: bool = True,
) -> dict[str, Any]:
    """Conclude a Live Call Guard session.

    Args:
        call_id: Identifier of the call session to conclude.
        create_case: Whether to automatically log transcript as a permanent case file.

    Returns:
        Summary with final risk score and case_id if created.
    """
    return call_guard_registry.end_session(call_id=call_id, create_case_file=create_case)


# ============================================================================
# FAMILY SAFE-WORD MCP TOOLS
# ============================================================================


@mcp_server.tool(
    name="set_safe_word",
    description=(
        "Register or update a secret family safe word for a trusted contact (Son, Daughter, Caregiver). "
        "Protects elders and families against 'Hi Mom' impersonation and AI voice-clone emergency scams."
    ),
)
def set_safe_word(
    contact_name: str,
    safe_word: str,
    relationship: str = "Family",
    hint: str | None = None,
) -> dict[str, Any]:
    """Configure a secret family authentication code.

    Args:
        contact_name: Name of trusted family contact (e.g., 'Rohan').
        safe_word: Secret code word agreed upon with family.
        relationship: Relation to user (Son, Daughter, Spouse, Caregiver).
        hint: Optional memory hint for the code word.

    Returns:
        Confirmation status and voice guidance.
    """
    return set_safe_word_service(
        contact_name=contact_name,
        safe_word=safe_word,
        relationship=relationship,
        hint=hint,
    )


@mcp_server.tool(
    name="verify_safe_word",
    description=(
        "Verify an incoming caller's claimed safe word against registered family codes. "
        "Alerts immediately if the caller fails authentication, defending against AI voice clones."
    ),
)
def verify_safe_word(
    contact_name: str,
    candidate_word: str,
) -> dict[str, Any]:
    """Authenticate an incoming caller using secret family safe word.

    Args:
        contact_name: Name of family contact caller claims to be (e.g., 'Rohan').
        candidate_word: The code word uttered by the caller.

    Returns:
        Verification status, verdict, warning if compromised, and speak guidance.
    """
    return verify_safe_word_service(
        contact_name=contact_name,
        candidate_word=candidate_word,
    )


# ============================================================================
# REPEAT-OFFENDER MEMORY MCP TOOLS
# ============================================================================


@mcp_server.tool(
    name="check_repeat_offender",
    description=(
        "Cross-reference a phone number, UPI ID, or domain against past incidents stored in "
        "AURALERT memory to detect serial offenders across multiple cases."
    ),
)
def check_repeat_offender(
    indicator: str,
    indicator_type: Literal["phone", "upi_id", "domain", "auto"] = "auto",
) -> dict[str, Any]:
    """Look up an indicator in AURALERT cross-case intelligence memory.

    Args:
        indicator: Phone number, UPI ID, or domain to search.
        indicator_type: Specific indicator type or 'auto' to infer.

    Returns:
        Match count, list of earlier linked cases, repeat offender flag, and speak summary.
    """
    return check_repeat_offender_service(
        indicator=indicator,
        indicator_type=indicator_type,
    )


@mcp_server.tool(
    name="export_indicators",
    description=(
        "Export all accumulated threat indicators (phones, UPI IDs, malicious domains) "
        "from AURALERT case memory as standardized Cyber Threat Intelligence (CTI) JSON."
    ),
)
def export_indicators(
    format: Literal["json", "csv"] = "json",
) -> dict[str, Any]:
    """Export threat indicators for law enforcement, fraud investigators, or community feeds.

    Args:
        format: Export format (default 'json').

    Returns:
        Structured STIX-compatible Threat Intelligence document and speak summary.
    """
    return export_threat_intel_service(format=format)
