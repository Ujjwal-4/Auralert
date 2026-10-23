"""Deterministic rule-based fallback router for simulated Alexa+ brain.

Guarantees 100% demo reliability even when Bedrock API is unreachable,
credentials are absent, or requests time out.
Maps user intents directly to MCP tool calls and formats calm voice responses.
"""

import logging
import re

from scamshield.agent.mcp_client import mcp_client
from scamshield.agent.schemas import AgentResponse, AgentUIState, ToolCallRecord
from scamshield.agent.session import session_store
from scamshield.detection.hindi_support import get_hindi_guidance, is_hindi_or_hinglish

logger = logging.getLogger("scamshield.fallback")

# Natural-language intent patterns (supplement the exact phrase lists below)
_SET_SAFE_RE = re.compile(
    r"\b(?:set|create|make|add|choose|register)\b.{0,40}\b(?:safe\s?word|code\s?word)\b"
)
_VERIFY_SAFE_RE = re.compile(
    r"\b(?:safe\s?word|code\s?word)\b.{0,60}\b(?:is|says|said|was)\b|\b(?:says|said)\b.{0,40}\b(?:safe\s?word|code\s?word)\b"
)
_OFFENDER_RE = re.compile(
    r"(?:reported\s+before|known\s+scammer|scam\s+number|seen\s+before|check\s+(?:if\s+)?(?:the\s+|this\s+)?(?:number|upi|id))"
)
_NEGATED_FAMILY_RE = re.compile(
    r"\b(?:do\s+not|don't|dont|never|must\s+not|should\s+not|not)\b.{0,15}\b(?:alert|notify|warn|inform|tell)\b"
)


def _wants_family_alert(text_lower: str) -> bool:
    """True only for a genuine request to alert family, not a scammer's 'do not inform your family'."""
    return bool(_FAMILY_RE.search(text_lower)) and not _NEGATED_FAMILY_RE.search(text_lower)


_FAMILY_RE = re.compile(
    r"\b(?:alert|notify|warn|inform)\b.{0,25}\b(?:family|son|daughter|wife|husband|parents?|caregiver)\b"
)

CATEGORY_NAMES = {
    "digital_arrest": "Digital Arrest & Police Extortion",
    "kyc_otp": "KYC Suspension & OTP Harvesting",
    "upi_collect_request": "UPI Collect Request & Fake Cashback",
    "courier_customs": "Courier Seizure & Customs Penalty",
    "fake_job": "Work From Home & Task Scam",
    "tech_support": "Tech Support Impersonation",
    "bank_impersonation": "Bank Impersonation & Card Security",
    "gift_card_crypto": "Gift Card & Crypto Payment Pressure",
    "prize_lottery": "Lottery & Lucky Draw Prize Fraud",
    "romance_investment": "Romance & Guaranteed Investment Fraud",
    "phishing_link": "Phishing Link & Typosquatted Domain",
    "financial_loss": "Financial Loss & Golden Hour Drain",
    "legitimate_notification": "Legitimate Automated Security Notice",
    "general_fraud": "Suspected Fraud / Social Engineering",
}


def _extract_url(text: str) -> str | None:
    """Find URL in user message."""
    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+|[a-zA-Z0-9.-]+\.(?:com|in|org|net|top|xyz|live|fit)[^\s<>\"']*"
    match = re.search(url_pattern, text)
    return match.group(0) if match else None


def _detect_payment_method(text: str) -> str:
    """Identify payment method mentioned in user text."""
    lower = text.lower()
    if any(w in lower for w in ("upi", "gpay", "phonepe", "paytm", "vpa")):
        return "upi"
    if any(w in lower for w in ("card", "credit card", "debit card", "cvv")):
        return "card"
    if any(w in lower for w in ("bank transfer", "neft", "imps", "rtgs", "wire")):
        return "bank_transfer"
    if any(w in lower for w in ("crypto", "bitcoin", "usdt", "wallet")):
        return "crypto"
    if any(w in lower for w in ("gift card", "apple card", "amazon card", "steam")):
        return "gift_card"
    return "none"


async def handle_fallback_turn(
    session_id: str,
    message: str,
    region: str = "IN",
) -> AgentResponse:
    """Execute deterministic intent routing and call MCP tools."""
    session = session_store.get_or_create(session_id, region)
    text_lower = message.lower()
    tool_calls: list[ToolCallRecord] = []
    case_id = session.case_id

    # 0A. Intent: Active Scam Drill Scoring (Elder Training response)
    if session.active_drill_id and not any(
        w in text_lower for w in ("cancel drill", "stop drill", "exit drill")
    ):
        drill_id = session.active_drill_id
        session.active_drill_id = None
        score_res = await mcp_client.call_tool(
            "score_drill_response", {"drill_id": drill_id, "user_reply": message}
        )
        tool_calls.append(
            ToolCallRecord(
                name="score_drill_response",
                arguments={"drill_id": drill_id, "user_reply": message},
                result_summary=score_res,
            )
        )
        ui_state = AgentUIState(
            case_id=case_id,
            urgency="normal",
            drill_state=score_res,
        )
        return AgentResponse(
            reply=score_res.get("speak", "Drill evaluation complete."),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 0B. Intent: Start Scam Drill (Elder Training)
    if any(
        w in text_lower
        for w in (
            "start drill",
            "scam drill",
            "practice scam",
            "practice drill",
            "elder drill",
            "elder training",
            "test my vigilance",
            "training mode",
            "start a drill",
        )
    ):
        scenario = "random"
        if "electricity" in text_lower or "power" in text_lower:
            scenario = "electricity_bill"
        elif "digital arrest" in text_lower or "police" in text_lower or "cbi" in text_lower:
            scenario = "digital_arrest"
        elif "kyc" in text_lower or "otp" in text_lower or "bank" in text_lower:
            scenario = "bank_kyc_otp"
        elif "courier" in text_lower or "customs" in text_lower or "fedex" in text_lower:
            scenario = "courier_customs"

        drill_res = await mcp_client.call_tool(
            "start_drill", {"scenario": scenario, "region": region}
        )
        session.active_drill_id = drill_res.get("drill_id")
        tool_calls.append(
            ToolCallRecord(
                name="start_drill",
                arguments={"scenario": scenario, "region": region},
                result_summary=drill_res,
            )
        )
        ui_state = AgentUIState(
            case_id=case_id,
            urgency="normal",
            drill_state=drill_res,
        )
        return AgentResponse(
            reply=drill_res.get("speak", "Starting scam drill."),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 0C. Intent: Notify Family / Emergency Contact
    if _wants_family_alert(text_lower) or any(
        w in text_lower
        for w in (
            "notify family",
            "notify my family",
            "alert my son",
            "alert family",
            "warn family",
            "tell my family",
            "send family alert",
            "notify son",
            "notify daughter",
            "emergency contact",
        )
    ):
        fam_res = await mcp_client.call_tool(
            "notify_family",
            {
                "case_id": case_id,
                "contact_name": "your trusted contact",
                "relationship": "family member",
                "alert_channel": "whatsapp",
            },
        )
        case_id = fam_res.get("case_id", case_id)
        session_store.update_case_id(session_id, case_id)
        tool_calls.append(
            ToolCallRecord(
                name="notify_family",
                arguments={"case_id": case_id, "contact_name": "your trusted contact"},
                result_summary=fam_res,
            )
        )
        ev_list = []
        case_risk = 90
        case_verdict = "likely_scam"
        case_cat = "general_fraud"
        red_flags = []
        if case_id:
            try:
                full_case = await mcp_client.call_tool("get_case", {"case_id": case_id})
                ev_list = full_case.get("evidence", [])
                for ev in ev_list:
                    an = ev.get("analysis") or {}
                    if an.get("risk_score"):
                        case_risk = max(case_risk, an["risk_score"])
                    if an.get("verdict"):
                        case_verdict = an["verdict"]
                    if an.get("category"):
                        case_cat = an["category"]
                    red_flags.extend(an.get("red_flags", []))
            except Exception as e:  # noqa: BLE001 - best-effort enrichment must never break a turn
                logger.debug("Failed to fetch case: %s", e)

        ui_state = AgentUIState(
            case_id=case_id,
            risk_score=case_risk,
            verdict=case_verdict,
            category=case_cat,
            category_name=CATEGORY_NAMES.get(case_cat, "Family Emergency Alert"),
            red_flags=red_flags,
            evidence=ev_list,
            urgency="immediate",
            family_alert=fam_res,
        )
        return AgentResponse(
            reply=fam_res.get(
                "speak", "I have prepared an alert for your family (demo: it is not actually sent)."
            ),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 0D. Intent: Live Call Guard Initiation
    if any(
        w in text_lower
        for w in (
            "live call guard",
            "start call guard",
            "guard call",
            "listen to call",
            "listen to my call",
            "call guard",
            "put call on speaker",
            "call on speaker",
            "कॉल सुनो",
            "कॉल गार्ड",
        )
    ):
        lang = "hi" if is_hindi_or_hinglish(message) else "en"
        guard_res = await mcp_client.call_tool(
            "start_call_guard", {"region": region, "language": lang}
        )
        tool_calls.append(
            ToolCallRecord(
                name="start_call_guard",
                arguments={"region": region, "language": lang},
                result_summary=guard_res,
            )
        )
        ui_state = AgentUIState(
            case_id=case_id,
            urgency="normal",
            category="live_call_guard",
            category_name="Live Call Guard",
        )
        return AgentResponse(
            reply=guard_res.get("speak", "Live Call Guard is active on speakerphone."),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 0E. Intent: Set Family Safe Word
    if _SET_SAFE_RE.search(text_lower) or any(
        w in text_lower
        for w in (
            "set safe word",
            "set safeword",
            "set code word",
            "set family safe word",
            "सेफ वर्ड सेट",
            "कोड वर्ड सेट",
        )
    ):
        # Extract word from quotes or after keyword
        word_match = re.search(
            r"(?:word|safeword|is|to)\s+['\"]?([a-zA-Z0-9_-]+)['\"]?", message, re.IGNORECASE
        )
        safe_word = word_match.group(1) if word_match else "Falcon"
        contact_name = "Rohan (Son)"
        if "daughter" in text_lower:
            contact_name = "Priya (Daughter)"
        elif "spouse" in text_lower or "wife" in text_lower or "husband" in text_lower:
            contact_name = "Spouse"

        safe_res = await mcp_client.call_tool(
            "set_safe_word",
            {
                "contact_name": contact_name,
                "safe_word": safe_word,
                "relationship": "Family",
            },
        )
        tool_calls.append(
            ToolCallRecord(
                name="set_safe_word",
                arguments={"contact_name": contact_name, "safe_word": safe_word},
                result_summary=safe_res,
            )
        )
        ui_state = AgentUIState(
            case_id=case_id,
            urgency="normal",
            category="family_safeguard",
            category_name="Family Safe-Word Shield",
        )
        return AgentResponse(
            reply=safe_res.get("speak", f"Safe word '{safe_word}' set for {contact_name}."),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 0F. Intent: Verify Family Safe Word
    if _VERIFY_SAFE_RE.search(text_lower) or any(
        w in text_lower
        for w in (
            "verify safe word",
            "check safe word",
            "verify code word",
            "safe word is",
            "safeword is",
            "code word is",
            "सेफ वर्ड चेक",
            "कोड वर्ड है",
        )
    ):
        # Take the word that follows "safe word is ..." (the last mention), not the first "is"
        word_matches = re.findall(
            r"(?:safe\s?word|code\s?word)\s*(?:is|was|says|said|:)?\s*['\"]?([A-Za-z0-9_-]+)",
            message,
            re.IGNORECASE,
        )
        cand_word = word_matches[-1] if word_matches else "unknown"
        contact_name = "Rohan (Son)"
        if "daughter" in text_lower:
            contact_name = "Priya (Daughter)"

        verify_res = await mcp_client.call_tool(
            "verify_safe_word",
            {
                "contact_name": contact_name,
                "candidate_word": cand_word,
            },
        )
        tool_calls.append(
            ToolCallRecord(
                name="verify_safe_word",
                arguments={"contact_name": contact_name, "candidate_word": cand_word},
                result_summary=verify_res,
            )
        )
        is_verified = verify_res.get("verified", False)
        ui_state = AgentUIState(
            case_id=case_id,
            urgency="normal" if is_verified else "immediate",
            verdict="safe" if is_verified else "likely_scam",
            risk_score=10 if is_verified else 95,
            category="family_safeguard",
            category_name="Family Safe-Word Authentication",
            red_flags=[]
            if is_verified
            else [
                {
                    "code": "SAFE_WORD_MISMATCH",
                    "explanation": "Caller failed family authentication check",
                }
            ],
        )
        return AgentResponse(
            reply=verify_res.get("speak", "Family safe word check completed."),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 0G. Intent: Repeat Offender Check
    if _OFFENDER_RE.search(text_lower) or any(
        w in text_lower
        for w in (
            "repeat offender",
            "check repeat offender",
            "repeat scammer",
            "is this number known",
            "check this number",
            "check upi id",
        )
    ):
        # Extract indicator
        phone_match = re.search(
            r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b[6-9]\d{9}\b", message
        )
        upi_match = re.search(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b", message)
        domain_match = re.search(
            r"https?://[^\s<>\"']+|www\.[^\s<>\"']+|[a-zA-Z0-9.-]+\.(?:com|in|org|net|top|xyz)[^\s<>\"']*",
            message,
        )

        ind = (
            phone_match.group(0)
            if phone_match
            else (
                upi_match.group(0)
                if upi_match
                else (domain_match.group(0) if domain_match else "+919876543210")
            )
        )
        rep_res = await mcp_client.call_tool(
            "check_repeat_offender",
            {"indicator": ind, "indicator_type": "auto"},
        )
        tool_calls.append(
            ToolCallRecord(
                name="check_repeat_offender",
                arguments={"indicator": ind},
                result_summary=rep_res,
            )
        )
        is_rep = rep_res.get("is_repeat_offender", False)
        ui_state = AgentUIState(
            case_id=case_id,
            risk_score=95 if is_rep else 20,
            verdict="likely_scam" if is_rep else "safe",
            category="threat_intelligence",
            category_name="Repeat-Offender Memory",
            urgency="immediate" if is_rep else "normal",
        )
        return AgentResponse(
            reply=rep_res.get("speak", f"Checked indicator {ind}."),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 0H. Intent: Export Threat Intelligence Feed
    if any(
        w in text_lower
        for w in (
            "export indicators",
            "export threat intel",
            "download indicators",
            "threat intelligence feed",
            "export json indicators",
        )
    ):
        export_res = await mcp_client.call_tool("export_indicators", {"format": "json"})
        tool_calls.append(
            ToolCallRecord(
                name="export_indicators",
                arguments={"format": "json"},
                result_summary={"total": export_res.get("total_unique_indicators", 0)},
            )
        )
        ui_state = AgentUIState(
            case_id=case_id,
            urgency="normal",
            category="threat_intelligence",
            category_name="Threat Intel Export",
        )
        return AgentResponse(
            reply=export_res.get(
                "speak", "Exported threat indicators from ScamShield intelligence database."
            ),
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
        )

    # 1. Intent: Generate Report
    if any(
        w in text_lower
        for w in (
            "generate report",
            "view report",
            "give me report",
            "complaint report",
            "file report",
        )
    ):
        if not case_id:
            # Create a case first if user immediately asks for report
            open_res = await mcp_client.call_tool(
                "open_case", {"title": "Incident Investigation", "region": region}
            )
            case_id = open_res.get("case_id")
            session_store.update_case_id(session_id, case_id)
            tool_calls.append(
                ToolCallRecord(
                    name="open_case",
                    arguments={"title": "Incident Investigation", "region": region},
                    result_summary=open_res,
                )
            )

        rep_res = await mcp_client.call_tool("generate_report", {"case_id": case_id})
        tool_calls.append(
            ToolCallRecord(
                name="generate_report", arguments={"case_id": case_id}, result_summary=rep_res
            )
        )

        full_case = await mcp_client.call_tool("get_case", {"case_id": case_id})
        reply = rep_res.get(
            "speak",
            f"I generated your incident report for case {case_id}. You can copy and submit it to the portal.",
        )

        ui_state = AgentUIState(
            case_id=case_id,
            evidence=full_case.get("evidence", []),
            urgency="normal",
        )
        return AgentResponse(
            reply=reply,
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
            report_markdown=rep_res.get("markdown"),
        )

    # 2. Intent: Check Link / URL
    extracted_url = _extract_url(message)
    if extracted_url or any(
        w in text_lower for w in ("check link", "check url", "is this link safe")
    ):
        url_to_check = extracted_url or message.strip()
        link_res = await mcp_client.call_tool("check_link", {"url": url_to_check})
        tool_calls.append(
            ToolCallRecord(
                name="check_link", arguments={"url": url_to_check}, result_summary=link_res
            )
        )

        # Open case if link is suspicious/scam
        if link_res.get("verdict") in ("likely_scam", "suspicious"):
            if not case_id:
                open_res = await mcp_client.call_tool(
                    "open_case",
                    {
                        "title": f"Suspicious Link {link_res.get('normalized_domain')}",
                        "region": region,
                    },
                )
                case_id = open_res.get("case_id")
                session_store.update_case_id(session_id, case_id)
                tool_calls.append(
                    ToolCallRecord(
                        name="open_case", arguments={"region": region}, result_summary=open_res
                    )
                )

            ev_res = await mcp_client.call_tool(
                "add_evidence", {"case_id": case_id, "kind": "link", "content": url_to_check}
            )
            tool_calls.append(
                ToolCallRecord(
                    name="add_evidence", arguments={"kind": "link"}, result_summary=ev_res
                )
            )

        ev_list = []
        steps = []
        report_md = None
        if case_id:
            full_case = await mcp_client.call_tool("get_case", {"case_id": case_id})
            ev_list = full_case.get("evidence", [])
            steps_res = await mcp_client.call_tool(
                "next_steps", {"case_id": case_id, "lost_money": False, "payment_method": "none"}
            )
            steps = steps_res.get("steps", [])
            tool_calls.append(
                ToolCallRecord(
                    name="next_steps", arguments={"lost_money": False}, result_summary=steps_res
                )
            )
            rep_res = await mcp_client.call_tool("generate_report", {"case_id": case_id})
            report_md = rep_res.get("markdown")

        reply = link_res.get("speak", "I inspected that link for safety indicators.")
        ui_state = AgentUIState(
            case_id=case_id,
            risk_score=link_res.get("risk_score"),
            verdict=link_res.get("verdict"),
            category="phishing_link",
            category_name="Phishing Link & Typosquatted Domain",
            red_flags=[
                {"code": s.get("code", "SIGNAL"), "explanation": s.get("detail", "")}
                for s in link_res.get("signals", [])
            ],
            steps=steps,
            evidence=ev_list,
        )
        return AgentResponse(
            reply=reply,
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
            report_markdown=report_md,
        )

    # 3. Intent: Payment Loss / Transferred Money
    is_payment_loss = any(
        w in text_lower
        for w in (
            "lost money",
            "sent money",
            "sent rs",
            "sent inr",
            "sent $",
            "sent £",
            "already sent",
            "already paid",
            "i sent",
            "i paid",
            "transferred money",
            "transferred rs",
            "transferred funds",
            "debited",
            "approve collect",
        )
    ) or (
        "sent" in text_lower
        and any(kw in text_lower for kw in ("fraudster", "scammer", "panicked"))
    )

    if is_payment_loss:
        if not case_id:
            open_res = await mcp_client.call_tool(
                "open_case", {"title": "Financial Fraud Loss", "region": region}
            )
            case_id = open_res.get("case_id")
            session_store.update_case_id(session_id, case_id)
            tool_calls.append(
                ToolCallRecord(
                    name="open_case", arguments={"region": region}, result_summary=open_res
                )
            )

        pay_method = _detect_payment_method(message)
        ev_res = await mcp_client.call_tool(
            "add_evidence", {"case_id": case_id, "kind": "payment", "content": message}
        )
        tool_calls.append(
            ToolCallRecord(
                name="add_evidence", arguments={"kind": "payment"}, result_summary=ev_res
            )
        )

        steps_res = await mcp_client.call_tool(
            "next_steps", {"case_id": case_id, "lost_money": True, "payment_method": pay_method}
        )
        tool_calls.append(
            ToolCallRecord(
                name="next_steps",
                arguments={"lost_money": True, "payment_method": pay_method},
                result_summary=steps_res,
            )
        )

        rep_res = await mcp_client.call_tool("generate_report", {"case_id": case_id})
        tool_calls.append(
            ToolCallRecord(
                name="generate_report", arguments={"case_id": case_id}, result_summary=rep_res
            )
        )

        full_case = await mcp_client.call_tool("get_case", {"case_id": case_id})
        ev_list = full_case.get("evidence", [])

        fam_res = None  # Family alerts are only prepared when the user asks for one

        reply = steps_res.get(
            "speak", "Because money was involved, contact your bank and helpline 1930 immediately."
        )
        ui_state = AgentUIState(
            case_id=case_id,
            risk_score=95,
            verdict="likely_scam",
            category="financial_loss",
            category_name="Financial Loss & Golden Hour Drain",
            steps=steps_res.get("steps", []),
            evidence=ev_list,
            urgency="immediate",
            family_alert=fam_res,
        )
        return AgentResponse(
            reply=reply,
            tool_calls=tool_calls,
            case_id=case_id,
            ui_state=ui_state,
            brain="fallback",
            report_markdown=rep_res.get("markdown"),
        )

    # 4. Default: Message Analysis
    msg_res = await mcp_client.call_tool(
        "analyze_message",
        {"text": message, "channel": "call" if "call" in text_lower else "sms", "region": region},
    )
    tool_calls.append(
        ToolCallRecord(
            name="analyze_message",
            arguments={"text": message[:80], "region": region},
            result_summary=msg_res,
        )
    )

    if msg_res.get("verdict") in ("likely_scam", "suspicious"):
        if not case_id:
            open_res = await mcp_client.call_tool(
                "open_case",
                {"title": f"Suspected {msg_res.get('category', 'Fraud')}", "region": region},
            )
            case_id = open_res.get("case_id")
            session_store.update_case_id(session_id, case_id)
            tool_calls.append(
                ToolCallRecord(
                    name="open_case", arguments={"region": region}, result_summary=open_res
                )
            )

        ev_res = await mcp_client.call_tool(
            "add_evidence", {"case_id": case_id, "kind": "message", "content": message}
        )
        tool_calls.append(
            ToolCallRecord(
                name="add_evidence", arguments={"kind": "message"}, result_summary=ev_res
            )
        )

        steps_res = await mcp_client.call_tool(
            "next_steps", {"case_id": case_id, "lost_money": False, "payment_method": "none"}
        )
        tool_calls.append(
            ToolCallRecord(
                name="next_steps", arguments={"lost_money": False}, result_summary=steps_res
            )
        )

        rep_res = await mcp_client.call_tool("generate_report", {"case_id": case_id})
        report_md = rep_res.get("markdown")
        steps = steps_res.get("steps", [])

        full_case = await mcp_client.call_tool("get_case", {"case_id": case_id})
        ev_list = full_case.get("evidence", [])
        cat_id = msg_res.get("category", "general_fraud")
        cat_name = CATEGORY_NAMES.get(cat_id, "Suspected Fraud / Social Engineering")

        # No automatic family alert: the user must ask (consent), see the offer in `reply`
        fam_res = None

        ui_state = AgentUIState(
            case_id=case_id,
            risk_score=msg_res.get("risk_score"),
            verdict=msg_res.get("verdict"),
            category=cat_id,
            category_name=cat_name,
            red_flags=msg_res.get("red_flags", []),
            steps=steps,
            evidence=ev_list,
            urgency="normal",
            family_alert=fam_res,
        )
    else:
        steps = []
        report_md = None
        ui_state = AgentUIState(
            case_id=None,
            risk_score=msg_res.get("risk_score", 5),
            verdict="safe",
            category="legitimate_notification",
            category_name="Legitimate Automated Security Notice",
            red_flags=[],
            steps=[],
            evidence=[],
            urgency="normal",
        )
        case_id = None

    reply = msg_res.get("speak", "I have evaluated your message.")

    # Native Hindi voice mode guidance if input is in Hindi or Hinglish
    if is_hindi_or_hinglish(message):
        hindi_guide = get_hindi_guidance(
            category=msg_res.get("category", "general_fraud"),
            verdict=msg_res.get("verdict", "safe"),
            risk_score=msg_res.get("risk_score", 0),
        )
        reply = hindi_guide["speak_hi"]
        if ui_state:
            ui_state.category_name = hindi_guide["title_hi"]

    return AgentResponse(
        reply=reply,
        tool_calls=tool_calls,
        case_id=case_id,
        ui_state=ui_state,
        brain="fallback",
        report_markdown=report_md,
    )
