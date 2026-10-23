"""Scam Drill training module for elders and citizens.

Provides interactive, voice-guided simulation drills to practice recognizing
and defusing common scams (digital arrest, electricity disconnection, fake bank KYC,
courier seizure) without sharing sensitive information.
"""

import random
import re
from typing import Any

DRILL_SCENARIOS: dict[str, dict[str, Any]] = {
    "electricity_bill": {
        "scenario_id": "electricity_bill",
        "title": "Electricity Disconnection Urgency",
        "category": "utility_impersonation",
        "scammer_message": (
            "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM "
            "due to an unpaid bill of rupees 1,450. Call power officer Sharma at 9876543210 "
            "immediately or install the QuickSupport app to update your meter."
        ),
        "speak": (
            "Starting Scam Drill: Electricity Disconnection. The caller says your power will be "
            "cut in thirty minutes unless you pay or install an app right now. What do you do?"
        ),
        "safe_keywords": [
            "hang up",
            "disconnect",
            "won't pay",
            "will not pay",
            "official portal",
            "electricity office",
            "electricity board",
            "fake",
            "scam",
            "consumer care",
            "bill receipt",
            "no app",
            "won't install",
            "not installing",
        ],
        "unsafe_keywords": [
            "install",
            "download",
            "quicksupport",
            "anydesk",
            "pay now",
            "transferring",
            "sending money",
            "paying",
            "otp",
        ],
        "best_practice": "Never install remote apps or pay numbers from SMS. Verify bills directly on your electricity board app or physical bill.",
    },
    "digital_arrest": {
        "scenario_id": "digital_arrest",
        "title": "Digital Arrest Police Extortion",
        "category": "digital_arrest",
        "scammer_message": (
            "This is Inspector Vijay Rathore from Central Cyber Crime Bureau Delhi. "
            "A bank account linked to your Aadhaar was used in a 2 crore money laundering case. "
            "You are under digital arrest. Do not disconnect this video call, and transfer your "
            "funds to our RBI safe verification account immediately."
        ),
        "speak": (
            "Starting Scam Drill: Digital Arrest. A man in police uniform on video call says you are "
            "under digital arrest and must transfer money for verification. What do you do?"
        ),
        "safe_keywords": [
            "hang up",
            "disconnect",
            "fake police",
            "digital arrest is fake",
            "police station",
            "local police",
            "call 1930",
            "won't transfer",
            "no money",
            "lawyer",
            "scam",
        ],
        "unsafe_keywords": [
            "transfer",
            "sending",
            "transferring",
            "rbi account",
            "staying on call",
            "paying",
            "bank details",
            "balance",
        ],
        "best_practice": "Police, CBI, and courts never conduct arrests over Skype or WhatsApp video calls, and never demand funds for 'verification'. Hang up immediately.",
    },
    "bank_kyc_otp": {
        "scenario_id": "bank_kyc_otp",
        "title": "Urgent Bank KYC & OTP Harvesting",
        "category": "kyc_otp",
        "scammer_message": (
            "Dear Customer, your State Bank account has been blocked due to pending KYC verification. "
            "To reactivate your debit card and avoid penalty, read out the 6-digit verification code "
            "just sent to your mobile."
        ),
        "speak": (
            "Starting Scam Drill: Bank KYC Verification. The caller claims your bank account is blocked "
            "and asks for the 6-digit OTP code sent to your phone. What do you do?"
        ),
        "safe_keywords": [
            "never share otp",
            "won't share",
            "not sharing",
            "no otp",
            "no code",
            "bank branch",
            "hang up",
            "disconnect",
            "call bank",
            "fraud",
            "scam",
        ],
        "unsafe_keywords": [
            "my otp is",
            "otp is",
            "the code is",
            "code is",
            "sharing code",
            "482910",
            "here is the otp",
        ],
        "best_practice": "Banks never ask for OTPs, PINs, or passwords over phone or SMS. Keep one-time passwords strictly confidential.",
    },
    "courier_customs": {
        "scenario_id": "courier_customs",
        "title": "FedEx Customs Contraband Detention",
        "category": "courier_customs",
        "scammer_message": (
            "This is FedEx International Mumbai. A parcel sent with your Aadhaar ID to Taiwan "
            "containing illegal passports and synthetic drugs has been intercepted by Customs. "
            "Pay the clearance penalty fee of 45,000 rupees to avoid immediate arrest."
        ),
        "speak": (
            "Starting Scam Drill: Courier Customs Penalty. The caller says a parcel under your name "
            "was seized with contraband and demands an immediate clearance fee. What do you do?"
        ),
        "safe_keywords": [
            "didn't send parcel",
            "hang up",
            "disconnect",
            "fake parcel",
            "scam",
            "won't pay",
            "customs office",
            "file complaint",
            "call police",
            "1930",
        ],
        "unsafe_keywords": [
            "paying penalty",
            "transfer money",
            "sending 45000",
            "pay fee",
            "transferring",
            "transfer",
            "will transfer",
            "45,000",
            "45000",
            "penalty",
            "scared",
            "pay penalty",
        ],
        "best_practice": "Courier companies do not collect criminal penalties. Customs officials never demand money transfers to personal UPI or bank accounts.",
    },
}

# In-memory store for active drills
_ACTIVE_DRILLS: dict[str, dict[str, Any]] = {}


def start_drill(scenario: str = "random", region: str = "IN") -> dict[str, Any]:
    """Initiate a voice-first scam training drill.

    Args:
        scenario: Specific scenario key ('electricity_bill', 'digital_arrest', 'bank_kyc_otp',
                  'courier_customs') or 'random'.
        region: ISO country code (default 'IN').

    Returns:
        Structured drill payload including drill_id, scenario details, and speak prompt.
    """
    if scenario not in DRILL_SCENARIOS or scenario == "random":
        scenario = random.choice(list(DRILL_SCENARIOS.keys()))

    data = DRILL_SCENARIOS[scenario]
    drill_id = f"drill-{random.randint(100, 999)}"

    drill_record = {
        "drill_id": drill_id,
        "scenario_id": scenario,
        "title": data["title"],
        "category": data["category"],
        "scammer_message": data["scammer_message"],
        "safe_keywords": data["safe_keywords"],
        "unsafe_keywords": data["unsafe_keywords"],
        "best_practice": data["best_practice"],
        "region": region,
        "status": "active",
    }

    _ACTIVE_DRILLS[drill_id] = drill_record

    return {
        "drill_id": drill_id,
        "scenario_id": scenario,
        "title": data["title"],
        "scammer_message": data["scammer_message"],
        "speak": data["speak"],
        "recommended_action": data["best_practice"],
        "status": "active",
    }


def score_drill_response(drill_id: str, user_reply: str) -> dict[str, Any]:
    """Score the user's spoken or typed response to an active drill.

    Evaluates citizen defense tactics:
    - Rejection & hanging up -> 100/100 PASSED
    - Disclosing OTP/code -> 0/100 FAILED (CRITICAL)
    - Agreeing to transfer money/penalty -> 10/100 FAILED (HIGH RISK)
    - Agreeing to install remote apps -> 10/100 FAILED (HIGH RISK)
    - Panicking/surrendering -> 15/100 FAILED (HIGH RISK)
    - Hesitant questioning without compliance -> 50/100 NEEDS_IMPROVEMENT

    Args:
        drill_id: The identifier of the active drill.
        user_reply: What the citizen said in response to the drill.

    Returns:
        Score (0-100), verdict (PASSED/FAILED/NEEDS_IMPROVEMENT), detailed feedback, and speak.
    """
    reply_lower = user_reply.lower().strip()
    drill = _ACTIVE_DRILLS.get(drill_id)

    # If drill not found in memory, dynamically infer from reply or default to bank_kyc_otp
    if not drill:
        if any(
            w in reply_lower
            for w in ("parcel", "customs", "fedex", "contraband", "45,000", "45000", "taiwan")
        ):
            drill = DRILL_SCENARIOS["courier_customs"]
        elif any(
            w in reply_lower
            for w in ("electricity", "power", "bill", "meter", "quicksupport", "sharma")
        ):
            drill = DRILL_SCENARIOS["electricity_bill"]
        elif any(
            w in reply_lower for w in ("arrest", "police", "cbi", "rbi", "video call", "savings")
        ):
            drill = DRILL_SCENARIOS["digital_arrest"]
        else:
            drill = DRILL_SCENARIOS["bank_kyc_otp"]

    best_practice = drill.get("best_practice", "")
    title = drill.get("title", "Scam Drill")

    # ---------------------------------------------------------
    # 1. DANGEROUS / COMPLIANCE ACTION DETECTION
    # ---------------------------------------------------------
    # Check if citizen expresses refusal / negation context:
    # e.g. "I refuse to pay", "never share otp", "won't install", "customs does not ask for upi"
    has_refusal = bool(
        re.search(
            r"\b(?:refus(?:e|ed|ing)|never|won'?t|will\s+not|don'?t|do\s+not|not\s+paying|not\s+sharing|not\s+installing|not\s+transferring|no\s+otp|no\s+code|no\s+money|no\s+app|does\s+not\s+ask|never\s+ask)\b",
            reply_lower,
        )
    )

    # 1A. OTP / Verification Code Disclosure
    has_numeric_code = bool(re.search(r"\b\d{4,8}\b", reply_lower))
    has_otp_phrase = any(
        p in reply_lower
        for p in (
            "my otp is",
            "otp is",
            "the code is",
            "code is",
            "verification code is",
            "here is the code",
            "here is my code",
            "here is the otp",
            "my 6-digit",
            "my verification code",
            "code is 482910",
            "482910",
        )
    )
    is_otp_sharing = False
    if has_numeric_code or has_otp_phrase:
        # Check if citizen is explicitly refusing: e.g. "never share otp", "refuse to give code", "won't share"
        negated_otp = bool(
            re.search(
                r"\b(?:never|won'?t|will\s+not|refus(?:e|ed|ing)|don'?t|do\s+not|not)\s+(?:share|give|disclose|read|tell|send)?.*(?:otp|code|pin|password|verification)\b",
                reply_lower,
            )
            or any(
                w in reply_lower
                for w in (
                    "never share",
                    "won't share",
                    "not sharing",
                    "no otp",
                    "no code",
                    "fake otp",
                )
            )
        )
        if not negated_otp:
            is_otp_sharing = True

    # 1B. Payment / Money Transfer Compliance
    payment_phrases = (
        "will transfer",
        "transfer the",
        "transferring",
        "transfer money",
        "transfer funds",
        "transfer my savings",
        "transfer my money",
        "transfer right away",
        "transfer penalty",
        "transfer the 45,000",
        "transfer 45000",
        "transfer 45,000",
        "sending 45000",
        "send 45000",
        "sending 45,000",
        "send money",
        "sending money",
        "send the payment",
        "send payment",
        "pay now",
        "will pay",
        "paying",
        "pay penalty",
        "pay the penalty",
        "pay clearance",
        "pay fee",
        "pay rupees",
        "pay rs",
        "pay right away",
        "paying the fine",
        "take my money",
        "i will transfer",
        "i will pay",
    )
    is_payment_compliance = False
    if any(p in reply_lower for p in payment_phrases) or (
        "transfer" in reply_lower
        and any(
            w in reply_lower
            for w in (
                "savings",
                "safe account",
                "rbi",
                "penalty",
                "fee",
                "rupees",
                "45000",
                "45,000",
                "money",
                "funds",
            )
        )
    ):
        negated_payment = bool(
            re.search(
                r"\b(?:never|won'?t|will\s+not|refus(?:e|ed|ing)|don'?t|do\s+not|not)\s+(?:pay|transfer|send|give)\b",
                reply_lower,
            )
            or any(
                w in reply_lower
                for w in (
                    "won't pay",
                    "refuse to pay",
                    "refuse to transfer",
                    "will not transfer",
                    "not paying",
                    "not transferring",
                    "no money",
                    "does not ask for upi",
                    "never ask for money",
                    "won't transfer",
                    "refuse to transfer any money",
                )
            )
        )
        if not negated_payment:
            is_payment_compliance = True

    # 1C. Remote Desktop App Installation
    install_phrases = (
        "install quicksupport",
        "download quicksupport",
        "install anydesk",
        "download anydesk",
        "install teamviewer",
        "download teamviewer",
        "install the app",
        "install app",
        "download app",
        "will install",
        "okay, i will install",
        "installing",
    )
    is_app_installation = False
    if any(p in reply_lower for p in install_phrases):
        negated_install = bool(
            re.search(
                r"\b(?:never|won'?t|will\s+not|refus(?:e|ed|ing)|don'?t|do\s+not|not)\s+(?:install|download|click)\b",
                reply_lower,
            )
            or any(
                w in reply_lower
                for w in (
                    "won't install",
                    "not installing",
                    "refuse to install",
                    "no app",
                    "not click any links",
                )
            )
        )
        if not negated_install:
            is_app_installation = True

    # 1D. Fear-based Surrender / Complying with threat
    is_fear_surrender = False
    if any(
        p in reply_lower
        for p in (
            "i am scared",
            "please do not arrest",
            "please don't arrest",
            "don't arrest me",
            "unblock my card",
            "please unblock",
        )
    ):
        if is_payment_compliance or is_otp_sharing or not has_refusal:
            is_fear_surrender = True

    # Composite unsafe indicator
    has_unsafe = is_otp_sharing or is_payment_compliance or is_app_installation or is_fear_surrender

    # ---------------------------------------------------------
    # 2. SAFE DEFENSIVE ACTION DETECTION
    # ---------------------------------------------------------
    safe_signals = [
        # Explicit refusal
        bool(
            re.search(
                r"\b(?:refus(?:e|ed|ing)|never|won'?t|will\s+not|not\s+paying|not\s+installing|not\s+sharing|not\s+transferring|no\s+otp|no\s+code|no\s+money|no\s+app)\b",
                reply_lower,
            )
        ),
        # Hanging up or disconnecting
        bool(
            re.search(
                r"\b(?:hang(?:ing)?\s*up|disconnect(?:ing)?|cutting\s+(?:the\s+)?call|end(?:ing)?\s+(?:the\s+)?call)\b",
                reply_lower,
            )
        ),
        # Blocking caller (strictly caller/scammer, NOT "unblock card")
        bool(re.search(r"\bblock(?:ing)?\s+(?:the\s+)?(?:caller|number|scammer)\b", reply_lower)),
        # Calling official helpline / authorities
        bool(
            re.search(
                r"\b(?:1930|call\s+1930|cyber\s*crime|police|police\s+station|lawyer|report(?:ing)?\s+(?:this\s+)?scam)\b",
                reply_lower,
            )
        ),
        # In-person or official verification
        bool(
            re.search(
                r"\b(?:bank\s+branch|local\s+branch|visiting\s+(?:my\s+)?local\s+bank|electricity\s+(?:board|office)|official\s+portal|consumer\s+care|customs\s+office|file\s+(?:a\s+)?complaint)\b",
                reply_lower,
            )
        ),
        # Identifying fraud
        bool(
            re.search(
                r"\b(?:scam|fraud|fake\s+police|fake\s+parcel|phishing|extortion)\b", reply_lower
            )
        ),
    ]
    # Scenario safe keywords
    for sk in drill.get("safe_keywords", []):
        sk_clean = sk.lower().strip()
        # Strictly ignore substring "block" when citizen says "unblock"
        if sk_clean == "block" and "unblock" in reply_lower:
            continue
        if re.search(r"\b" + re.escape(sk_clean) + r"\b", reply_lower):
            safe_signals.append(True)
            break

    has_safe = any(safe_signals)

    # ---------------------------------------------------------
    # 3. EVALUATION MATRIX (Defensive Security Logic)
    # ---------------------------------------------------------

    # CRITICAL RISK: Disclosing OTP code
    if is_otp_sharing:
        score = 0
        passed = False
        verdict = "FAILED"
        feedback = (
            "CRITICAL SECURITY RISK: You shared your 6-digit verification code (OTP). "
            "Sharing an OTP gives fraudsters instant access to drain your savings or hijack your accounts. "
            "Banks and government agencies will NEVER ask for an OTP or PIN over phone or SMS. "
            "Always hang up immediately without sharing any digits."
        )
        speak = (
            "Critical danger! Never disclose your OTP or verification codes to any caller. "
            "Doing so allows criminals to drain your accounts immediately. Always hang up."
        )

    # HIGH RISK: Agreeing to transfer money / pay penalty
    elif is_payment_compliance:
        score = 10
        passed = False
        verdict = "FAILED"
        feedback = (
            f"HIGH RISK: You agreed to transfer money or pay an urgent penalty fee. "
            f"Real customs officials, police officers, and utility companies NEVER demand instant UPI "
            f"or bank transfers over the phone under threat of arrest. {best_practice}"
        )
        speak = (
            "In this drill, that action would lose your money. Real authorities never demand urgent "
            "money transfers over the phone. Hang up immediately."
        )

    # HIGH RISK: Installing remote access software
    elif is_app_installation:
        score = 10
        passed = False
        verdict = "FAILED"
        feedback = (
            f"HIGH RISK: You agreed to install remote desktop software. Apps like QuickSupport or AnyDesk "
            f"give scammers full remote access to view your screen, intercept SMS passwords, and drain banking apps. {best_practice}"
        )
        speak = (
            "High risk! Never install apps like QuickSupport or AnyDesk at the request of an unknown caller. "
            "Hang up immediately."
        )

    # HIGH RISK: Fear surrender without refusal
    elif is_fear_surrender:
        score = 15
        passed = False
        verdict = "FAILED"
        feedback = (
            f"HIGH RISK: Scammers intentionally use panic, arrest threats, and fake urgency to manipulate victims. "
            f"Police, CBI, and courts NEVER conduct arrests or demand verification deposits over phone or video calls. {best_practice}"
        )
        speak = (
            "High risk. Do not give in to fear or arrest threats from callers. Real authorities never conduct "
            "arrests over phone or video calls. Hang up immediately."
        )

    # GENUINE SAFE ACTION: Refusal & Disconnection without compliance
    elif has_safe and not has_unsafe:
        score = 100
        passed = True
        verdict = "PASSED"
        feedback = f"Outstanding vigilance! You successfully recognized and rejected the scam attempt. {best_practice}"
        speak = (
            f"Outstanding job! You refused to comply and protected your information. "
            f"You passed the {title} drill with a perfect score of 100."
        )

    # PARTIAL / QUESTIONING: Skeptical but staying on the line
    else:
        score = 50
        passed = False
        verdict = "NEEDS_IMPROVEMENT"
        feedback = (
            f"Caution: While questioning the caller shows skepticism, staying on the line allows manipulative callers "
            f"to create panic and pressure you. The safest protocol is to hang up immediately and verify directly through official channels. {best_practice}"
        )
        speak = (
            "Good effort being skeptical, but staying on the line with scammers is risky. "
            "Always hang up immediately and verify with official customer care."
        )

    return {
        "drill_id": drill_id,
        "scenario_title": title,
        "score": score,
        "passed": passed,
        "verdict": verdict,
        "feedback": feedback,
        "best_practice": best_practice,
        "speak": speak,
    }
