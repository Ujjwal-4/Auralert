"""Deterministic, rule-based message analysis engine for fraud detection.

Strictly offline: performs zero network calls or LLM invocations.
Combines regex pattern matching across English and Hinglish, feature extractors
for stable red-flag codes, static URL extraction, and benign message discrimination.
"""

import json
import re
from pathlib import Path
from typing import Any

from scamshield.detection.link_checker import check_link

# Stable Red Flag Definitions with weights and plain explanations
RED_FLAG_DEFINITIONS = {
    "URGENCY": {
        "weight": 25,
        "regex": r"(immediately|within\s+(24|12|2|1)\s+hours?|urgent(ly)?|at\s+once|expire[sd]?\s+today|blocked\s+today|jaldi|turant|aaj\s+hi|bina\s+deri|tonight\s+at)",
        "explanation": "Scammers create artificial urgency to prevent you from pausing and verifying.",
    },
    "ACCOUNT_SUSPENSION_THREAT": {
        "weight": 35,
        "regex": r"(account.*(suspended|blocked|deactivated|frozen|band)|(suspended|blocked|deactivated|frozen|band).*account|(card|sim|atm).{0,30}(block|band)\s+ho\s+(gaya|jayega|raha)|(will\s+be|is)\s+(frozen|blocked|suspended).{0,25}within\s+\d+\s+hours?)",
        "explanation": "Threatens immediate suspension or freezing of your bank account to induce panic.",
    },
    "OTP_REQUEST": {
        "weight": 40,
        "regex": r"(share.*otp|tell.*(me)?.*code|send.*(the)?.*otp|enter.*otp.*to.*verify|batao.*otp|otp.*bhejo|otp.*share|otp\s+(bataiye|bataye|batayiye|bata\s+do|dijiye)|(bataiye|batayiye).*otp|press\s+1\s+to\s+cancel\s+or\s+share|ओटीपी|पिन\s*(?:बताएं|बताओ|शेयर))",
        "explanation": "The message demands your one-time verification password, which grants access to your account.",
    },
    "PAYMENT_PRESSURE": {
        "weight": 35,
        "regex": r"(pay\s+(now|immediately|fine|charges|fee|registration|rs)|deposit\s+(rs|money|\$|security|fee|usdt)|send\s+(rs|payment|money)|transfer\s+to\s+account|paise\s+(bhejo|jama\s+karo)|पैसे\s*(?:भेजें|भेजो|ट्रांसफर|डिपॉजिट)|सेफ\s*अकाउंट)",
        "explanation": "Demands immediate transfer of money, registration fees, or advance deposits.",
    },
    "AUTHORITY_IMPERSONATION": {
        "weight": 35,
        "regex": r"(cbi|police|customs|enforcement\s+directorate|\bed\b|supreme\s+court|rbi|income\s+tax\s+department|\birs\b|\bhmrc\b|bank\s+manager|cyber\s+crime\s+branch|police\s+officer|electricity\s+officer|सीबीआई|पुलिस|कस्टम्स|आरबीआई|क्राइम\s*ब्रांच)",
        "explanation": "Posing as law enforcement, tax authorities (IRS/HMRC), or utility officers to intimidate victims.",
    },
    "THREAT_OF_ARREST": {
        "weight": 45,
        "regex": r"(digital\s+arrest|arrest\s+warrant|non-bailable|jail|criminal\s+case|fir\s+registered|police\s+custody|arrest\s+kar\s+lenge|डिजिटल\s*अरेस्ट|गिरफ्तार(ी)?|वारंट|जेल|थाना)",
        "explanation": "Threatens criminal prosecution, arrest, or police detention to induce panic.",
    },
    "THREAT_OF_DISCONNECTION": {
        "weight": 35,
        "regex": r"((electricity|power|gas|sim\s+card|connection|bill).*(disconnected|disconnect|cut).*(tonight|today|immediately)|बिजली\s*(?:कट|बिल|काट))",
        "explanation": "Threatens immediate cutoff of vital utilities like power or cell phone service to cause panic.",
    },
    "REMOTE_ACCESS_REQUEST": {
        "weight": 40,
        "regex": r"(anydesk|teamviewer|quicksupport|rustdesk|screen\s+share|remote\s+access|download\s+app\s+to\s+assist)",
        "explanation": "Instructs you to install remote desktop control software that allows attackers to seize control of your device.",
    },
    "SECRECY_REQUEST": {
        "weight": 30,
        "regex": r"(do\s+not\s+(tell|inform|disconnect|cut)|keep.*confidential|stay\s+on\s+(the)?.*call|kisi\s+ko\s+mat\s+batana|call\s+katna\s+mat)",
        "explanation": "Instructs you to keep the matter secret or stay continuously on the call to isolate you from help.",
    },
    "UNUSUAL_PAYMENT_METHOD": {
        "weight": 40,
        "regex": r"(gift\s+cards?|apple\s+card|google\s+play\s+card|steam\s+wallet|bitcoin\s+atm|crypto\s+wallet|(send|transfer|deposit|invest)\s+(\w+\s+){0,3}(in\s+)?(usdt|btc|bitcoin|crypto))",
        "explanation": "Requests payment through untraceable gift cards or cryptocurrency kiosks.",
    },
    "TOO_GOOD_TO_BE_TRUE": {
        "weight": 35,
        "regex": r"(won.*(25\s+lakh|lottery|prize|car|crorepati|cash|cashback)|earn.*(3000|5000|daily|per\s+day).*from\s+home|like.*(video|youtube|subscribe).*earn|inaam\s+jeet\s+gaye|ghar\s+baithe\s+kamayein)",
        "explanation": "Offers unrealistic easy earnings, lottery prizes, or cash rewards with minimal effort.",
    },
    "FAKE_REFUND_CLAIM": {
        "weight": 35,
        "regex": r"((refund|reward|cashback|bonus|prize).{0,60}(claim|click|tap|apply)|(claim|click|tap).{0,60}(refund|reward|cashback|bonus|prize))",
        "explanation": "Lures you with an approved refund, reward, or cashback that you must 'claim' through a link or form.",
    },
    "PAYMENT_METHOD_UPDATE": {
        "weight": 20,
        "regex": r"((payment|billing)\s+(failed|declined|unsuccessful|problem).{0,60}(update|verify|re-?enter)|(update|verify|re-?enter).{0,30}(card|billing|payment\s+(details|method)))",
        "explanation": "Claims a payment failed and asks you to re-enter card or billing details on a link.",
    },
    "FAKE_VIRUS_ALERT": {
        "weight": 25,
        "regex": r"((virus|malware|hacked|infected).{0,40}(computer|device|pc|laptop|phone)|(computer|device|pc|laptop|phone).{0,40}(virus|malware|hacked|infected))",
        "explanation": "Claims your device is infected so you will grant remote access or pay for fake support.",
    },
    "GUARANTEED_RETURNS": {
        "weight": 40,
        "regex": r"((guaranteed|assured|fixed)\s+(\d+x|\d+%|returns?|profit)|\d{3,}%\s+returns?|\d+x\s+returns?|(double|triple)\s+your\s+money)",
        "explanation": "Promises guaranteed or unrealistic investment returns, a hallmark of investment fraud.",
    },
    "EMOTIONAL_PAYMENT_APPEAL": {
        "weight": 25,
        "regex": r"((surgery|operation|hospital|accident|stranded).{0,80}(send|transfer|donate|pay|upi)|(send|transfer|donate|upi).{0,80}(surgery|operation|hospital|accident))",
        "explanation": "Uses an emotional emergency to rush you into sending money; verify with the person directly.",
    },
}

# Regex to detect URLs in unstructured text
URL_TLDS = (
    "com|in|org|net|top|xyz|gov|edu|co|ly|tk|ml|ga|cf|gq|click|link|online|site|shop|live|"
    "icu|cc|me|info|biz|to|gl|page|app|support|help|cyou|buzz|vip|work|club"
)
URL_REGEX = (
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+|"
    rf"[a-zA-Z0-9.-]+\.(?:{URL_TLDS})(?![a-zA-Z0-9])[^\s<>\"']*"
)

# Benign notification safety indicators (e.g., real bank notification warning the user)
BENIGN_WARNING_PATTERNS = [
    r"do\s+not\s+share.*(with|to)?\s*(anyone|anybody)",
    r"never\s+share.*otp",
    r"bank\s+never\s+asks?\s+for",
    r"if\s+not\s+done\s+by\s+you.*report",
    r"sbi\s+never\s+calls\s+asking",
]


def _load_scam_categories() -> list[dict[str, Any]]:
    """Load scam categories from data/scam_patterns.json."""
    cat_file = Path(__file__).resolve().parent.parent.parent.parent / "data" / "scam_patterns.json"
    if cat_file.exists():
        try:
            with open(cat_file, encoding="utf-8") as f:
                data = json.load(f)
                return data.get("categories", [])
        except (OSError, json.JSONDecodeError):
            return []
    return []


SCAM_CATEGORIES = _load_scam_categories()


def _is_benign_security_notice(text: str) -> bool:
    """Detect if an OTP or alert is a legitimate automated bank security notification.

    Real bank notifications provide an OTP for an action the user took, and explicitly
    instruct the user 'Do NOT share this code with anyone'.
    """
    text_lower = text.lower()
    has_warning = any(re.search(pat, text_lower) for pat in BENIGN_WARNING_PATTERNS)
    has_threat = bool(
        re.search(
            r"(arrest|warrant|block.*today|suspend.*today|expire.*today|disconnect.*tonight)",
            text_lower,
        )
    )
    return has_warning and not has_threat


def analyze_message(
    text: str,
    channel: str = "other",
    region: str = "IN",
) -> dict[str, Any]:
    """Analyze a message for scam markers, red flags, and fraud risk.

    Args:
        text: Communication text (SMS, call transcript, email, WhatsApp).
        channel: Delivery channel.
        region: Geographic region / jurisdiction.

    Returns:
        Structured result with verdict, risk_score (0-100), category,
        red_flags with snippets and explanations, and speak.
    """
    cleaned_text = text.strip() if text else ""
    if not cleaned_text:
        return {
            "verdict": "safe",
            "risk_score": 0,
            "category": "none",
            "red_flags": [],
            "speak": "I did not receive any message text to analyze. Please tell or paste what you received.",
        }

    text_lower = cleaned_text.lower()
    red_flags: list[dict[str, str]] = []
    base_score = 0

    # 1. Check for Benign Bank/Service Notification
    if _is_benign_security_notice(cleaned_text):
        return {
            "verdict": "safe",
            "risk_score": 5,
            "category": "legitimate_notification",
            "red_flags": [],
            "speak": (
                "This appears to be a legitimate automated bank notification. "
                "Remember to follow its advice: never share your one-time passwords with anyone."
            ),
        }

    # 2. Extract and statically check any URLs in the text
    urls = [u.rstrip(".,;:!?)\"'") for u in re.findall(URL_REGEX, cleaned_text, re.IGNORECASE)]
    has_scam_link = False

    for url_str in urls:
        link_analysis = check_link(url_str)
        if link_analysis["verdict"] in ("likely_scam", "suspicious"):
            has_scam_link = True
            red_flags.append(
                {
                    "code": "SUSPICIOUS_LINK",
                    "evidence": url_str,
                    "explanation": f"The message contains a suspicious link ({link_analysis['normalized_domain']}) with risk score {link_analysis['risk_score']}.",
                }
            )
            base_score += 45 if link_analysis["verdict"] == "likely_scam" else 30

    # 3. Feature Extraction for stable red-flag codes
    for code, flag_def in RED_FLAG_DEFINITIONS.items():
        # Avoid false OTP_REQUEST flag if user text explicitly says "do not share OTP"
        if code == "OTP_REQUEST" and re.search(r"do\s+not\s+share", text_lower):
            continue

        match = re.search(flag_def["regex"], text_lower, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 10)
            end = min(len(cleaned_text), match.end() + 20)
            evidence_snippet = cleaned_text[start:end].strip()

            red_flags.append(
                {
                    "code": code,
                    "evidence": evidence_snippet,
                    "explanation": flag_def["explanation"],
                }
            )
            base_score += flag_def["weight"]

    # 4. Scam Category Classification
    matched_category = "none"
    highest_cat_weight = 0

    for category in SCAM_CATEGORIES:
        cat_matches = 0
        for pattern in category.get("patterns", []):
            if re.search(pattern, text_lower, re.IGNORECASE):
                cat_matches += 1

        if cat_matches > 0:
            combined_weight = category.get("weight", 20) + (cat_matches * 15)
            if combined_weight > highest_cat_weight:
                highest_cat_weight = combined_weight
                matched_category = category.get("id", "general_fraud")

    # Add extra weight from category match
    if highest_cat_weight > 0:
        base_score += min(highest_cat_weight, 40)

    # UPI collect requests tricking users to enter PIN to "receive" money is automatically high risk
    if (
        "enter" in text_lower
        and "pin" in text_lower
        and any(w in text_lower for w in ("receive", "cashback", "refund", "milenge"))
    ):
        base_score = max(base_score, 75)
        matched_category = "upi_collect_request"

    # Infer specific threat category from detected red flags if patterns were language-specific
    flag_codes = {rf["code"] for rf in red_flags}
    if matched_category in ("none", "general_fraud"):
        if "THREAT_OF_ARREST" in flag_codes or "डिजिटल" in text_lower or "गिरफ्तार" in text_lower:
            matched_category = "digital_arrest"
        elif "THREAT_OF_DISCONNECTION" in flag_codes or "बिजली" in text_lower:
            matched_category = "electricity_bill"
        elif "OTP_REQUEST" in flag_codes or "ओटीपी" in text_lower:
            matched_category = "kyc_otp"
        elif "REMOTE_ACCESS_REQUEST" in flag_codes:
            matched_category = "tech_support"

    # 5. Calculate Final Risk Score and Verdict
    risk_score = min(base_score, 100)

    if risk_score >= 60 or (has_scam_link and risk_score >= 45):
        verdict = "likely_scam"
    elif risk_score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Category bookkeeping: benign messages have no category; risky but unclassified ones are general fraud
    if verdict == "safe":
        matched_category = "none"
    elif matched_category == "none":
        matched_category = "general_fraud"

    # 6. Formulate Voice-first Spoken Response (at most 2 calm sentences, action first)
    if verdict == "likely_scam":
        if matched_category == "digital_arrest":
            speak = (
                "This looks like a digital arrest scam. "
                "Hang up immediately; the police and government never arrest or conduct trials over video calls."
            )
        elif matched_category == "kyc_otp":
            speak = (
                "This looks like a KYC OTP scam. "
                "Do not share any codes or tap any links; legitimate banks never ask for your verification password."
            )
        elif matched_category == "upi_collect_request":
            speak = (
                "This is a UPI collect scam. "
                "Decline the request; you never enter your UPI PIN to receive money or refunds."
            )
        elif matched_category == "courier_customs":
            speak = (
                "This appears to be a courier customs scam. "
                "Do not send any clearance fees or personal IDs; hang up and do not engage."
            )
        elif matched_category == "tax_refund":
            speak = (
                "This looks like a fake tax refund scam. "
                "Do not tap the link; refunds are only handled on the official income tax portal."
            )
        elif matched_category == "fake_job":
            speak = (
                "This looks like a task deposit job scam. "
                "Do not deposit any security fees or follow their Telegram instructions."
            )
        elif matched_category == "tech_support":
            speak = (
                "This is a tech support impersonation scam. "
                "Do not install AnyDesk or grant remote access to your device; disconnect immediately."
            )
        elif matched_category == "gift_card_crypto" or any(
            rf.get("code") == "UNUSUAL_PAYMENT_METHOD" for rf in red_flags
        ):
            speak = (
                "This is a gift card payment scam. "
                "No legitimate agency or tax authority ever demands payment via gift cards; do not buy or send any codes."
            )
        else:
            speak = (
                "This message has multiple high-risk scam indicators. "
                "Do not reply, send money, or click any links; block the sender."
            )
    elif verdict == "suspicious":
        speak = (
            "This communication looks suspicious and contains pressure tactics. "
            "Do not share any personal details until you verify directly through the company's official number."
        )
    else:
        speak = (
            "I did not detect common scam patterns or fraudulent links in this message. "
            "However, always stay cautious and never share passwords or banking PINs."
        )

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "category": matched_category,
        "red_flags": red_flags,
        "speak": speak,
    }
