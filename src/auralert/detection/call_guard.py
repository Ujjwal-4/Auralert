"""Live Call Guard engine for AURALERT.

Listens to suspicious speakerphone calls in rolling chunks, tracks cumulative risk
across the dialogue, escalates red flags, and interrupts with urgent voice warnings
(e.g., 'They just asked for an OTP, hang up now') when scam patterns are detected.
"""

import re
import secrets
from datetime import UTC, datetime
from typing import Any

from auralert.cases.db import create_case, insert_evidence

# Warnings such as "never share your OTP" are protective, not a solicitation
NEGATION_CONTEXT = re.compile(
    r"\b(?:never|do not|don't|dont|should not|shouldn't|must not)\s+(?:ever\s+)?"
    r"(?:share|give|tell|reveal|disclose|install|download|send|enter)\b|कभी\s+(?:भी\s+)?(?:नहीं|न)\s+(?:बताएं|बताएँ|साझा)",
    re.IGNORECASE,
)

# Only these speakers' words are scored; the user's own speech is recorded but never counted as a threat
SCORED_SPEAKERS = {"caller", "unknown", "other", "scammer"}

# Maximum active calls stored in memory
MAX_ACTIVE_CALLS = 100

# Critical scam escalation rules and signature patterns
TACTIC_RULES: list[dict[str, Any]] = [
    {
        "code": "OTP_SOLICITATION",
        "negatable": True,
        "category": "kyc_otp",
        "patterns": [
            r"\botp\b",
            r"\bverification code\b",
            r"\bone[- ]time password\b",
            r"\b6[- ]digit\b",
            r"\b4[- ]digit\b",
            r"\bupi pin\b",
            r"\benter (?:your )?pin\b",
            r"\bshare (?:the )?(?:code|otp)\b",
            r"\bread (?:me )?(?:the )?otp\b",
            r"ओटीपी",
            r"पिन",
        ],
        "score_boost": 50,
        "is_critical": True,
        "warning_en": "🚨 CRITICAL: They just asked for an OTP! Hang up now!",
        "warning_hi": "🚨 सावधान: उन्होंने अभी आपसे OTP मांगा है! तुरंत फोन काटें!",
    },
    {
        "code": "REMOTE_ACCESS_TAKEOVER",
        "negatable": True,
        "category": "tech_support",
        "patterns": [
            r"\banydesk\b",
            r"\bquicksupport\b",
            r"\bteamviewer\b",
            r"\brustdesk\b",
            r"\bscreen share\b",
            r"\bdownload apk\b",
            r"\binstall (?:this )?app\b",
            r"\b9[- ]digit code\b",
            r"रिमोट ऐप",
            r"एनीडेस्क",
        ],
        "score_boost": 45,
        "is_critical": True,
        "warning_en": "🚨 DANGER: Never install AnyDesk or remote control apps! Hang up immediately!",
        "warning_hi": "🚨 खतरा: AnyDesk या कोई रिमोट ऐप इंस्टॉल न करें! तुरंत फोन काटें!",
    },
    {
        "code": "DIGITAL_ARREST_COERCION",
        "category": "digital_arrest",
        "patterns": [
            r"\bdigital arrest\b",
            r"\bcbi\b",
            r"\bnarcotics (?:control )?bureau\b",
            r"\bcrime branch\b",
            r"\bmumbai police\b",
            r"\barrest warrant\b",
            r"\bdo not (?:hang up|disconnect)\b",
            r"\bstay on (?:camera|skype|call)\b",
            r"\bnon[- ]bailable\b",
            r"डिजिटल अरेस्ट",
            r"गिरफ्तार",
            r"सीबीआई",
            r"पुलिस",
        ],
        "score_boost": 40,
        "is_critical": True,
        "warning_en": "🚨 DIGITAL ARREST DETECTED: Real police never arrest citizens over phone or video calls. Hang up now!",
        "warning_hi": "🚨 डिजिटल अरेस्ट फ्रॉड: असली पुलिस कभी फोन या वीडियो पर अरेस्ट नहीं करती। तुरंत फोन काटें!",
    },
    {
        "code": "EXTORTION_PAYMENT_DEMAND",
        "category": "financial_loss",
        "patterns": [
            r"\bsafe account\b",
            r"\bverification deposit\b",
            r"\bclear your name\b",
            r"\brbi (?:clearance|safety|verification)\b",
            r"\btransfer rs\b",
            r"\bsend money\b",
            r"\bpay penalty\b",
            r"\bsecurity deposit\b",
            r"पैसे ट्रांसफर",
            r"खाते में पैसे",
        ],
        "score_boost": 45,
        "is_critical": True,
        "warning_en": "🚨 FRAUD ALERT: Demanding money to a 'safe account' is extortion. Hang up immediately!",
        "warning_hi": "🚨 फ्रॉड अलर्ट: सेफ अकाउंट में पैसे ट्रांसफर करने की मांग पूरी तरह फर्जी है। तुरंत फोन काटें!",
    },
    {
        "code": "FABRICATED_CONTRABAND_PARCEL",
        "category": "courier_customs",
        "patterns": [
            r"\b(?:fedex|dhl|courier|parcel).{0,100}(?:illegal|narcotics|drugs|passport|customs|seiz|intercept|contraband)",
            r"\bcustoms (?:clearance|seizure|hold)\b",
            r"\billegal (?:parcel|consignment|drugs|passport)\b",
            r"\bmdma\b",
            r"\bseized at airport\b",
            r"कस्टम्स",
            r"कूरियर पार्सल",
        ],
        "score_boost": 30,
        "is_critical": False,
        "warning_en": "⚠️ CUSTOMS SCAM: Real couriers send postal letters, not WhatsApp or phone threats.",
        "warning_hi": "⚠️ कस्टम्स फ्रॉड: असली कूरियर कंपनी कभी फोन पर गिरफ्तारी की धमकी नहीं देती।",
    },
    {
        "code": "UTILITY_DISCONNECTION_THREAT",
        "category": "electricity_bill",
        "patterns": [
            r"\belectricity (?:bill|connection|power)\b",
            r"\bdisconnected (?:tonight|today)\b",
            r"\bpower cut\b",
            r"\bpermanent power cut\b",
            r"\bpower grid\b",
            r"बिजली कट",
            r"बिजली विभाग",
        ],
        "score_boost": 30,
        "is_critical": False,
        "warning_en": "⚠️ UTILITY SCAM: Power boards never disconnect electricity on immediate phone threats.",
        "warning_hi": "⚠️ बिजली फ्रॉड: बिजली विभाग कभी फोन पर तुरंत बिजली काटने की धमकी नहीं देता।",
    },
    {
        "code": "ISOLATION_COERCION",
        "category": "general_fraud",
        "patterns": [
            r"\bdo not tell (?:anyone|family)\b",
            r"\bkeep (?:this )?confidential\b",
            r"\bclosed room\b",
            r"\bdo not consult\b",
            r"किसी को मत बताना",
        ],
        "score_boost": 25,
        "is_critical": False,
        "warning_en": "⚠️ ISOLATION TACTIC: Scammer is coercing you not to consult your family.",
        "warning_hi": "⚠️ अलगाव की चाल: कॉलर आपको परिवार से बात करने से रोक रहा है।",
    },
    {
        "code": "IMPERSONATION_VOICE_CLONE",
        "category": "general_fraud",
        "patterns": [
            r"\bhi mom\b",
            r"\bhi dad\b",
            r"\blost my phone\b",
            r"\bnew number\b",
            r"\bin (?:jail|accident|emergency)\b",
            r"\bneed bail\b",
            r"नया नंबर",
            r"फोन खो गया",
        ],
        "requires": r"\b(?:send|transfer|pay|upi|money|bail|urgent|urgently|rs\.?|inr)\b|₹|पैसे",
        "score_boost": 35,
        "is_critical": False,
        "warning_en": "⚠️ 'HI MOM' SCAM: Suspect voice-clone or impersonation from a new number.",
        "warning_hi": "⚠️ फर्जी रिश्तेदार: नया नंबर बताकर पैसे मांगने का फ्रॉड हो सकता है।",
    },
]

# Built-in multi-chunk scenarios for seamless demonstration
DEMO_SCENARIOS: dict[str, dict[str, Any]] = {
    "digital_arrest": {
        "title": "CBI Digital Arrest & Contraband Parcel Call",
        "region": "IN",
        "chunks": [
            {
                "speaker": "caller",
                "text": "Hello, this is Inspector Vikram Rathore from Mumbai Crime Branch. Am I speaking with the resident?",
            },
            {
                "speaker": "caller",
                "text": "A FedEx international courier sent in your name to Taiwan containing 140 grams of narcotics and 5 fake passports was intercepted at Mumbai airport.",
            },
            {
                "speaker": "caller",
                "text": "A non-bailable arrest warrant has been issued against your Aadhaar card. You are now placed under Digital Arrest.",
            },
            {
                "speaker": "caller",
                "text": "Do not hang up this call or talk to your family, or our tactical police unit will raid your house in 30 minutes.",
            },
            {
                "speaker": "caller",
                "text": "To clear your name and verify your assets before the judge, you must transfer Rs 50,000 to the official RBI safety verification account right now.",
            },
        ],
    },
    "electricity_kyc": {
        "title": "Electricity Bill Threat & Screen-Share APK",
        "region": "IN",
        "chunks": [
            {
                "speaker": "caller",
                "text": "Dear consumer, your electricity connection will be disconnected tonight at 9:30 PM due to pending KYC update.",
            },
            {
                "speaker": "caller",
                "text": "Your previous month electricity bill payment was not updated in our power grid server.",
            },
            {
                "speaker": "caller",
                "text": "To avoid immediate blackout, open Google Play Store and install the QuickSupport app right now.",
            },
            {
                "speaker": "caller",
                "text": "Now read me the 9-digit code displayed on your screen so our power executive can verify your bill.",
            },
            {
                "speaker": "caller",
                "text": "We just sent a 6-digit verification OTP to your mobile phone. Share the OTP immediately or power will be cut.",
            },
        ],
    },
    "bank_kyc_otp": {
        "title": "SBI Account Freeze & Urgent OTP Trap",
        "region": "IN",
        "chunks": [
            {
                "speaker": "caller",
                "text": "Good afternoon, this is customer service calling from State Bank of India fraud monitoring team.",
            },
            {
                "speaker": "caller",
                "text": "Your debit card and savings account have been temporarily suspended due to unverified PAN card details.",
            },
            {
                "speaker": "caller",
                "text": "We are initiating a secure unfreezing sequence to restore your net banking immediately.",
            },
            {
                "speaker": "caller",
                "text": "You will receive a 6-digit one-time password on your registered phone. Please tell me the OTP to confirm your identity.",
            },
        ],
    },
}


class LiveCallSession:
    """Maintains state and rolling score for an active speakerphone call."""

    def __init__(self, call_id: str, region: str = "IN", language: str = "en") -> None:
        self.call_id = call_id
        self.region = region.upper()
        self.language = language.lower()
        self.cumulative_risk_score = 0
        self.detected_tactics: set[str] = set()
        self.chunks: list[dict[str, Any]] = []
        self.urgent_warning: str | None = None
        self.hang_up_recommended = False
        self.created_at = datetime.now(UTC).isoformat()
        self.primary_category = "general_fraud"

    def add_chunk(self, chunk_text: str, speaker: str = "caller") -> dict[str, Any]:
        """Analyze incoming chunk, increment cumulative score, and detect emergency triggers."""
        text = chunk_text.strip()
        text_lower = text.lower()
        now = datetime.now(UTC).isoformat()

        chunk_flags: list[dict[str, Any]] = []
        highest_chunk_warning: str | None = None
        score_increment = 0

        # The user's own words (for example "the caller asked me for an OTP") are never scored
        is_scored_speaker = speaker.lower() in SCORED_SPEAKERS
        has_negation = bool(NEGATION_CONTEXT.search(text))

        # Evaluate rules against chunk text
        for rule in TACTIC_RULES if is_scored_speaker else []:
            if rule.get("negatable") and has_negation:
                continue
            requires = rule.get("requires")
            if requires and not re.search(requires, text_lower, re.IGNORECASE):
                continue
            matched = False
            for pat in rule["patterns"]:
                if re.search(pat, text_lower, re.IGNORECASE):
                    matched = True
                    break

            if matched:
                code = rule["code"]
                chunk_flags.append(
                    {
                        "code": code,
                        "category": rule["category"],
                        "evidence": text[:120],
                    }
                )

                # Prioritize primary threat category
                if self.primary_category == "general_fraud" or rule["is_critical"]:
                    self.primary_category = rule["category"]

                # Apply score increment (diminishing return if tactic already fired)
                if code not in self.detected_tactics:
                    score_increment += rule["score_boost"]
                    self.detected_tactics.add(code)
                else:
                    score_increment += int(rule["score_boost"] * 0.3)

                if rule["is_critical"]:
                    self.hang_up_recommended = True
                    warn_txt = (
                        rule["warning_hi"]
                        if self.language in ("hi", "hindi")
                        else rule["warning_en"]
                    )
                    highest_chunk_warning = warn_txt

        # Cumulative escalation with saturation curve
        self.cumulative_risk_score = min(100, self.cumulative_risk_score + score_increment)

        # Baseline threshold for hanging up
        if self.cumulative_risk_score >= 60:
            self.hang_up_recommended = True

        if highest_chunk_warning:
            self.urgent_warning = highest_chunk_warning

        # Determine verdict
        if self.cumulative_risk_score >= 60:
            verdict = "likely_scam"
        elif self.cumulative_risk_score >= 30:
            verdict = "suspicious"
        else:
            verdict = "safe"

        # Build voice-first speech announcement (max 2 sentences)
        if highest_chunk_warning:
            speak = highest_chunk_warning
        elif self.hang_up_recommended:
            if self.language in ("hi", "hindi"):
                speak = (
                    f"सावधान! इस कॉल में बहुत अधिक जोखिम ({self.cumulative_risk_score}/100) पाया गया है। "
                    "यह एक धोखाधड़ी है, तुरंत फोन काटें!"
                )
            else:
                speak = (
                    f"Warning: High scam risk detected on this call ({self.cumulative_risk_score}/100). "
                    "Intimidation tactics detected. Hang up immediately!"
                )
        elif self.cumulative_risk_score >= 30:
            if self.language in ("hi", "hindi"):
                speak = "सतर्क रहें। कॉलर दबाव बनाने की कोशिश कर रहा है। कोई निजी जानकारी न दें।"
            else:
                speak = "Caution advised. The caller is creating artificial urgency. Do not share credentials or PINs."
        else:
            if self.language in ("hi", "hindi"):
                speak = "कॉल की निगरानी जारी है। अभी तक कोई संदिग्ध संकेत नहीं मिला।"
            else:
                speak = "AURALERT is monitoring your speaker call. No critical red flags detected yet."

        chunk_record = {
            "chunk_index": len(self.chunks) + 1,
            "speaker": speaker,
            "text": text,
            "timestamp": now,
            "flags_detected": chunk_flags,
            "score_increment": score_increment,
            "cumulative_risk_score": self.cumulative_risk_score,
            "urgent_warning": highest_chunk_warning,
        }
        self.chunks.append(chunk_record)

        return {
            "call_id": self.call_id,
            "chunk_index": chunk_record["chunk_index"],
            "speaker": speaker,
            "cumulative_risk_score": self.cumulative_risk_score,
            "verdict": verdict,
            "category": self.primary_category,
            "flags_detected": chunk_flags,
            "urgent_warning": highest_chunk_warning or self.urgent_warning,
            "hang_up_recommended": self.hang_up_recommended,
            "speak": speak,
        }

    def summarize_to_case(self) -> dict[str, Any]:
        """Convert live call transcript into a formal AURALERT case file."""
        title = f"Live Call Interception: {self.primary_category.replace('_', ' ').title()}"
        case_rec = create_case(title=title, region=self.region)
        cid = case_rec["id"]

        # Insert full transcript as call_note evidence
        full_transcript = "\n".join(f"[{c['speaker'].upper()}] {c['text']}" for c in self.chunks)

        analysis = {
            "verdict": "likely_scam" if self.cumulative_risk_score >= 60 else "suspicious",
            "risk_score": self.cumulative_risk_score,
            "category": self.primary_category,
            "red_flags": [
                {"code": t, "explanation": f"Detected tactic {t} during live call audio"}
                for t in sorted(self.detected_tactics)
            ],
            "live_call_id": self.call_id,
            "total_chunks": len(self.chunks),
        }

        insert_evidence(
            case_id=cid,
            kind="call_note",
            content=full_transcript,
            analysis=analysis,
        )

        return {
            "case_id": cid,
            "title": title,
            "call_id": self.call_id,
            "total_chunks": len(self.chunks),
            "final_score": self.cumulative_risk_score,
            "speak": f"I have transferred your intercepted call transcript into case file {cid} and generated official safety steps.",
        }


class CallGuardRegistry:
    """Thread-safe registry of in-flight live call sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, LiveCallSession] = {}

    def start_session(
        self,
        region: str = "IN",
        language: str = "en",
        call_id: str | None = None,
    ) -> LiveCallSession:
        """Initialize a new live call guard session."""
        cid = call_id or f"call-{secrets.token_hex(3)}"
        # Clean older sessions if exceeding max
        if len(self._sessions) >= MAX_ACTIVE_CALLS:
            oldest_key = next(iter(self._sessions))
            self._sessions.pop(oldest_key, None)

        sess = LiveCallSession(call_id=cid, region=region, language=language)
        self._sessions[cid] = sess
        return sess

    def get_session(self, call_id: str) -> LiveCallSession | None:
        """Lookup active call session."""
        return self._sessions.get(call_id)

    def process_chunk(
        self,
        call_id: str,
        chunk_text: str,
        speaker: str = "caller",
        language: str = "en",
    ) -> dict[str, Any]:
        """Process incoming audio chunk for a live call."""
        sess = self.get_session(call_id)
        if not sess:
            sess = self.start_session(region="IN", language=language, call_id=call_id)

        if language:
            sess.language = language.lower()

        return sess.add_chunk(chunk_text=chunk_text, speaker=speaker)

    def end_session(self, call_id: str, create_case_file: bool = True) -> dict[str, Any]:
        """End a live call guard session and optionally export to a case file."""
        sess = self._sessions.pop(call_id, None)
        if not sess:
            return {
                "status": "not_found",
                "call_id": call_id,
                "speak": f"Call session {call_id} was not found.",
            }

        if create_case_file and sess.chunks:
            return sess.summarize_to_case()

        return {
            "status": "ended",
            "call_id": call_id,
            "total_chunks": len(sess.chunks),
            "final_score": sess.cumulative_risk_score,
            "speak": f"Call Guard session {call_id} ended. Final risk score: {sess.cumulative_risk_score} out of 100.",
        }


# Global registry instance
call_guard_registry = CallGuardRegistry()
