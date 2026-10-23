"""Hindi Voice Mode support and bilingual scam defense intelligence for ScamShield.

Provides Devanagari detection, native Hindi speech guidance, authentic voice warnings,
and Hindi UI state labels to empower citizens across India.
"""

import re

DEVANAGARI_REGEX = re.compile(r"[\u0900-\u097F]")

HINGLISH_KEYWORDS = {
    "karo",
    "kare",
    "karen",
    "bhejo",
    "bheja",
    "paise",
    "paisa",
    "kat",
    "gaya",
    "gaye",
    "aaya",
    "aayi",
    "mera",
    "meri",
    "mere",
    "apna",
    "apni",
    "phone",
    "kaat",
    "kaato",
    "police",
    "thaana",
    "bijli",
    "khatam",
    "dhokha",
    "thagi",
    "fargi",
    "farzi",
    "bacho",
    "jaldi",
    "turant",
}

HINDI_GUIDANCE_CATALOG: dict[str, dict[str, str]] = {
    "digital_arrest": {
        "title_hi": "डिजिटल अरेस्ट और पुलिस ब्लैकमेल फ्रॉड",
        "speak_hi": (
            "सावधान! यह एक 'डिजिटल अरेस्ट' फ्रॉड है। "
            "असली पुलिस कभी फोन या वीडियो कॉल पर अरेस्ट नहीं करती और न ही पैसे मांगती है। "
            "तुरंत फोन काटें और राष्ट्रीय हेल्पलाइन 1930 पर कॉल करें।"
        ),
        "action_hi": "तुरंत फोन काटें, कोई पैसा न भेजें, और 1930 पर शिकायत दर्ज करें।",
    },
    "kyc_otp": {
        "title_hi": "फर्जी बैंक केवाईसी और ओटीपी फ्रॉड",
        "speak_hi": (
            "चेतावनी! कभी भी अपना बैंक ओटीपी, पासवर्ड या पिन किसी के साथ शेयर न करें। "
            "बैंक कभी फोन पर ओटीपी नहीं मांगता। यह आपके खाते से पैसे निकालने की चाल है।"
        ),
        "action_hi": "ओटीपी किसी को न बताएं और तुरंत बैंक कस्टमर केयर को सूचित करें।",
    },
    "upi_collect_request": {
        "title_hi": "फर्जी यूपीआई कलेक्ट रिक्वेस्ट व कैशबैक फ्रॉड",
        "speak_hi": (
            "सावधान! पैसे प्राप्त करने के लिए कभी यूपीआई पिन नहीं डाला जाता। "
            "पिन डालने से आपके खाते से पैसे कट जाएंगे। तुरंत इस कलेक्ट रिक्वेस्ट को रिजेक्ट करें।"
        ),
        "action_hi": "यूपीआई पिन बिल्कुल न डालें और कलेक्ट रिक्वेस्ट डिक्लाइन करें।",
    },
    "electricity_bill": {
        "title_hi": "बिजली कनेक्शन काटने की फर्जी धमकी",
        "speak_hi": (
            "चेतावनी! बिजली विभाग कभी भी अचानक फोन करके बिजली काटने की धमकी नहीं देता "
            "और न ही ऐप डाउनलोड करने को कहता है। कोई भी ऐप इंस्टॉल न करें और तुरंत फोन काटें।"
        ),
        "action_hi": "कोई रिमोट ऐप इंस्टॉल न करें और अपने स्थानीय बिजली दफ्तर से जांच करें।",
    },
    "courier_customs": {
        "title_hi": "कूरियर पार्सल और कस्टम्स जब्ती फ्रॉड",
        "speak_hi": (
            "सावधान! कूरियर कंपनियां कभी फोन पर गिरफ्तारी या कस्टम्स पेनल्टी की धमकी नहीं देतीं। "
            "यह आपको डराकर पैसे ऐंठने की चाल है। कोई भुगतान न करें।"
        ),
        "action_hi": "कोई पेनल्टी न भरें और सीधे असली कूरियर वेबसाइट पर ट्रैकिंग चेक करें।",
    },
    "tech_support": {
        "title_hi": "फर्जी टेक सपोर्ट और स्क्रीन शेयरिंग फ्रॉड",
        "speak_hi": (
            "सावधान! कभी भी अपने फोन या कंप्यूटर में एनीडेस्क या क्विकसपोर्ट जैसे रिमोट ऐप इंस्टॉल न करें। "
            "इससे धोखेबाज आपके बैंक खाते पर कब्जा कर सकते हैं।"
        ),
        "action_hi": "इंटरनेट बंद करें और डाउनलोड किए गए ऐप को तुरंत अनइंस्टॉल करें।",
    },
    "legitimate_notification": {
        "title_hi": "सुरक्षित अधिकृत बैंक नोटिफिकेशन",
        "speak_hi": (
            "यह एक सामान्य और वैध बैंकिंग सूचना प्रतीत होती है। "
            "इसमें कोई खतरा नहीं है, फिर भी अपना ओटीपी या पासवर्ड किसी को न बताएं।"
        ),
        "action_hi": "संदेश सुरक्षित है, किसी कार्रवाई की आवश्यकता नहीं है।",
    },
    "general_fraud": {
        "title_hi": "संदिग्ध साइबर धोखाधड़ी",
        "speak_hi": (
            "सावधान! यह संचार संदिग्ध है। किसी भी अज्ञात लिंक पर क्लिक न करें "
            "और न ही किसी के कहने पर पैसे ट्रांसफर करें। सतर्क रहें।"
        ),
        "action_hi": "संदिग्ध नंबर को ब्लॉक करें और किसी भी अज्ञात लिंक को न खोलें।",
    },
}


def is_hindi_or_hinglish(text: str) -> bool:
    """Detect whether input text contains Hindi (Devanagari) or strong Hinglish cues."""
    if not text:
        return False

    # Check for Devanagari script
    if DEVANAGARI_REGEX.search(text):
        return True

    # Check for Hinglish keywords
    words = {w.lower().strip(".,!?:;\"'()[]{}") for w in text.split()}
    matched_keywords = words.intersection(HINGLISH_KEYWORDS)
    return len(matched_keywords) >= 2 or any(
        phrase in text.lower()
        for phrase in (
            "paise kat",
            "paisa kat",
            "phone kaat",
            "bijli kat",
            "farzi call",
            "police aayi",
            "mera account",
            "meri kyc",
            "apna pin",
        )
    )


def get_hindi_guidance(
    category: str,
    verdict: str = "likely_scam",
    risk_score: int = 80,
    repeat_offender: bool = False,
    safe_word_status: str | None = None,
) -> dict[str, str]:
    """Provide voice-first spoken guidance and localized titles in Hindi."""
    # Special overrides
    if safe_word_status == "verified":
        return {
            "title_hi": "पारिवारिक सेफ-वर्ड सत्यापित",
            "speak_hi": "सेफ-वर्ड सत्यापित हो गया है! यह वाकई आपके परिवार का सदस्य है। बात जारी रखना सुरक्षित है।",
            "action_hi": "सत्यापन सफल।",
        }
    elif safe_word_status == "mismatch":
        return {
            "title_hi": "🚨 सेफ-वर्ड गलत — फर्जी कॉल चेतावनी",
            "speak_hi": (
                "सावधान! गुप्त सेफ-वर्ड गलत है। "
                "यह एआई वॉयस क्लोन या फर्जी कॉल हो सकती है। कोई भी पैसा न भेजें और तुरंत फोन काटें।"
            ),
            "action_hi": "तुरंत फोन काटें और परिवार के सदस्य को उनके असली नंबर पर कॉल करें।",
        }

    cat_info = HINDI_GUIDANCE_CATALOG.get(category, HINDI_GUIDANCE_CATALOG["general_fraud"])

    speak_text = cat_info["speak_hi"]

    if repeat_offender:
        speak_text = (
            "चेतावनी! यह नंबर पहले भी धोखाधड़ी के मामलों में दर्ज हो चुका है। यह एक पुराना धोखेबाज है। "
            + speak_text
        )

    return {
        "title_hi": cat_info["title_hi"],
        "speak_hi": speak_text,
        "action_hi": cat_info["action_hi"],
    }
