"""Case management service orchestrating SQLite state, detection, and reporting."""

import random
import re
from datetime import UTC, datetime
from typing import Any

from scamshield.cases.db import (
    check_safe_word,
    create_case,
    export_all_threat_indicators,
    extract_indicators_from_text,
    fetch_case,
    find_repeat_offenders,
    index_indicators_for_case,
    init_db,
    insert_evidence,
    save_safe_word,
)
from scamshield.detection.link_checker import check_link
from scamshield.detection.message_analyzer import analyze_message
from scamshield.regions import (
    get_helpline_number,
    get_official_portal_url,
    get_payment_steps,
    get_region_data,
)

# Initialize database on module load
init_db()


# Abuse limits
MAX_EVIDENCE_PER_CASE = 50
MAX_CONTENT_LENGTH = 20000


def open_case_service(
    title: str | None = None,
    region: str = "IN",
) -> dict[str, Any]:
    """Create a new case file and return voice-friendly confirmation."""
    case_rec = create_case(title=title, region=region)
    cid = case_rec["id"]

    # Format speakable case id (e.g., 'shield four eight two')
    parts = cid.split("-")
    spelled_id = f"{parts[0]} {' '.join(parts[1])}" if len(parts) > 1 else cid

    return {
        "case_id": cid,
        "speak": (
            f"I have opened case file {spelled_id} for you. "
            "You can now describe what the caller said, forward messages, or share any links."
        ),
    }


def add_evidence_service(
    case_id: str,
    kind: str,
    content: str,
) -> dict[str, Any]:
    """Analyze and attach evidence to an existing case file."""
    case = fetch_case(case_id)
    if not case:
        return {
            "evidence_id": "",
            "analysis": None,
            "speak": f"I could not find case file {case_id}. Please open a case first.",
        }

    # Abuse check: maximum evidence items per case
    if len(case.get("evidence", [])) >= MAX_EVIDENCE_PER_CASE:
        return {
            "evidence_id": "",
            "analysis": None,
            "speak": (
                f"Case {case_id} has reached the maximum limit of {MAX_EVIDENCE_PER_CASE} evidence items. "
                "Please generate your incident report or open a new case."
            ),
        }

    # Abuse check: cap content length
    sanitized_content = (content or "")[:MAX_CONTENT_LENGTH].strip()

    # Automatically analyze message or link evidence
    analysis: dict[str, Any] | None = None
    if kind == "message":
        analysis = analyze_message(sanitized_content, region=case.get("region", "IN"))
    elif kind == "link":
        analysis = check_link(sanitized_content)

    # Check for repeat offender indicators (phone, UPI ID, domain)
    extracted_inds = extract_indicators_from_text(sanitized_content)
    repeat_matches: list[dict[str, Any]] = []
    for ind in extracted_inds:
        rep = find_repeat_offenders(ind["raw"], ind["type"], exclude_case_id=case_id)
        if rep.get("is_repeat_offender"):
            repeat_matches.append(rep)

    if repeat_matches:
        if analysis is None:
            analysis = {
                "verdict": "likely_scam",
                "risk_score": 85,
                "category": "general_fraud",
                "red_flags": [],
            }
        else:
            analysis["verdict"] = "likely_scam"
            analysis["risk_score"] = max(analysis.get("risk_score", 0), 85)

        analysis["repeat_offender_matches"] = repeat_matches
        red_flags_list = analysis.get("red_flags") or []
        red_flags_list.append(
            {
                "code": "REPEAT_OFFENDER",
                "evidence": repeat_matches[0]["indicator"],
                "explanation": repeat_matches[0]["summary"],
            }
        )
        analysis["red_flags"] = red_flags_list

    # Index indicators into intelligence database for this case
    ind_category = (analysis or {}).get("category", "general_fraud")
    ind_risk = (analysis or {}).get("risk_score", 0)
    index_indicators_for_case(case_id, sanitized_content, ind_category, ind_risk)

    ev_rec = insert_evidence(
        case_id=case_id,
        kind=kind,
        content=sanitized_content,
        analysis=analysis,
    )

    ev_id = ev_rec["id"]
    if repeat_matches:
        speak = (
            f"Logged {kind} as evidence {ev_id}. "
            f"Warning: {repeat_matches[0]['summary']} This is a confirmed repeat scammer."
        )
    elif analysis and analysis.get("verdict") == "likely_scam":
        speak = (
            f"Logged {kind} as evidence {ev_id}. "
            "My analysis indicates a high risk of fraud with critical security red flags."
        )
    elif analysis and analysis.get("verdict") == "suspicious":
        speak = (
            f"Added {kind} as evidence {ev_id}. "
            "This item has several warning signs and appears suspicious."
        )
    else:
        speak = f"Added that {kind} to your case file under evidence {ev_id}."

    return {
        "evidence_id": ev_id,
        "analysis": analysis,
        "speak": speak,
    }


def get_case_service(case_id: str) -> dict[str, Any]:
    """Retrieve full incident case file."""
    case = fetch_case(case_id)
    if not case:
        return {
            "case_id": case_id,
            "status": "not_found",
            "evidence": [],
            "timeline": [],
            "speak": f"Case file {case_id} was not found.",
        }

    ev_count = len(case.get("evidence", []))
    speak = (
        f"Case file {case_id} contains {ev_count} logged piece{'s' if ev_count != 1 else ''} of evidence "
        f"and is currently {case.get('status', 'open')}."
    )
    case["speak"] = speak
    return case


def next_steps_service(
    case_id: str,
    lost_money: bool = False,
    payment_method: str = "none",
) -> dict[str, Any]:
    """Compute prioritized remediation actions based on case jurisdiction and payment method."""
    case = fetch_case(case_id)
    region_code = case.get("region", "IN") if case else "IN"
    reg_data = get_region_data(region_code)
    helpline = get_helpline_number(region_code)

    case_title = (case.get("title") or "").lower() if case else ""
    has_link = (
        any(ev.get("kind") == "link" for ev in case.get("evidence", []))
        or "link" in case_title
        or "http" in case_title
        if case
        else False
    )

    if not lost_money and (payment_method or "none").lower() == "none":
        if has_link:
            steps = [
                {
                    "order": 1,
                    "action": "Do not enter any passwords, OTPs, or card details on the link",
                    "why": "Phishing websites harvest your credentials to execute unauthorized account takeovers.",
                    "official_channel": "Browser security & safe browsing",
                },
                {
                    "order": 2,
                    "action": "If you already entered credentials, change your netbanking password immediately and lock cards",
                    "why": "Immediate password reset prevents scammers from transferring funds out of your account.",
                    "official_channel": "Bank mobile app / emergency desk",
                },
                {
                    "order": 3,
                    "action": f"Report the phishing URL to Chakshu (sancharsaathi.gov.in) and {reg_data.get('portal_name', 'national cyber portal')}",
                    "why": "Enables authorities and web browsers to take down the fraudulent domain globally.",
                    "official_channel": reg_data.get("portal_name", "Cybercrime portal"),
                },
            ]
        elif "digital_arrest" in case_title or "arrest" in case_title:
            steps = [
                {
                    "order": 1,
                    "action": "Disconnect the call immediately — police never arrest citizens over video calls",
                    "why": "There is no legal concept of 'digital arrest'; real police and courts never conduct trials on Skype, WhatsApp, or video calls.",
                    "official_channel": "Law enforcement safety advisory",
                },
                {
                    "order": 2,
                    "action": "Do not transfer money to any 'safe account' or 'verification deposit'",
                    "why": "Government authorities never demand security deposits or financial transfers to clear your name.",
                    "official_channel": f"Helpline {helpline}",
                },
                {
                    "order": 3,
                    "action": f"Report the extortion attempt to National Cybercrime Helpline {helpline} or your local police station",
                    "why": "Registers formal law enforcement notice and shields you from legal harassment.",
                    "official_channel": f"Helpline {helpline} / Local Police",
                },
            ]
        elif "kyc" in case_title or "otp" in case_title:
            steps = [
                {
                    "order": 1,
                    "action": "Do not share verification OTPs or click SMS KYC update links",
                    "why": "Legitimate banks never threaten immediate account suspension to harvest OTPs via text.",
                    "official_channel": "Official bank communication policy",
                },
                {
                    "order": 2,
                    "action": "Verify your account standing directly through your bank's official app or branch",
                    "why": "Confirms your real KYC status without exposing your credentials to phishing portals.",
                    "official_channel": "Bank branch / Official verified app",
                },
                {
                    "order": 3,
                    "action": "Report the sender number or SMS header on the Chakshu portal",
                    "why": "Helps telecom regulators blacklist the spoofed SMS header.",
                    "official_channel": "Chakshu portal (sancharsaathi.gov.in)",
                },
            ]
        elif "tech_support" in case_title:
            steps = [
                {
                    "order": 1,
                    "action": "Disconnect from Wi-Fi immediately and do not grant remote access",
                    "why": "Software like AnyDesk or TeamViewer gives fraudsters full control over your files and banking apps.",
                    "official_channel": "Device security",
                },
                {
                    "order": 2,
                    "action": "Uninstall any remote tools recently downloaded and run a full antivirus scan",
                    "why": "Removes any persistent backdoors or malware installed by attackers.",
                    "official_channel": "Antivirus & OS security",
                },
            ]
        elif "courier" in case_title or "customs" in case_title:
            steps = [
                {
                    "order": 1,
                    "action": "Do not pay any customs clearance penalties or parcel release fees",
                    "why": "Customs agencies issue formal postal summons, never phone/WhatsApp demands for payment.",
                    "official_channel": "Customs department advisory",
                },
                {
                    "order": 2,
                    "action": "Verify with the official courier service (FedEx/DHL) using legitimate tracking numbers",
                    "why": "Exposes fake parcel claims before scammers can intimidate you.",
                    "official_channel": "Official courier portal",
                },
            ]
        else:
            steps = get_payment_steps(region_code, payment_method)
    else:
        steps = get_payment_steps(region_code, payment_method)

    urgency = "immediate" if lost_money else "today"

    if lost_money:
        speak = (
            f"Because money was transferred, time is critical. "
            f"Call emergency helpline {helpline} immediately, then contact your bank to freeze transactions."
        )
    else:
        speak = (
            f"No financial loss was reported. "
            f"Block the scammer's number, do not respond, and report the message to {reg_data.get('portal_name', 'official channels')}."
        )

    return {
        "urgency": urgency,
        "region": region_code,
        "payment_method": payment_method,
        "steps": steps,
        "speak": speak,
    }


def _extract_identifiers(evidence_items: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Extract phone numbers, links, and UPI IDs from logged evidence."""
    phone_pattern = r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b[6-9]\d{9}\b"
    upi_pattern = r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}"
    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"

    phones = set()
    upis = set()
    urls = set()

    for item in evidence_items:
        text = item.get("content", "")
        if item.get("kind") == "link":
            urls.add(text)
        else:
            for p in re.findall(phone_pattern, text):
                if len(re.sub(r"\D", "", p)) >= 10:
                    phones.add(p.strip())
            for u in re.findall(upi_pattern, text):
                # Avoid standard email false positives if domain is gmail/yahoo unless upi context
                if any(
                    handle in u
                    for handle in ("@okaxis", "@okhdfc", "@oksbi", "@paytm", "@ibl", "@ybl", "@axl")
                ):
                    upis.add(u.strip())
            for url in re.findall(url_pattern, text):
                urls.add(url.strip())

    return {
        "phones": sorted(phones),
        "upi_ids": sorted(upis),
        "urls": sorted(urls),
    }


def generate_report_service(case_id: str) -> dict[str, Any]:
    """Generate a formal complaint-ready incident dossier in Markdown dynamically synthesized for the specific case."""
    case = fetch_case(case_id)
    if not case:
        return {
            "markdown": f"Error: Case file '{case_id}' was not found.",
            "speak": f"Could not find case {case_id} to generate a report.",
        }

    region_code = case.get("region", "IN")
    reg_data = get_region_data(region_code)
    portal_url = get_official_portal_url(region_code)
    helpline = get_helpline_number(region_code)
    evidence_items = case.get("evidence", [])
    timeline = case.get("timeline", [])
    identifiers = _extract_identifiers(evidence_items)

    # Detect dominant threat archetype from evidence
    archetype = "general_fraud"
    max_risk = 0
    primary_text = ""
    red_flag_codes: set[str] = set()

    for item in evidence_items:
        txt = item.get("content", "")
        if not primary_text and txt:
            primary_text = txt
        analysis = item.get("analysis") or {}
        cat = analysis.get("category")
        risk = analysis.get("risk_score", 0)
        max_risk = max(max_risk, risk)
        if cat and cat != "general_fraud":
            archetype = cat
        for rf in analysis.get("red_flags", []):
            if isinstance(rf, dict) and rf.get("code"):
                red_flag_codes.add(rf["code"])

    # Fallback archetype detection from title or text
    combined_content = (case.get("title", "") + " " + primary_text).lower()
    if any(
        w in combined_content
        for w in ("arrest", "cbi", "police", "customs parcel", "narcotics", "court")
    ):
        archetype = "digital_arrest"
    elif any(
        w in combined_content
        for w in ("upi", "collect", "sent rs", "lost money", "debited", "transferred")
    ):
        archetype = "upi_collect_request"
    elif any(
        w in combined_content
        for w in ("link", "http", "url", "portal", "login", "sbi-kyc", "verify")
    ):
        archetype = "phishing_link"
    elif any(
        w in combined_content for w in ("bill", "electricity", "power", "quicksupport", "apk")
    ):
        archetype = "electricity_bill"

    if max_risk == 0:
        max_risk = 95 if archetype in ("digital_arrest", "upi_collect_request") else 85

    # Archetype metadata
    archetype_titles = {
        "digital_arrest": "Digital Arrest Cyber Extortion & Law Enforcement Impersonation",
        "upi_collect_request": "Fraudulent UPI Collect Request & Unauthorized Account Debit",
        "phishing_link": "Deceptive Banking Lookalike Domain & Credential Harvesting Attack",
        "electricity_bill": "Urgent Utility Disconnection Extortion & Malicious Remote Access",
        "tech_support": "Fraudulent Technical Support & Screen-Sharing Device Takeover",
        "courier_customs": "Fabricated Courier Contraband & Customs Clearance Extortion",
        "general_fraud": "Targeted Social Engineering & Financial Cybercrime",
    }
    threat_title = archetype_titles.get(
        archetype, case.get("title", "Suspected Cybercrime Incident")
    )

    # Archetype MO descriptions
    mo_details = {
        "digital_arrest": (
            "- **Authority Simulation:** Perpetrators posed as senior officers from central investigative agencies (CBI / State Police), utilizing forged badges and official-sounding legal jargon.\n"
            "- **Manufactured Incarceration Panic:** Threat actors falsely claimed an illegal contraband parcel was intercepted in the victim's name, demanding immediate confinement under 'Digital Arrest'.\n"
            "- **Continuous Isolation Coercion:** The victim was coerced into remaining on live communication to prevent verification with real law enforcement or family members.\n"
            "- **Unlawful Financial Demand:** Perpetrators directed the victim to transfer funds to a purported 'RBI verification / safety account' under duress."
        ),
        "upi_collect_request": (
            "- **Reverse-Payment Deception:** Perpetrators sent a UPI Collect Request while dishonestly instructing the victim that entering their UPI PIN was required to receive a refund or verify their bill.\n"
            "- **Artificial Temporal Urgency:** High-pressure claims of immediate power disconnection or account locking were fabricated to force hasty compliance without checking the transaction direction.\n"
            "- **Account Draining Attempt:** Exploitation of digital payment instant settlement to transfer funds into mule bank accounts before victim discovery."
        ),
        "phishing_link": (
            "- **Domain Typosquatting & Spoofing:** Perpetrators registered deceptive domain names closely mimicking genuine banking and utility portals (e.g. suspicious TLDs, punycode, or hyphenated brand names).\n"
            "- **Credential & OTP Harvesting:** The malicious portal was engineered to capture net banking credentials, PAN/Aadhaar data, and incoming two-factor authentication codes.\n"
            "- **Immediate Identity Theft Risk:** Harvested credentials enable subsequent unauthorized account access and unauthorized SIM swap attempts."
        ),
        "electricity_bill": (
            "- **Critical Service Threat:** Exploitation of urgent fear regarding imminent electrical power cut-off within hours.\n"
            "- **Malicious Remote App Injection:** Persuading the victim to install screen-sharing software (QuickSupport, AnyDesk) to intercept banking OTPs.\n"
            "- **Unauthorized Financial Extraction:** Coercing nominal payments that expose banking PINs to remote viewing."
        ),
        "general_fraud": (
            "- **Social Engineering Vectors:** Exploitation of urgency, fear of financial penalty, or artificial rewards.\n"
            "- **Channel Manipulation:** Unsolicited outreach via phone calls, SMS spoofing, or messaging applications.\n"
            "- **Data Exfiltration:** Seeking sensitive personal identifiers, OTP codes, or unauthorized banking transfers."
        ),
    }

    # Section 4 Legal Penal Provisions
    if region_code == "IN":
        legal_provisions = (
            "- **Section 66D, Information Technology Act, 2000:** Punishment for cheating by personation by using computer resource (Imprisonment up to 3 years and fine).\n"
            "- **Section 66C, Information Technology Act, 2000:** Punishment for identity theft and fraudulent use of unique electronic identification.\n"
            "- **Section 318(4) / Section 420, Bharatiya Nyaya Sanhita / Indian Penal Code:** Cheating and dishonestly inducing delivery of property (Imprisonment up to 7 years).\n"
            "- **Section 204 / Section 170, BNS / IPC:** Personating a public servant (Impersonation of police, CBI, or government officials).\n"
            "- **Section 308(2) / Section 384, BNS / IPC:** Extortion by putting person in fear of injury or false accusation."
        )
    elif region_code == "US":
        legal_provisions = (
            "- **18 U.S.C. § 1343 (Wire Fraud):** Transmitting fraudulent communications in interstate or foreign commerce (Penalties up to 20-30 years).\n"
            "- **18 U.S.C. § 1030 (Computer Fraud and Abuse Act):** Intentional unauthorized access to protected computer systems.\n"
            "- **18 U.S.C. § 912:** Impersonating an officer, agent, or employee of the United States."
        )
    else:
        legal_provisions = (
            "- **Section 2, Fraud Act 2006:** Fraud by false representation (Dishonest false representation intended to cause gain or loss).\n"
            "- **Section 1, Computer Misuse Act 1990:** Unauthorized access to computer material."
        )

    lines = [
        f"# Cybercrime Incident Report — Case {case['case_id'].upper()}",
        "",
        "> **Notice for Citizen / Victim:** This is an official cybercrime evidentiary dossier compiled by ScamShield. Review and submit this document to law enforcement authorities and official reporting portals without delay. Never share confidential banking PINs or OTPs in public forums.",
        "",
        "## 1. Executive Incident Summary & Risk Assessment",
        f"- **Case Reference:** `{case['case_id'].upper()}`",
        f"- **Threat Classification:** **{threat_title}**",
        f"- **Incident Status:** {case.get('status', 'open').upper()}",
        f"- **Assessed Threat Level:** **CRITICAL / HIGH ({max_risk}/100)**",
        f"- **Jurisdiction:** {reg_data.get('country', 'India')} ({region_code})",
        f"- **Timestamp of Incident Intake:** `{case.get('created_at', '')}`",
        "",
        "### Incident Narrative",
        f'The complainant reported being targeted by an active cybercrime scheme. Based on recorded statements and digital evidence: *"{primary_text or case.get("title", "Targeted cyber fraud attempt")}"*. Threat actors deployed deliberate psychological intimidation and urgency tactics to coerce compliance and extract financial assets or sensitive credentials.',
        "",
        "## 2. Attacker Modus Operandi & Psychological Exploitation",
        mo_details.get(archetype, mo_details["general_fraud"]),
        "",
        "## 3. Suspect Identifiers & Communication Endpoints",
    ]

    if identifiers["phones"]:
        lines.append(
            f"- **Suspect Phone Numbers:** {', '.join(f'`{p}`' for p in identifiers['phones'])}"
        )
    else:
        lines.append("- **Suspect Phone Numbers:** None logged in current evidence chain")

    if identifiers["urls"]:
        lines.append(
            f"- **Deceptive URLs / Lookalike Domains:** {', '.join(f'`{u}`' for u in identifiers['urls'])}"
        )
    else:
        lines.append(
            "- **Deceptive URLs / Lookalike Domains:** None logged in current evidence chain"
        )

    if identifiers["upi_ids"]:
        lines.append(
            f"- **Suspect Payment Identifiers (UPI / VPA):** {', '.join(f'`{v}`' for v in identifiers['upi_ids'])}"
        )
    else:
        lines.append(
            "- **Suspect Payment Identifiers (UPI / VPA):** None logged in current evidence chain"
        )

    lines.extend(
        [
            "",
            "## 4. Technical Evidence Log & Forensic Audit",
        ]
    )

    if not evidence_items:
        lines.append("*No digital artifacts logged yet.*")
    else:
        for idx, item in enumerate(evidence_items, start=1):
            analysis = item.get("analysis") or {}
            verdict_badge = f"**[{analysis.get('verdict', 'LIKELY_SCAM').upper()}]**"
            item_score = analysis.get("risk_score", max_risk)
            lines.append(
                f"### Evidence {idx}: {item['kind'].capitalize()} ({item['evidence_id']}) {verdict_badge}"
            )
            lines.append(f"```text\n{item['content']}\n```")
            lines.append(f"- **Threat Assessment Rating:** {item_score}/100")
            if analysis.get("red_flags"):
                flag_summary = ", ".join(f["code"] for f in analysis["red_flags"])
                lines.append(f"- **Security Red Flags:** `{flag_summary}`")
            if analysis.get("signals"):
                signal_summary = ", ".join(s["code"] for s in analysis["signals"])
                lines.append(f"- **Link Forensic Signals:** `{signal_summary}`")
            lines.append("")

    lines.extend(
        [
            "## 5. Applicable Statutory Legal Provisions",
            legal_provisions,
            "",
            "## 6. Official Emergency Remediation & Filing Instructions",
            f"1. **National Emergency Helpline:** Immediately call **{helpline}** to report active financial fraud and initiate bank payment freezing.",
            f"2. **Official Online Complaint Portal:** File this complaint immediately at [{reg_data.get('portal_name', 'National Cybercrime Portal')}]({portal_url}) attaching this case dossier.",
            f"3. **Golden Hour Bank Account Freeze:** Contact your bank's fraud control unit immediately with the case reference (`{case['case_id'].upper()}`) to place a lien on suspect beneficiary accounts.",
            f"4. **Telecom Spam Reporting:** {reg_data.get('sms_spam_reporting', 'Report fraudulent numbers and messages on telecom portal.')}",
            "5. **Preserve Chain of Custody:** Keep original SMS records, WhatsApp chat exports, call recordings, and UPI transaction reference numbers (UTR) intact for police investigation.",
            "",
            "## 7. Incident Timeline Audit Trail",
        ]
    )

    if not timeline:
        lines.append("*Initial complaint intake logged.*")
    else:
        for ev in timeline:
            lines.append(f"- `{ev['timestamp']}` — {ev['description']}")

    lines.extend(
        [
            "",
            "## 8. Family Safety Net & Caregiver Directive",
            "- Designate a trusted caregiver or family member to review all high-value financial actions.",
            "- Remember: Real police, CBI, customs, and bank officials **never** conduct judicial trials or demand payments over video calls or UPI.",
            "",
            "---",
            f"*Evidentiary dossier synthesized by ScamShield for Alexa+ | Official portal verification required ({reg_data.get('notice', 'Verify before use')}).*",
        ]
    )

    report_markdown = "\n".join(lines)
    speak = (
        f"I compiled your official cybercrime incident dossier for case {case['case_id']}. "
        f"You can copy and submit it directly to {reg_data.get('portal_name', 'the national portal')}."
    )

    return {
        "markdown": report_markdown,
        "speak": speak,
        "ai_generated": True,
    }


def notify_family_service(
    case_id: str | None = None,
    contact_name: str = "your trusted contact",
    relationship: str = "Son",
    alert_channel: str = "whatsapp",
    custom_message: str | None = None,
) -> dict[str, Any]:
    """Prepare a family alert about an active scam attempt (simulated: nothing is actually sent).

    This demo build logs the alert to the case file and returns the message text. It does not
    connect to WhatsApp, SMS, or Alexa announcements, and it says so to the user.

    Args:
        case_id: The identifier of the case file (creates one if missing).
        contact_name: Name of trusted family contact (e.g., 'Rohan').
        relationship: Relation to victim ('Son', 'Daughter', 'Caregiver').
        alert_channel: Notification method ('whatsapp', 'sms', 'alexa_announcement').
        custom_message: Optional custom message override.

    Returns:
        Structured notification confirmation with alert_id, message, and speak confirmation.
    """
    case = fetch_case(case_id) if case_id else None
    if not case:
        case = create_case(title="Urgent Scam Interception", region="IN")
        case_id = case["id"]

    alert_id = f"fam-{random.randint(1000, 9999)}"

    # Determine primary threat name from evidence if available
    threat_topic = "an urgent suspected scam attempt"
    evidence_items = case.get("evidence", [])
    for ev in reversed(evidence_items):
        analysis = ev.get("analysis") or {}
        if isinstance(analysis, dict) and analysis.get("category"):
            threat_topic = f"a high-risk {analysis['category'].replace('_', ' ').title()} scam"
            break

    alert_body = custom_message or (
        f"🚨 ScamShield Family Alert: {relationship} {contact_name}, your family member just encountered "
        f"{threat_topic} on Alexa+. ScamShield flagged it and saved the evidence. "
        f"Case Ref: #{case_id}. Please check in with them to make sure they are safe."
    )

    # Attach this alert to case evidence
    insert_evidence(
        case_id=case_id,
        kind="call_note",
        content=f"Family alert prepared (simulated, not sent) for {contact_name} ({relationship}) via {alert_channel}: {alert_body}",
        analysis={"alert_id": alert_id, "channel": alert_channel, "status": "simulated"},
    )

    speak = (
        f"I have prepared an alert for your {relationship}, {contact_name}, and saved it to your case file. "
        "In this demo it is not actually sent, so please call them yourself."
    )

    return {
        "alert_id": alert_id,
        "case_id": case_id,
        "recipient": contact_name,
        "relationship": relationship,
        "channel": alert_channel,
        "message": alert_body,
        "status": "simulated",
        "sent": False,
        "timestamp": datetime.now(UTC).isoformat(),
        "speak": speak,
    }


def set_safe_word_service(
    contact_name: str,
    safe_word: str,
    relationship: str = "Family",
    hint: str | None = None,
) -> dict[str, Any]:
    """Register or update a secret family safe word for authentication against AI voice clones."""
    clean_name = (contact_name or "Family Member").strip()
    clean_word = (safe_word or "").strip()
    clean_rel = (relationship or "Family").strip()

    if not clean_word:
        return {
            "status": "error",
            "contact_name": clean_name,
            "relationship": clean_rel,
            "speak": "Please provide a non-empty safe word to protect your family.",
        }

    rec = save_safe_word(
        contact_name=clean_name,
        safe_word=clean_word,
        relationship=clean_rel,
        hint=hint,
    )

    speak = (
        f"Secret safe word successfully set for your {clean_rel}, {clean_name}. "
        "If anyone contacts you claiming an emergency from a new number, ask for this secret word before sending money."
    )

    return {
        "status": "success",
        "contact_name": rec["contact_name"],
        "relationship": rec["relationship"],
        "hint": rec["hint"],
        "created_at": rec["created_at"],
        "speak": speak,
    }


def verify_safe_word_service(
    contact_name: str,
    candidate_word: str,
) -> dict[str, Any]:
    """Verify an incoming caller's claimed safe word against registered family codes."""
    clean_name = (contact_name or "").strip()
    clean_candidate = (candidate_word or "").strip()

    result = check_safe_word(clean_name, clean_candidate)

    if not result.get("found"):
        speak = (
            f"No secret safe word has been configured for {clean_name} yet. "
            "Please configure a family safe word in ScamShield settings first."
        )
        return {
            "verified": False,
            "verdict": "contact_not_found",
            "contact_name": clean_name,
            "relationship": "Unknown",
            "warning": "Unregistered contact.",
            "speak": speak,
        }

    rel = result.get("relationship", "Family")
    if result.get("matched"):
        speak = (
            f"Safe word verified! This is confirmed to be your {rel}, {result['contact_name']}. "
            "It is safe to continue speaking with them."
        )
        return {
            "verified": True,
            "verdict": "verified",
            "contact_name": result["contact_name"],
            "relationship": rel,
            "hint": result.get("hint"),
            "speak": speak,
        }
    else:
        speak = (
            f"Warning! Safe word mismatch for your {rel}, {result['contact_name']}. "
            "The caller failed the secret code check. This may be an AI voice clone or impersonation scam. Hang up immediately."
        )
        return {
            "verified": False,
            "verdict": "impersonation_scam_warning",
            "contact_name": result["contact_name"],
            "relationship": rel,
            "hint": result.get("hint"),
            "warning": "CRITICAL: Potential AI Voice Clone or 'Hi Mom' impersonation fraud.",
            "speak": speak,
        }


def check_repeat_offender_service(
    indicator: str,
    indicator_type: str = "auto",
) -> dict[str, Any]:
    """Cross-reference a phone number, UPI ID, or domain against past incidents in ScamShield memory."""
    res = find_repeat_offenders(indicator_value=indicator, indicator_type=indicator_type)

    if res.get("is_repeat_offender"):
        cnt = res["match_count"]
        itype = res["indicator_type"]
        speak = (
            f"Warning: This {itype} appeared in {cnt} earlier case{'s' if cnt != 1 else ''} on ScamShield. "
            "This is a confirmed repeat offender. Do not engage or send any funds."
        )
    else:
        speak = f"No earlier cases found matching {res['indicator_type']} {indicator}."

    res["speak"] = speak
    return res


def export_threat_intel_service(format: str = "json") -> dict[str, Any]:
    """Export all accumulated threat indicators in standardized Cyber Threat Intelligence format."""
    data = export_all_threat_indicators()
    count = data.get("total_unique_indicators", 0)
    repeats = data.get("total_repeat_offenders", 0)

    speak = (
        f"Exported {count} unique threat indicators from the ScamShield database, "
        f"including {repeats} confirmed repeat offenders."
    )
    data["speak"] = speak
    return data
