# ScamShield Demo Scenarios

These 6 scripted scenarios represent real-world fraud patterns, edge cases, and multi-region support for live judging and video recording.

---

## Scenario A: "Digital Arrest" Phone Call (India)

- **Context:** An elder receives a terrifying call from someone claiming to be an Inspector from the CBI / Police Crime Branch stating their name was found in an illegal money laundering or narcotics shipment.
- **Exact User Line:**
  > *"I got a call from CBI saying I am under digital arrest for a drug parcel seized at Mumbai airport. They told me not to hang up or police will arrest me."*
- **Expected Tool Calls:**
  1. `analyze_message(text=..., channel="call", region="IN")`
  2. `open_case(title="Digital Arrest Threat", region="IN")`
  3. `add_evidence(case_id=..., kind="message", content=...)`
  4. `next_steps(case_id=..., lost_money=False)`
- **Expected Verdict & Risk:**
  - **Verdict:** `LIKELY_SCAM`
  - **Risk Score:** 100 / 100
  - **Red Flags:** `AUTHORITY_IMPERSONATION`, `THREAT_OF_ARREST`, `SECRECY_REQUEST`
- **Spoken Voice Response:**
  > *"This looks like a digital arrest scam. Hang up immediately; the police and government never arrest or conduct trials over video calls."*

---

## Scenario B: Fake KYC SMS with Lookalike Bank Link

- **Context:** An SMS arrives stating the victim's State Bank of India account is suspended and directs them to an unverified phishing site.
- **Exact User Line:**
  > *"Check this link sent to me by SMS: http://sbi-kyc-verify-portal.top/login"*
- **Expected Tool Calls:**
  1. `check_link(url="http://sbi-kyc-verify-portal.top/login")`
  2. `add_evidence(case_id=..., kind="link", content=...)`
- **Expected Verdict & Risk:**
  - **Verdict:** `LIKELY_SCAM`
  - **Risk Score:** 100 / 100
  - **Signals:** `RISKY_TLD` (.top), `BRAND_NAME_IMPERSONATION` (sbi), `NON_HTTPS`, `CREDENTIAL_KEYWORDS_IN_PATH` (/login)
- **Spoken Voice Response:**
  > *"This link looks like a scam imitating an official website on domain sbi-kyc-verify-portal.top. Do not open it or enter any passwords or OTPs."*

---

## Scenario C: UPI Collect-Request Cashback Trick

- **Context:** Victim is told they won Rs 2,500 cashback on Google Pay / PhonePe, but is asked to approve a collect request and enter their secret UPI PIN.
- **Exact User Line:**
  > *"Someone on PhonePe told me I won cashback of Rs 2,500 and said to approve the collect request and enter my UPI PIN to receive the money."*
- **Expected Tool Calls:**
  1. `analyze_message(text=..., channel="sms", region="IN")`
  2. `add_evidence(case_id=..., kind="message", content=...)`
- **Expected Verdict & Risk:**
  - **Verdict:** `LIKELY_SCAM`
  - **Risk Score:** 75-100 / 100
  - **Category:** `upi_collect_request`
  - **Red Flags:** `PAYMENT_PRESSURE`, `TOO_GOOD_TO_BE_TRUE`
- **Spoken Voice Response:**
  > *"This is a UPI collect scam. Decline the request; you never enter your UPI PIN to receive money or refunds."*

---

## Scenario D: Legitimate Bank OTP Notification (Low False Positive Demo)

- **Context:** Shows that ScamShield does not cry wolf on benign transactional bank notifications that contain security warnings.
- **Exact User Line:**
  > *"OTP for your transaction at Amazon India for Rs. 1,499 is 482910. Do NOT share this OTP with anyone. SBI never asks for OTP."*
- **Expected Tool Calls:**
  1. `analyze_message(text=..., channel="sms", region="IN")`
- **Expected Verdict & Risk:**
  - **Verdict:** `SAFE`
  - **Risk Score:** 5 / 100
  - **Category:** `legitimate_notification`
- **Spoken Voice Response:**
  > *"This appears to be a legitimate automated bank notification. Remember to follow its advice: never share your one-time passwords with anyone."*

---

## Scenario E: User Already Lost Money via UPI (Golden-Hour Remediation + Ready Report)

- **Context:** The victim panicked and already transferred Rs 15,000 to the scammer's UPI ID.
- **Exact User Line:**
  > *"I got panicked and sent Rs 15,000 via UPI to fraudster@okaxis. What should I do now?"*
- **Expected Tool Calls:**
  1. `add_evidence(case_id=..., kind="payment", content=...)`
  2. `next_steps(case_id=..., lost_money=True, payment_method="upi")`
  3. `generate_report(case_id=...)`
- **Expected Urgency & Steps:**
  - **Urgency:** `IMMEDIATE`
  - **Step 1:** Call National Cybercrime Helpline `1930` immediately to initiate inter-bank freeze.
  - **Step 2:** Contact bank fraud department to report unauthorized UPI debit.
  - **Step 3:** Report VPA inside UPI app.
- **Spoken Voice Response:**
  > *"Because money was transferred, time is critical. Call emergency helpline 1930 immediately, then contact your bank to freeze transactions."*

---

## Scenario F: Region Switch to United States (Global Scalability)

- **Context:** Demonstrates regional adaptation to US regulatory frameworks, FTC reporting, and FBI IC3.
- **Action:** Switch Region dropdown in header to **United States (US)**.
- **Exact User Line:**
  > *"I received an email claiming my wire transfer was sent to IRS, and I need to buy Apple Gift Cards to settle a tax penalty."*
- **Expected Tool Calls:**
  1. `analyze_message(text=..., channel="email", region="US")`
  2. `next_steps(case_id=..., lost_money=False, payment_method="gift_card")`
- **Expected Jurisdiction Details:**
  - **Helpline:** 1-877-382-4357 (FTC)
  - **Portals:** `reportfraud.ftc.gov` & `ic3.gov`
- **Spoken Voice Response:**
  > *"No official company, utility, or government entity accepts gift cards as payment. Block the sender and report this to the FTC."*
