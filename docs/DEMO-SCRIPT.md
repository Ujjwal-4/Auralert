# Demo Video Script: ScamShield for Alexa+

> **Build, Ship, Shape: Amazon Developer Hackathon 2026**  
> **Track:** Alexa+ (Self-Hosted Model Context Protocol Server & Agent Brain)  
> **Target Video Length:** 2 minutes 30 seconds (Hard Limit: Under 3:00)  
> **Platform:** Public YouTube / Vimeo (English audio with English closed captions)

---

## 📋 Pre-Recording Setup Checklist

Before pressing record, make sure your environment matches this checklist:
- [ ] **Display Resolution:** Set your screen resolution to **1920x1080 (1080p)**.
- [ ] **Browser Window:** Chrome or Edge open at full-screen on `http://127.0.0.1:8000/`. Close all extraneous tabs, bookmarks bar, and notification popups.
- [ ] **Audio Setup:** External USB microphone configured. Ensure room is quiet and audio levels peak between -6dB and -3dB.
- [ ] **Backend Running:** Verify the ScamShield backend is running in terminal:
  ```bash
  python scripts/run.py
  ```
- [ ] **Microphone Permission:** Verify Chrome has microphone access granted on `http://127.0.0.1:8000/`.
- [ ] **Contingency Backup:** If browser speech recognition or microphone fails during recording, you can use the pre-loaded **Quick-Start scenario chips** or type directly into the input bar. If internet fails, append `?mock=1` for guaranteed offline simulation.

---

## 🎬 Timed 2:30 Video Walkthrough & Script

```
Total Target Runtime: 02:30
Safe Buffer: 30 seconds below 03:00 limit
```

### [0:00 - 0:25] Segment 1: The Crisis & Hook (25s)

| Time | On-Screen Action | Narration (Voice-Over) |
|---|---|---|
| **0:00 - 0:10** | Title card: **ScamShield for Alexa+**.<br/>Show brief news headlines of "Digital Arrest" and cyber fraud losses. | *"Over one trillion dollars is lost to cybercrime every year. In India and across the world, criminal syndicates exploit panic with 'digital arrest' video calls and fake KYC threats—targeting elderly and vulnerable families."* |
| **0:10 - 0:25** | Cut to the **ScamShield Web Console** (`http://127.0.0.1:8000/`). Show the clean voice interface and glowing Alexa orb. | *"When a threatening call or text arrives, victims don't know who to call or how to inspect malicious links. What if your smart speaker could act as an instant, calm cybersecurity guardian? This is ScamShield for Alexa+."* |

---

### [0:25 - 0:50] Segment 2: Architecture & MCP Integration (25s)

| Time | On-Screen Action | Narration (Voice-Over) |
|---|---|---|
| **0:25 - 0:38** | Cut to Mermaid Architecture diagram (or highlight the top status bar showing *MCP Server Connected*). | *"ScamShield connects Alexa+ to a self-hosted Model Context Protocol server over Streamable HTTP, adhering to the latest 2025-11-25 MCP specification. It exposes seven defensive cybersecurity tools."* |
| **0:38 - 0:50** | Show Bedrock integration and 100% offline detection engine badges. | *"Powered by Amazon Bedrock's Converse API with a deterministic zero-downtime fallback router, ScamShield analyzes messages and phishing links with zero outbound network calls—eliminating SSRF and malware risks."* |

---

### [0:50 - 1:25] Segment 3: Live Demo 1 — Digital Arrest & Link Triage (35s)

| Time | On-Screen Action | Narration (Voice-Over) |
|---|---|---|
| **0:50 - 1:00** | Click the **Microphone** button (or click the quick-start chip `"🚨 Digital Arrest Call"`).<br/>Say clearly: *"I got a call claiming to be CBI saying I'm under digital arrest. Is this real?"* | *(Presenter speaking into mic)*: *"Alexa, I got a call claiming to be CBI saying I'm under digital arrest. Is this real?"* |
| **1:00 - 1:12** | Alexa orb pulses. The spoken response plays:<br/>*"This looks like a digital arrest scam. Hang up immediately; the police never arrest over video calls."*<br/>Risk gauge shoots to **85 (Likely Scam)**. | *(Alexa voice plays)*: *"This looks like a digital arrest scam. Hang up immediately; the police and government never arrest or conduct trials over video calls."* |
| **1:12 - 1:25** | Point cursor at the **MCP Tool Chip**: expand `analyze_message` and show JSON output with red-flag code `THREAT_OF_ARREST`.<br/>Case ID `shield-XXXX` appears in the sidebar. | *"Alexa delivers a calm, two-sentence verdict, visually logs the red flags, and automatically creates an incident case file. Notice the transparent MCP tool chip showing the exact JSON-RPC call."* |

---

### [1:25 - 2:00] Segment 4: Live Demo 2 — Financial Loss & Golden Hour Report (35s)

| Time | On-Screen Action | Narration (Voice-Over) |
|---|---|---|
| **1:25 - 1:35** | Say into mic (or click `"💸 Lost Money via UPI"`):<br/>*"I got panicked and sent 15,000 Rupees via UPI to fraudster@okaxis. What should I do now?"* | *(Presenter speaking into mic)*: *"I got panicked and sent 15,000 Rupees via UPI to fraudster@okaxis. What should I do now?"* |
| **1:35 - 1:48** | Risk gauge shows **95 (Emergency)**. Alexa responds:<br/>*"Because money was involved, contact your bank and helpline 1930 immediately."*<br/>Steps checklist displays Step 1: Call 1930, Step 2: Bank dispute. | *"When money has been sent, every second counts. ScamShield triggers immediate 'Golden Hour' guidance, providing the exact official 1930 cybercrime helpline and dispute steps for UPI."* |
| **1:48 - 2:00** | Click **"View Case Report"** button. The modal opens showing the Markdown report with timestamped evidence. | *"With one click, ScamShield generates an official Markdown incident report, formatted with extracted transaction IDs, ready to copy and paste into cybercrime.gov.in."* |

---

### [2:00 - 2:18] Segment 5: Global Scalability & Reliability (18s)

| Time | On-Screen Action | Narration (Voice-Over) |
|---|---|---|
| **2:00 - 2:10** | Click the **Region selector** in the header and switch from `IN` to `US`. Type or speak a tax gift card scam message. | *"ScamShield scales globally. Switching to the US immediately reconfigures emergency guidance to the FTC helpline at 1-877-382-4357 and the FBI IC3 portal."* |
| **2:10 - 2:18** | Briefly show terminal with `pytest tests -v` passing all 35 tests including zero-network monkeypatching. | *"With 35 automated tests, 100% precision and recall on our benchmark, and complete prompt-injection immunity, ScamShield is enterprise-hardened."* |

---

### [2:18 - 2:30] Segment 6: Closing & Submission Credits (12s)

| Time | On-Screen Action | Narration (Voice-Over) |
|---|---|---|
| **2:18 - 2:30** | Cut to closing slide showing:<br/>• **ScamShield for Alexa+**<br/>• Amazon Developer Hackathon 2026<br/>• AWS Builder (Amazon Bedrock) & Open Source (MIT)<br/>• GitHub Repository URL | *"ScamShield empowers Alexa+ to transform from a passive voice assistant into an active cybersecurity guardian. Thank you for watching!"* |

---

## 💡 Pro-Tips for a Winning Recording

1. **Keep Pace Snappy:** Do not pause for more than 1 second between sentences. Keep energy confident, empathetic, and professional.
2. **Audio Quality Matters Most:** Judges will forgive simple graphics, but poor audio will lose points. Keep the microphone 6 inches from your mouth.
3. **Show, Don't Just Tell:** When mentioning "MCP tools", always highlight or expand the tool chip in the UI so judges see the real-time JSON-RPC interaction.
4. **Export Settings:** Export MP4 at 1080p, 60fps or 30fps, H.264 video, AAC audio. Upload to YouTube as **Public** or **Unlisted**. Ensure English captions are enabled.
