/**
 * AURALERT — Voice-First Scam Defense (v4.0)
 * Connects Web Speech API, MCP tool call transparency, Family Safety Net, and Elder Scam Drill.
 */

(function () {
    "use strict";

    // Application State
    const state = {
        sessionId: "session-" + Math.random().toString(36).substring(2, 9),
        region: "IN",
        language: "en",
        voiceEnabled: true,
        isListening: false,
        activeCaseId: null,
        reportMarkdown: "",
        isMockMode: new URLSearchParams(window.location.search).get("mock") === "1",
        liveCallId: null,
        liveCallPreset: null,
        liveChunkIndex: 0,
        liveAutoplayTimer: null,
        livePresets: null
    };

    // DOM Elements - Navigation & Audio
    const chatHistory = document.getElementById("chat-history");
    const chatForm = document.getElementById("chat-form");
    const userTextInput = document.getElementById("user-text-input");
    const micBtn = document.getElementById("mic-btn");
    const micStatusLabel = document.getElementById("mic-status-label");
    const voiceStatus = document.getElementById("voice-status");
    const ttsToggle = document.getElementById("tts-toggle");
    const ttsIcon = document.getElementById("tts-icon");
    const ttsLabel = document.getElementById("tts-label");
    const resetBtn = document.getElementById("reset-btn");
    const regionSelect = document.getElementById("region-select");
    const brainBadge = document.getElementById("brain-badge");
    const alexaHaloMini = document.getElementById("alexa-halo-mini");
    const liveCallBtn = document.getElementById("live-call-btn");
    const langToggleBtn = document.getElementById("lang-toggle-btn");
    const langLabel = document.getElementById("lang-label");

    // Case File DOM Elements
    const caseIdBadge = document.getElementById("case-id-badge");
    const riskVerdictTag = document.getElementById("risk-verdict-tag");
    const threatCategoryWrap = document.getElementById("threat-category-wrap");
    const threatCategoryIcon = document.getElementById("threat-category-icon");
    const threatCategoryName = document.getElementById("threat-category-name");
    const riskBar = document.getElementById("risk-bar");
    const riskScoreText = document.getElementById("risk-score-text");
    const redFlagsContainer = document.getElementById("red-flags-container");
    const nextStepsList = document.getElementById("next-steps-list");
    const urgencyBadge = document.getElementById("urgency-badge");
    const timelineContainer = document.getElementById("timeline-container");
    const viewReportBtn = document.getElementById("view-report-btn");
    const exportIntelBtn = document.getElementById("export-intel-btn");

    // Family Safety Net & Safe-Word Elements
    const familyCard = document.getElementById("family-card");
    const familyStatusBadge = document.getElementById("family-status-badge");
    const familyAlertDispatchWrap = document.getElementById("family-alert-dispatch-wrap");
    const dispatchMsgPreview = document.getElementById("dispatch-msg-preview");
    const safeWordInput = document.getElementById("safe-word-input");
    const verifySafeWordBtn = document.getElementById("verify-safe-word-btn");
    const safeWordFeedback = document.getElementById("safe-word-feedback");
    const safeWordActivePill = document.getElementById("safe-word-active-pill");

    // Live Call Guard Modal Elements
    const liveCallModal = document.getElementById("live-call-modal");
    const closeLiveCallModalBtn = document.getElementById("close-live-call-modal-btn");
    const closeLiveCallFooterBtn = document.getElementById("close-live-call-footer-btn");
    const liveCallScenarioSelect = document.getElementById("live-call-scenario-select");
    const startLiveCallBtn = document.getElementById("start-live-call-btn");
    const liveCallDashboard = document.getElementById("live-call-dashboard");
    const liveUrgentWarningBanner = document.getElementById("live-urgent-warning-banner");
    const liveUrgentWarningText = document.getElementById("live-urgent-warning-text");
    const liveCumulativeScoreText = document.getElementById("live-cumulative-score-text");
    const liveVerdictBadge = document.getElementById("live-verdict-badge");
    const liveGaugeBar = document.getElementById("live-gauge-bar");
    const liveFlagsList = document.getElementById("live-flags-list");
    const liveTranscriptFeed = document.getElementById("live-transcript-feed");
    const liveChunkCounter = document.getElementById("live-chunk-counter");
    const nextChunkBtn = document.getElementById("next-chunk-btn");
    const autoplayCallBtn = document.getElementById("autoplay-call-btn");
    const hangUpActionBtn = document.getElementById("hang-up-action-btn");
    const customChunkText = document.getElementById("custom-chunk-text");
    const sendCustomChunkBtn = document.getElementById("send-custom-chunk-btn");

    // Scam Drill Modal Elements
    const drillModeBtn = document.getElementById("drill-mode-btn");
    const drillModal = document.getElementById("drill-modal");
    const closeDrillModalBtn = document.getElementById("close-drill-modal-btn");
    const closeDrillFooterBtn = document.getElementById("close-drill-footer-btn");
    const drillScenarioSelect = document.getElementById("drill-scenario-select");
    const startDrillActionBtn = document.getElementById("start-drill-action-btn");
    const drillActiveContainer = document.getElementById("drill-active-container");
    const drillScammerText = document.getElementById("drill-scammer-text");
    const drillChoiceChips = document.getElementById("drill-choice-chips");
    const drillScoreResult = document.getElementById("drill-score-result");
    const scoreTrophy = document.getElementById("score-trophy");
    const scoreTitle = document.getElementById("score-title");
    const scoreFeedback = document.getElementById("score-feedback");
    const retryDrillBtn = document.getElementById("retry-drill-btn");

    // Report Modal DOM Elements
    const reportModal = document.getElementById("report-modal");
    const reportContent = document.getElementById("report-content");
    const closeModalBtn = document.getElementById("close-modal-btn");
    const closeModalFooterBtn = document.getElementById("close-modal-footer-btn");
    const copyReportBtn = document.getElementById("copy-report-btn");

    // Setup Web Speech Recognition
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    let recognition = null;

    if (SpeechRecognition) {
        recognition = new SpeechRecognition();
        recognition.continuous = false;
        recognition.interimResults = false;
        recognition.lang = "en-IN";

        recognition.onstart = function () {
            state.isListening = true;
            micBtn.classList.add("listening");
            micStatusLabel.textContent = "Listening...";
            voiceStatus.textContent = "Listening";
            voiceStatus.style.color = "var(--danger-red)";
        };

        recognition.onresult = function (event) {
            const transcript = event.results[0][0].transcript;
            userTextInput.value = transcript;
            handleUserSubmit(transcript);
        };

        recognition.onerror = function (event) {
            console.warn("Speech recognition error:", event.error);
            stopListening();
            micStatusLabel.textContent = "Voice error (try typing)";
        };

        recognition.onend = function () {
            stopListening();
        };
    } else {
        micStatusLabel.textContent = "Mic unavailable (type below)";
        micBtn.disabled = true;
        micBtn.title = "Web Speech API not supported in this browser";
    }

    function toggleListening() {
        if (!recognition) return;
        if (state.isListening) {
            recognition.stop();
            stopListening();
        } else {
            try {
                recognition.start();
            } catch (err) {
                console.warn("Failed to start speech recognition:", err);
            }
        }
    }

    function stopListening() {
        state.isListening = false;
        micBtn.classList.remove("listening");
        micStatusLabel.textContent = "Click mic or type";
        voiceStatus.textContent = "Ready";
        voiceStatus.style.color = "";
    }

    // Speech Synthesis with Animated Pulse
    function speakText(text) {
        if (!state.voiceEnabled || !window.speechSynthesis || !text) return;
        window.speechSynthesis.cancel();
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.0;
        utterance.pitch = 1.0;

        const voices = window.speechSynthesis.getVoices();
        if (voices && voices.length > 0) {
            let preferredVoice = null;
            if (state.language === "hi" || /[\u0900-\u097F]/.test(text)) {
                preferredVoice =
                    voices.find((v) => v.lang.startsWith("hi") || v.name.includes("Hindi") || v.name.includes("Lekha") || v.name.includes("Kalpana")) ||
                    voices.find((v) => v.lang.includes("IN"));
            } else {
                preferredVoice =
                    voices.find(
                        (v) =>
                            v.lang.startsWith("en") &&
                            (v.name.includes("Google") ||
                                v.name.includes("Natural") ||
                                v.name.includes("Female") ||
                                v.name.includes("Samantha") ||
                                v.name.includes("Zira"))
                    ) || voices.find((v) => v.lang.startsWith("en"));
            }
            if (preferredVoice) {
                utterance.voice = preferredVoice;
            }
        }

        utterance.onstart = function () {
            if (alexaHaloMini) alexaHaloMini.classList.add("speaking");
        };

        utterance.onend = function () {
            if (alexaHaloMini) alexaHaloMini.classList.remove("speaking");
        };

        utterance.onerror = function () {
            if (alexaHaloMini) alexaHaloMini.classList.remove("speaking");
        };

        window.speechSynthesis.speak(utterance);
    }

    if (window.speechSynthesis) {
        window.speechSynthesis.onvoiceschanged = function () {
            window.speechSynthesis.getVoices();
        };
    }

    // Toggle Voice Audio
    ttsToggle.addEventListener("click", function () {
        state.voiceEnabled = !state.voiceEnabled;
        if (state.voiceEnabled) {
            ttsIcon.textContent = "🔊";
            ttsLabel.textContent = "Voice On";
            ttsToggle.setAttribute("aria-pressed", "true");
        } else {
            if (window.speechSynthesis) window.speechSynthesis.cancel();
            ttsIcon.textContent = "🔇";
            ttsLabel.textContent = "Voice Off";
            ttsToggle.setAttribute("aria-pressed", "false");
        }
    });

    // Chat Message Rendering
    function appendUserMessage(text) {
        const bubble = document.createElement("div");
        bubble.className = "message-bubble user-bubble";
        bubble.innerHTML = `
            <div class="bubble-header">
                <span class="avatar" aria-hidden="true">👤</span>
                <span class="sender-name">You</span>
            </div>
            <div class="bubble-body">
                <p>${escapeHtml(text)}</p>
            </div>
        `;
        chatHistory.appendChild(bubble);
        scrollToBottom();
    }

    function appendAssistantMessage(replyText, toolCalls) {
        const bubble = document.createElement("div");
        bubble.className = "message-bubble assistant-bubble";

        let toolChipsHtml = "";
        if (toolCalls && toolCalls.length > 0) {
            toolCalls.forEach(function (tc, idx) {
                const targetId = `tool-detail-${Date.now()}-${idx}`;
                toolChipsHtml += `
                    <div class="tool-chip">
                        <div class="tool-chip-header" data-target="${targetId}" role="button" tabindex="0" aria-expanded="false">
                            <span>⚡ MCP: <strong>${escapeHtml(tc.name)}</strong></span>
                            <span class="toggle-indicator">▾</span>
                        </div>
                        <div class="tool-chip-body" id="${targetId}" style="display: none;">
                            <strong>Input:</strong> ${escapeHtml(JSON.stringify(tc.arguments, null, 2))}\n
                            <strong>Result:</strong> ${escapeHtml(JSON.stringify(tc.result_summary, null, 2))}
                        </div>
                    </div>
                `;
            });
        }

        bubble.innerHTML = `
            <div class="bubble-header">
                <span class="avatar" aria-hidden="true">🎙️</span>
                <span class="sender-name">Alexa+ (AURALERT)</span>
            </div>
            <div class="bubble-body">
                <p>${escapeHtml(replyText)}</p>
                ${toolChipsHtml}
            </div>
        `;

        chatHistory.appendChild(bubble);

        // Attach collapse toggles for MCP chips
        bubble.querySelectorAll(".tool-chip-header").forEach(function (header) {
            header.addEventListener("click", function () {
                const targetId = header.getAttribute("data-target");
                const body = document.getElementById(targetId);
                const isHidden = body.style.display === "none";
                body.style.display = isHidden ? "block" : "none";
                header.setAttribute("aria-expanded", isHidden ? "true" : "false");
                header.querySelector(".toggle-indicator").textContent = isHidden ? "▴" : "▾";
            });
        });

        scrollToBottom();
        speakText(replyText);
    }

    function scrollToBottom() {
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Dynamic Scenario Choices for Drill Mode
    function getChoicesForScenario(scenarioId) {
        if (scenarioId === "electricity_bill") {
            return [
                { safe: true, text: "I refuse to pay or install any app. I am hanging up and checking with my electricity board directly." },
                { safe: true, text: "I already paid my bill. I will not click any links or download QuickSupport." },
                { safe: false, text: "Okay, I will install QuickSupport and send the payment right now." }
            ];
        } else if (scenarioId === "digital_arrest") {
            return [
                { safe: true, text: "Police do not arrest people over video calls. I am hanging up and calling 1930." },
                { safe: true, text: "I refuse to transfer any money to an RBI verification account. I am contacting my lawyer." },
                { safe: false, text: "Please do not arrest me, I am transferring my savings to your safe account." }
            ];
        } else if (scenarioId === "bank_kyc_otp") {
            return [
                { safe: true, text: "I will never share my OTP with anyone. I am visiting my local bank branch in person." },
                { safe: true, text: "Banks never ask for verification codes over the phone. I am disconnecting." },
                { safe: false, text: "My 6-digit verification code is 482910, please unblock my card." }
            ];
        } else {
            return [
                { safe: true, text: "I did not send any parcel. I refuse to pay any penalty and I am reporting this scam." },
                { safe: true, text: "Customs does not ask for UPI transfers. I am hanging up immediately." },
                { safe: false, text: "I am scared, I will transfer the 45,000 rupees penalty right away." }
            ];
        }
    }

    // Render Drill State
    function renderDrillState(drillState) {
        if (!drillState) return;
        openDrillModal();

        if (drillActiveContainer) drillActiveContainer.style.display = "flex";

        if (drillState.scammer_message && drillScammerText) {
            drillScammerText.textContent = drillState.scammer_message;
        }

        // When starting or viewing scenario (no score yet)
        if (!drillState.score && drillChoiceChips) {
            if (drillScoreResult) drillScoreResult.style.display = "none";
            if (retryDrillBtn) retryDrillBtn.style.display = "none";
            drillChoiceChips.style.display = "flex";
            drillChoiceChips.innerHTML = "";
            const choices = getChoicesForScenario(drillState.scenario_id || "general");
            choices.forEach(function (choice) {
                const btn = document.createElement("button");
                btn.className = "drill-choice-btn";
                btn.innerHTML = `${choice.safe ? "🛡️" : "⚠️"} ${escapeHtml(choice.text)}`;
                btn.addEventListener("click", function () {
                    // Disable all choice buttons while scoring
                    drillChoiceChips.querySelectorAll(".drill-choice-btn").forEach(b => b.disabled = true);
                    handleUserSubmit(choice.text);
                });
                drillChoiceChips.appendChild(btn);
            });
        }

        // Show Score if evaluation is present
        if (typeof drillState.score === "number" && drillScoreResult) {
            drillScoreResult.style.display = "flex";
            if (drillChoiceChips) drillChoiceChips.style.display = "none";
            
            // Remove previous styling states
            drillScoreResult.classList.remove("drill-score-pass", "drill-score-fail", "drill-score-warn");

            if (drillState.passed) {
                drillScoreResult.classList.add("drill-score-pass");
                scoreTrophy.textContent = "🏆";
                scoreTitle.textContent = `Score: ${drillState.score} / 100 — ${drillState.verdict}`;
                scoreTitle.style.color = "#4ade80";
            } else if (drillState.score <= 20) {
                drillScoreResult.classList.add("drill-score-fail");
                scoreTrophy.textContent = drillState.score === 0 ? "🚨" : "❌";
                scoreTitle.textContent = `Score: ${drillState.score} / 100 — ${drillState.verdict}`;
                scoreTitle.style.color = "#f87171";
            } else {
                drillScoreResult.classList.add("drill-score-warn");
                scoreTrophy.textContent = "⚠️";
                scoreTitle.textContent = `Score: ${drillState.score} / 100 — ${drillState.verdict}`;
                scoreTitle.style.color = "#fbbf24";
            }

            if (scoreFeedback) {
                scoreFeedback.textContent = drillState.feedback || drillState.speak;
            }

            if (retryDrillBtn) {
                retryDrillBtn.style.display = "inline-block";
            }

            // Scroll modal smoothly to the score
            if (drillModal) {
                const body = drillModal.querySelector(".modal-body");
                if (body) {
                    setTimeout(() => {
                        body.scrollTo({ top: body.scrollHeight, behavior: "smooth" });
                    }, 80);
                }
            }
        }
    }

    // Update UI Case File Panel
    function updateCaseFileUI(uiState) {
        if (!uiState) return;

        // TOP PRIORITY: SAFE MESSAGE AUDIT HANDLER
        // Instantly resets all meters and badges to safe status with zero contradiction
        if (uiState.verdict === "safe") {
            state.activeCaseId = null;
            state.reportMarkdown = "";
            caseIdBadge.textContent = "NO ACTIVE CASE";
            caseIdBadge.classList.remove("active");
            viewReportBtn.disabled = true;

            // Reset Family Safety Net
            if (familyAlertDispatchWrap) familyAlertDispatchWrap.style.display = "none";
            if (familyStatusBadge) {
                familyStatusBadge.textContent = "🟢 Active Shield";
                familyStatusBadge.className = "badge badge-family-active";
            }

            // Safe Threat Classification
            if (threatCategoryWrap && threatCategoryName) {
                threatCategoryWrap.style.display = "flex";
                threatCategoryWrap.className = "threat-category-wrap safe-category";
                threatCategoryIcon.textContent = "🛡️";
                threatCategoryName.textContent = "Verified Legitimate Communication";
            }

            // Safe Risk Meter
            const score = typeof uiState.risk_score === "number" ? Math.max(0, Math.min(100, uiState.risk_score)) : 5;
            riskBar.style.width = Math.max(3, score) + "%";
            riskBar.setAttribute("aria-valuenow", score);
            riskScoreText.textContent = `Score: ${score} / 100`;
            riskBar.className = "risk-meter-bar";
            riskVerdictTag.className = "verdict-tag verdict-safe";
            riskVerdictTag.textContent = "SAFE";

            // Clean Security Audit
            redFlagsContainer.innerHTML = `
                <div class="safe-banner">
                    <span class="safe-icon">🛡️</span>
                    <div class="safe-text">
                        <strong>Clean Security Audit</strong>
                        <p>No social engineering keywords, urgent threats, or phishing URLs detected.</p>
                    </div>
                </div>
            `;

            // Best Practice Next Steps
            nextStepsList.innerHTML = `
                <li class="step-item safe-step">
                    <div class="step-num">✓</div>
                    <div class="step-content">
                        <strong class="step-action">Standard Security Best Practice</strong>
                        <p class="step-why">Never share one-time passwords (OTPs) or banking PINs, even if asked by someone claiming to be bank staff.</p>
                        <span class="step-channel">🛡️ Safe Communication Hygiene</span>
                    </div>
                </li>
            `;
            urgencyBadge.textContent = "All Clear";
            urgencyBadge.className = "badge badge-urgency safe-badge";

            // Timeline
            timelineContainer.innerHTML = '<p class="empty-state">No incident file opened for verified safe messages.</p>';

            // Drill state if any
            if (uiState.drill_state) {
                renderDrillState(uiState.drill_state);
            }
            return;
        }

        // 1. Case ID
        if (uiState.case_id) {
            state.activeCaseId = uiState.case_id;
            caseIdBadge.textContent = "CASE: " + uiState.case_id.toUpperCase();
            caseIdBadge.classList.add("active");
            viewReportBtn.disabled = false;
        } else {
            state.activeCaseId = null;
            caseIdBadge.textContent = "NO ACTIVE CASE";
            caseIdBadge.classList.remove("active");
            viewReportBtn.disabled = true;
        }

        // 2. Threat Category Banner
        if (threatCategoryWrap && threatCategoryName) {
            if (uiState.category_name || uiState.category) {
                threatCategoryWrap.style.display = "flex";
                threatCategoryName.textContent =
                    uiState.category_name ||
                    uiState.category.replace(/_/g, " ").toUpperCase();
                threatCategoryWrap.className = "threat-category-wrap";

                let icon = "⚠️";
                if (uiState.category === "digital_arrest") {
                    icon = "🚨";
                } else if (
                    uiState.category === "phishing_link" ||
                    (uiState.category && uiState.category.includes("link"))
                ) {
                    icon = "🔗";
                } else if (
                    uiState.category === "financial_loss" ||
                    uiState.category === "upi_collect_request"
                ) {
                    icon = "💸";
                } else if (uiState.category === "gift_card_crypto") {
                    icon = "🎁";
                } else if (uiState.category === "tech_support") {
                    icon = "💻";
                } else if (uiState.category === "courier_customs") {
                    icon = "📦";
                } else if (uiState.category === "fake_job") {
                    icon = "💼";
                } else if (uiState.verdict === "suspicious") {
                    threatCategoryWrap.classList.add("suspicious-category");
                }
                threatCategoryIcon.textContent = icon;
            } else {
                threatCategoryWrap.style.display = "none";
            }
        }

        // 3. Risk Meter
        if (typeof uiState.risk_score === "number") {
            const score = Math.max(0, Math.min(100, uiState.risk_score));
            riskBar.style.width = score + "%";
            riskBar.setAttribute("aria-valuenow", score);
            riskScoreText.textContent = `Score: ${score} / 100`;

            riskBar.className = "risk-meter-bar";
            riskVerdictTag.className = "verdict-tag";

            if (score >= 60 || uiState.verdict === "likely_scam") {
                riskBar.classList.add("danger");
                riskVerdictTag.classList.add("verdict-danger");
                riskVerdictTag.textContent = "LIKELY SCAM";
            } else if (score >= 25 || uiState.verdict === "suspicious") {
                riskBar.classList.add("suspicious");
                riskVerdictTag.classList.add("verdict-suspicious");
                riskVerdictTag.textContent = "SUSPICIOUS";
            } else {
                riskVerdictTag.classList.add("verdict-safe");
                riskVerdictTag.textContent = "SAFE";
            }
        }

        // 4. Red Flags
        if (uiState.red_flags && uiState.red_flags.length > 0) {
            redFlagsContainer.innerHTML = "";
            uiState.red_flags.forEach(function (flag) {
                const chip = document.createElement("div");
                chip.className = "flag-chip";
                const isCritical = [
                    "THREAT_OF_ARREST",
                    "UNUSUAL_PAYMENT_METHOD",
                    "OTP_REQUEST",
                    "REMOTE_ACCESS_REQUEST",
                ].includes(flag.code);
                chip.innerHTML = `
                    <div class="flag-header">
                        <span class="flag-code">⚠️ ${escapeHtml(flag.code)}</span>
                        <span class="flag-severity ${isCritical ? "critical" : "warning"}">${isCritical ? "Critical" : "Warning"}</span>
                    </div>
                    ${flag.evidence ? `<div class="flag-evidence">"${escapeHtml(flag.evidence)}"</div>` : ""}
                    <div class="flag-desc">${escapeHtml(flag.explanation || flag.evidence)}</div>
                `;
                redFlagsContainer.appendChild(chip);
            });
        } else {
            redFlagsContainer.innerHTML = '<p class="empty-state">No red flags logged yet.</p>';
        }

        // 5. Next Steps
        if (uiState.steps && uiState.steps.length > 0) {
            nextStepsList.innerHTML = "";
            uiState.steps.forEach(function (step, idx) {
                const li = document.createElement("li");
                li.className = "step-item";
                li.innerHTML = `
                    <div class="step-num">${idx + 1}</div>
                    <div class="step-content">
                        <strong class="step-action">${escapeHtml(step.action)}</strong>
                        ${step.why ? `<p class="step-why">${escapeHtml(step.why)}</p>` : ""}
                        <span class="step-channel">🏛️ ${escapeHtml(step.official_channel || "National Helpline")}</span>
                    </div>
                `;
                nextStepsList.appendChild(li);
            });
            urgencyBadge.style.display = "inline-block";
            if (uiState.urgency === "immediate") {
                urgencyBadge.textContent = "Immediate Action Required";
                urgencyBadge.className = "badge badge-urgency immediate";
            } else {
                urgencyBadge.textContent = "Recommended Today";
                urgencyBadge.className = "badge badge-urgency";
            }
        } else {
            nextStepsList.innerHTML =
                '<li class="empty-state">Next steps will appear once an incident is reported.</li>';
            urgencyBadge.textContent = "Normal";
            urgencyBadge.className = "badge badge-urgency";
        }

        // 6. Timeline / Evidence Items
        if (uiState.evidence && uiState.evidence.length > 0) {
            timelineContainer.innerHTML = "";
            uiState.evidence.forEach(function (item, idx) {
                const div = document.createElement("div");
                div.className = "timeline-item";
                const kindIcon =
                    item.kind === "link" ? "🔗" : item.kind === "payment" ? "💳" : "💬";

                let repeatTag = "";
                if (item.analysis && item.analysis.repeat_offender_matches && item.analysis.repeat_offender_matches.length > 0) {
                    const rep = item.analysis.repeat_offender_matches[0];
                    repeatTag = `<div class="repeat-offender-pill">🚨 REPEAT OFFENDER (${rep.match_count} prior case${rep.match_count > 1 ? 's' : ''})</div>`;
                }

                div.innerHTML = `
                    <div class="timeline-header">
                        <span class="timeline-kind">${kindIcon} ${escapeHtml((item.kind || "evidence").toUpperCase())}</span>
                        <span class="timeline-badge">Item #${idx + 1}</span>
                    </div>
                    <div class="timeline-body">
                        ${escapeHtml(item.content)}
                        ${repeatTag}
                    </div>
                `;
                timelineContainer.appendChild(div);
            });
        } else {
            timelineContainer.innerHTML = '<p class="empty-state">Timeline is empty.</p>';
        }

        // 7. Family Safety Net Alert Dispatch
        if (uiState.family_alert && familyAlertDispatchWrap && dispatchMsgPreview) {
            familyAlertDispatchWrap.style.display = "block";
            dispatchMsgPreview.textContent = uiState.family_alert.message;
            if (familyStatusBadge) {
                familyStatusBadge.textContent = "🚨 Alert Prepared (demo)";
                familyStatusBadge.className = "badge badge-urgency immediate";
            }
        } else if (familyAlertDispatchWrap) {
            familyAlertDispatchWrap.style.display = "none";
            if (familyStatusBadge) {
                familyStatusBadge.textContent = "🟢 Active Shield";
                familyStatusBadge.className = "badge badge-family-active";
            }
        }

        // 8. Scam Drill State
        if (uiState.drill_state) {
            renderDrillState(uiState.drill_state);
        }
    }

    // Send User Query to Simulated Alexa+ Brain (/api/agent)
    async function handleUserSubmit(text) {
        const query = (text || userTextInput.value || "").trim();
        if (!query) return;

        userTextInput.value = "";
        appendUserMessage(query);

        if (state.isMockMode) {
            handleMockFlow(query);
            return;
        }

        try {
            voiceStatus.textContent = "Analyzing...";
            const res = await fetch("/api/agent", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    session_id: state.sessionId,
                    message: query,
                    region: state.region,
                    language: state.language
                })
            });

            if (!res.ok) {
                throw new Error("HTTP error " + res.status);
            }

            const data = await res.json();
            voiceStatus.textContent = "Ready";

            // Update brain indicator badge
            let brainName = "Local Forensic Engine";
            if (data.brain === "bedrock") {
                brainName = "Amazon Bedrock";
            } else if (data.brain && data.brain.includes("openrouter")) {
                brainName = "OpenRouter Cloud AI";
            } else if (data.brain && data.brain.includes("gemini")) {
                brainName = "Google Gemini AI";
            }
            brainBadge.textContent = `Brain: ${brainName}`;

            appendAssistantMessage(data.reply, data.tool_calls);

            if (data.ui_state) {
                updateCaseFileUI(data.ui_state);
            }
            if (data.report_markdown) {
                state.reportMarkdown = data.report_markdown;
            }
        } catch (err) {
            console.error("Agent error:", err);
            voiceStatus.textContent = "Offline";
            appendAssistantMessage(
                "I encountered a temporary connection issue. Analyzing offline with AURALERT rule engine.",
                []
            );
        }
    }

    // Mock Mode Scripted Flow for Independent UI Polish (?mock=1)
    let mockStep = 0;
    function handleMockFlow(query) {
        brainBadge.textContent = "Brain: Mock Mode";
        setTimeout(function () {
            mockStep++;
            if (mockStep === 1 || query.toLowerCase().includes("arrest") || query.toLowerCase().includes("cbi")) {
                const reply = "This looks like a digital arrest scam. Hang up immediately; the police and government never arrest or conduct trials over video calls.";
                const toolCalls = [
                    {
                        name: "analyze_message",
                        arguments: { text: query, channel: "call", region: "IN" },
                        result_summary: { verdict: "likely_scam", risk_score: 95, category: "digital_arrest" }
                    },
                    {
                        name: "open_case",
                        arguments: { title: "Digital Arrest Scam Call", region: "IN" },
                        result_summary: { case_id: "shield-482" }
                    }
                ];
                appendAssistantMessage(reply, toolCalls);
                updateCaseFileUI({
                    case_id: "shield-482",
                    verdict: "likely_scam",
                    risk_score: 95,
                    red_flags: [
                        { code: "AUTHORITY_IMPERSONATION", explanation: "Impersonating CBI and Crime Branch officers." },
                        { code: "THREAT_OF_ARREST", explanation: "Threatening false arrest warrants to induce panic." },
                        { code: "SECRECY_REQUEST", explanation: "Demanding victim stay continuously on call." }
                    ],
                    steps: [
                        { action: "Hang up the call immediately and block caller number.", official_channel: "Phone block feature" },
                        { action: "Report the scam call to National Cyber Crime Helpline 1930.", official_channel: "Helpline 1930 / cybercrime.gov.in" }
                    ],
                    urgency: "immediate",
                    evidence: [
                        { kind: "call_note", content: query }
                    ]
                });
                state.reportMarkdown = `# Cybercrime Incident Report — Case SHIELD-482\n\n**Incident:** Digital arrest impersonation attempt.\n**Helpline:** 1930\n**Filing Portal:** https://cybercrime.gov.in`;
            } else if (query.toLowerCase().includes("link") || query.toLowerCase().includes("sbi")) {
                const reply = "This link looks like a scam imitating an official website on domain sbi-kyc-verify.top. Do not open it or enter any passwords or OTPs.";
                const toolCalls = [
                    {
                        name: "check_link",
                        arguments: { url: "http://sbi-kyc-verify.top/login" },
                        result_summary: { verdict: "likely_scam", risk_score: 100, signals: ["RISKY_TLD", "BRAND_NAME_IMPERSONATION"] }
                    }
                ];
                appendAssistantMessage(reply, toolCalls);
                updateCaseFileUI({
                    case_id: state.activeCaseId || "shield-482",
                    verdict: "likely_scam",
                    risk_score: 100,
                    red_flags: [
                        { code: "BRAND_NAME_IMPERSONATION", explanation: "Domain unauthorizedly imitates 'sbi'." },
                        { code: "RISKY_TLD", explanation: "Uses high-risk fraudulent TLD '.top'." },
                        { code: "NON_HTTPS", explanation: "Unencrypted HTTP connection." }
                    ]
                });
            } else {
                appendAssistantMessage("I analyzed your input. It has been documented in your case file.", []);
            }
        }, 600);
    }

    // Quick-Start Scenario Buttons
    document.querySelectorAll(".chip-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            const promptText = btn.getAttribute("data-text");
            const action = btn.getAttribute("data-action");
            if (action === "drill") {
                openDrillModal();
            } else {
                userTextInput.value = promptText;
                handleUserSubmit(promptText);
            }
        });
    });

    // Form Submit
    chatForm.addEventListener("submit", function (e) {
        e.preventDefault();
        handleUserSubmit(userTextInput.value);
    });

    // Mic Click
    micBtn.addEventListener("click", toggleListening);

    // Region Change
    regionSelect.addEventListener("change", function () {
        state.region = regionSelect.value;
        appendAssistantMessage(`Region changed to ${regionSelect.options[regionSelect.selectedIndex].text}. Official helplines and reporting steps updated.`, []);
    });

    // Reset Demo
    resetBtn.addEventListener("click", function () {
        state.sessionId = "session-" + Math.random().toString(36).substring(2, 9);
        state.activeCaseId = null;
        state.reportMarkdown = "";
        mockStep = 0;
        chatHistory.innerHTML = `
            <div class="message-bubble assistant-bubble">
                <div class="bubble-header">
                    <span class="avatar" aria-hidden="true">🎙️</span>
                    <span class="sender-name">Alexa+ (AURALERT)</span>
                </div>
                <div class="bubble-body">
                    <p>Demo reset. I'm listening. Describe any suspicious communication or link to get started.</p>
                </div>
            </div>
        `;
        caseIdBadge.textContent = "NO ACTIVE CASE";
        caseIdBadge.classList.remove("active");
        if (threatCategoryWrap) threatCategoryWrap.style.display = "none";
        riskBar.style.width = "0%";
        riskScoreText.textContent = "Score: 0 / 100";
        riskVerdictTag.className = "verdict-tag verdict-neutral";
        riskVerdictTag.textContent = "UNKNOWN";
        redFlagsContainer.innerHTML = '<p class="empty-state">No red flags logged yet.</p>';
        nextStepsList.innerHTML = '<li class="empty-state">Next steps will appear once an incident is reported.</li>';
        timelineContainer.innerHTML = '<p class="empty-state">Timeline is empty.</p>';
        viewReportBtn.disabled = true;

        // Reset Family Alert
        if (familyAlertDispatchWrap) familyAlertDispatchWrap.style.display = "none";
        if (familyStatusBadge) {
            familyStatusBadge.textContent = "🟢 Active Shield";
            familyStatusBadge.className = "badge badge-family-active";
        }
    });

    // Drill Modal Handlers
    function openDrillModal() {
        if (!drillModal) return;
        drillModal.hidden = false;
        drillModal.classList.add("active");
        drillModal.style.display = "flex";
    }

    function closeDrillModal() {
        if (!drillModal) return;
        drillModal.hidden = true;
        drillModal.classList.remove("active");
        drillModal.style.display = "none";
    }

    if (drillModeBtn) drillModeBtn.addEventListener("click", openDrillModal);
    if (closeDrillModalBtn) closeDrillModalBtn.addEventListener("click", closeDrillModal);
    if (closeDrillFooterBtn) closeDrillFooterBtn.addEventListener("click", closeDrillModal);

    if (retryDrillBtn) {
        retryDrillBtn.addEventListener("click", function () {
            if (drillScoreResult) drillScoreResult.style.display = "none";
            if (drillChoiceChips) {
                drillChoiceChips.style.display = "flex";
                drillChoiceChips.querySelectorAll(".drill-choice-btn").forEach(b => b.disabled = false);
            }
            retryDrillBtn.style.display = "none";
        });
    }

    if (drillModal) {
        drillModal.addEventListener("click", function (e) {
            if (e.target === drillModal) closeDrillModal();
        });
    }

    if (startDrillActionBtn && drillScenarioSelect) {
        startDrillActionBtn.addEventListener("click", function () {
            const scn = drillScenarioSelect.value;
            handleUserSubmit(`Alexa, start a scam drill on ${scn}`);
        });
    }

    // Report Modal Handlers
    async function openModal() {
        if (state.activeCaseId) {
            reportContent.textContent = "Compiling dynamic AI cybercrime incident dossier from case database...";
            try {
                const res = await fetch("/api/agent", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        session_id: state.sessionId,
                        message: "generate report",
                        region: state.region
                    })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.report_markdown) {
                        state.reportMarkdown = data.report_markdown;
                    }
                }
            } catch (err) {
                console.warn("Could not fetch live report:", err);
            }
        }
        reportContent.textContent = state.reportMarkdown || "# Cybercrime Incident Report\nNo incident report generated yet. Test an incident first.";
        reportModal.hidden = false;
        reportModal.classList.add("active");
        reportModal.style.display = "flex";
    }

    function closeModal() {
        reportModal.hidden = true;
        reportModal.classList.remove("active");
        reportModal.style.display = "none";
    }

    // Ensure modals start hidden
    closeModal();
    closeDrillModal();
    if (liveCallModal) closeLiveCallModal();

    // ========================================================================
    // HINDI VOICE MODE TOGGLE
    // ========================================================================
    function setLanguageMode(lang) {
        state.language = lang;
        if (lang === "hi") {
            if (langToggleBtn) langToggleBtn.classList.add("active-hi");
            if (langLabel) langLabel.textContent = "English";
            if (userTextInput) userTextInput.placeholder = "संदिग्ध कॉल, SMS या लिंक का विवरण दें या बोलें...";
            if (recognition) recognition.lang = "hi-IN";
            if (voiceStatus) voiceStatus.textContent = "तैयार";

            // Update quick chips
            document.querySelectorAll(".quick-chips-bar .chip-btn").forEach(function (chip) {
                const action = chip.getAttribute("data-action");
                if (action === "drill") {
                    chip.textContent = "🎯 बुजुर्गों के लिए प्रैक्टिस ड्रिल";
                } else if (action === "family") {
                    chip.textContent = "👨‍👩‍👧 परिवार को आपातकालीन सूचना";
                } else if (chip.textContent.includes("Digital Arrest")) {
                    chip.textContent = "📞 'डिजिटल अरेस्ट' कॉल";
                } else if (chip.textContent.includes("Bank Link")) {
                    chip.textContent = "🔗 फर्जी बैंक लिंक";
                } else if (chip.textContent.includes("Lost Money")) {
                    chip.textContent = "💸 यूपीआई से पैसे कट गए";
                } else if (chip.textContent.includes("Legitimate")) {
                    chip.textContent = "✅ सुरक्षित बैंक ओटीपी";
                }
            });
        } else {
            if (langToggleBtn) langToggleBtn.classList.remove("active-hi");
            if (langLabel) langLabel.textContent = "हिन्दी";
            if (userTextInput) userTextInput.placeholder = "Describe a suspicious call, SMS, or paste a link...";
            if (recognition) recognition.lang = "en-IN";
            if (voiceStatus) voiceStatus.textContent = "Ready";

            // Restore quick chips
            document.querySelectorAll(".quick-chips-bar .chip-btn").forEach(function (chip) {
                const action = chip.getAttribute("data-action");
                if (action === "drill") {
                    chip.textContent = "🎯 Elder Scam Drill";
                } else if (action === "family") {
                    chip.textContent = "👨‍👩‍👧 Family Emergency Alert";
                } else if (chip.textContent.includes("डिजिटल अरेस्ट")) {
                    chip.textContent = '📞 "Digital Arrest" Call';
                } else if (chip.textContent.includes("फर्जी बैंक लिंक")) {
                    chip.textContent = "🔗 Fake Bank Link";
                } else if (chip.textContent.includes("पैसे कट गए")) {
                    chip.textContent = "💸 Lost Money via UPI";
                } else if (chip.textContent.includes("सुरक्षित बैंक")) {
                    chip.textContent = "✅ Legitimate Bank OTP";
                }
            });
        }
    }

    if (langToggleBtn) {
        langToggleBtn.addEventListener("click", function () {
            setLanguageMode(state.language === "en" ? "hi" : "en");
        });
    }

    // ========================================================================
    // FAMILY SAFE-WORD VERIFICATION
    // ========================================================================
    async function initFamilySafeWord() {
        try {
            await fetch("/api/safe-word/set", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    contact_name: "Rohan (Son)",
                    safe_word: "Falcon",
                    relationship: "Son",
                    hint: "Rohan's favorite superhero",
                }),
            });
        } catch (e) {
            console.debug("Safe-word initialization:", e);
        }
    }
    initFamilySafeWord();

    if (verifySafeWordBtn && safeWordInput && safeWordFeedback) {
        verifySafeWordBtn.addEventListener("click", async function () {
            const candidate = safeWordInput.value.trim();
            if (!candidate) {
                safeWordInput.focus();
                return;
            }
            try {
                const res = await fetch("/api/safe-word/verify", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        contact_name: "Rohan (Son)",
                        candidate_word: candidate,
                    }),
                });
                const data = await res.json();
                safeWordFeedback.style.display = "block";
                if (data.verified) {
                    safeWordFeedback.className = "safe-word-feedback safe-word-pass";
                    safeWordFeedback.innerHTML = `<strong>✓ SAFE-WORD VERIFIED:</strong> Confirmed Son Rohan. Safe to proceed.`;
                } else {
                    safeWordFeedback.className = "safe-word-feedback safe-word-fail";
                    safeWordFeedback.innerHTML = `<strong>🚨 CODE WORD MISMATCH!</strong> Warning: The caller failed the family safe-word test. Potential AI voice clone or impersonator!`;
                }
                if (data.speak) {
                    speakText(data.speak);
                }
            } catch (err) {
                console.warn("Safe word verification error:", err);
            }
        });
    }

    // ========================================================================
    // THREAT INTELLIGENCE FEED EXPORT (JSON)
    // ========================================================================
    if (exportIntelBtn) {
        exportIntelBtn.addEventListener("click", async function () {
            try {
                const res = await fetch("/api/indicators/export");
                if (!res.ok) throw new Error("HTTP error " + res.status);
                const data = await res.json();
                const jsonStr = JSON.stringify(data, null, 2);
                const blob = new Blob([jsonStr], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "auralert-threat-intel.json";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                const orig = exportIntelBtn.textContent;
                exportIntelBtn.textContent = "✓ Intel Exported!";
                setTimeout(() => {
                    exportIntelBtn.textContent = orig;
                }, 2000);
            } catch (err) {
                console.warn("Export threat intel failed:", err);
            }
        });
    }

    // ========================================================================
    // LIVE CALL GUARD SPEAKERPHONE ENGINE
    // ========================================================================
    function openLiveCallModal() {
        if (!liveCallModal) return;
        liveCallModal.hidden = false;
        liveCallModal.classList.add("active");
        liveCallModal.style.display = "flex";
        fetchLivePresets();
    }

    function closeLiveCallModal() {
        if (!liveCallModal) return;
        if (state.liveAutoplayTimer) {
            clearInterval(state.liveAutoplayTimer);
            state.liveAutoplayTimer = null;
        }
        liveCallModal.hidden = true;
        liveCallModal.classList.remove("active");
        liveCallModal.style.display = "none";
    }

    async function fetchLivePresets() {
        if (state.livePresets) return;
        try {
            const res = await fetch("/api/call-guard/presets");
            if (res.ok) {
                state.livePresets = await res.json();
            }
        } catch (e) {
            console.warn("Could not load call guard presets:", e);
        }
    }

    async function startLiveCallSession() {
        await fetchLivePresets();
        const scnKey = liveCallScenarioSelect.value;
        const preset = state.livePresets ? state.livePresets[scnKey] : null;

        state.liveCallPreset = preset;
        state.liveChunkIndex = 0;
        if (state.liveAutoplayTimer) {
            clearInterval(state.liveAutoplayTimer);
            state.liveAutoplayTimer = null;
        }

        try {
            const res = await fetch("/api/call-guard/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    region: state.region,
                    language: state.language,
                }),
            });
            const data = await res.json();
            state.liveCallId = data.call_id;

            // Reset UI
            liveCallDashboard.style.display = "flex";
            liveTranscriptFeed.innerHTML = "";
            liveCumulativeScoreText.textContent = "0 / 100";
            liveGaugeBar.style.width = "0%";
            liveGaugeBar.style.background = "#22c55e";
            liveVerdictBadge.textContent = "MONITORING";
            liveVerdictBadge.className = "verdict-tag verdict-neutral";
            liveUrgentWarningBanner.style.display = "none";
            liveFlagsList.innerHTML = '<span class="flag-pill flag-clean">Listening for tactics...</span>';
            liveChunkCounter.textContent = `Chunks: 0 / ${preset ? preset.chunks.length : "Live"}`;
            autoplayCallBtn.textContent = "▶️ Auto-Play Dialogue";
            hangUpActionBtn.classList.remove("pulse-danger");

            speakText(data.speak || "Live call monitoring started.");
        } catch (err) {
            console.warn("Failed to start live call:", err);
        }
    }

    async function feedNextLiveChunk(textOverride) {
        if (!state.liveCallId) {
            await startLiveCallSession();
        }

        let chunkText = "";
        let speaker = "caller";

        if (textOverride) {
            chunkText = textOverride;
        } else if (state.liveCallPreset && state.liveCallPreset.chunks) {
            if (state.liveChunkIndex >= state.liveCallPreset.chunks.length) {
                speakText("All dialogue chunks for this scenario have been processed.");
                if (state.liveAutoplayTimer) {
                    clearInterval(state.liveAutoplayTimer);
                    state.liveAutoplayTimer = null;
                    autoplayCallBtn.textContent = "▶️ Auto-Play Dialogue";
                }
                return;
            }
            const chunkObj = state.liveCallPreset.chunks[state.liveChunkIndex];
            chunkText = chunkObj.text;
            speaker = chunkObj.speaker || "caller";
            state.liveChunkIndex++;
        } else {
            return;
        }

        try {
            const res = await fetch("/api/call-guard/chunk", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    call_id: state.liveCallId,
                    text: chunkText,
                    speaker: speaker,
                    language: state.language,
                }),
            });
            const data = await res.json();

            // Append chunk to dialogue feed
            const item = document.createElement("div");
            item.className = `chunk-item chunk-${speaker}`;
            item.innerHTML = `<span class="chunk-speaker-tag">[${speaker.toUpperCase()}]</span> ${escapeHtml(chunkText)}`;
            liveTranscriptFeed.appendChild(item);
            liveTranscriptFeed.scrollTop = liveTranscriptFeed.scrollHeight;

            // Update Counter
            liveChunkCounter.textContent = `Chunks: ${data.chunk_index} ${state.liveCallPreset ? `/ ${state.liveCallPreset.chunks.length}` : ""}`;

            // Update cumulative score & gauge
            const score = Math.max(0, Math.min(100, data.cumulative_risk_score));
            liveCumulativeScoreText.textContent = `${score} / 100`;
            liveGaugeBar.style.width = score + "%";

            // Colorize gauge and verdict
            liveVerdictBadge.className = "verdict-tag";
            if (score >= 60 || data.verdict === "likely_scam") {
                liveGaugeBar.style.background = "linear-gradient(90deg, #ea580c, #dc2626)";
                liveVerdictBadge.classList.add("verdict-danger");
                liveVerdictBadge.textContent = "CRITICAL RISK";
                hangUpActionBtn.classList.add("pulse-danger");
            } else if (score >= 30) {
                liveGaugeBar.style.background = "linear-gradient(90deg, #22c55e, #eab308)";
                liveVerdictBadge.classList.add("verdict-suspicious");
                liveVerdictBadge.textContent = "SUSPICIOUS";
            } else {
                liveGaugeBar.style.background = "#22c55e";
                liveVerdictBadge.classList.add("verdict-safe");
                liveVerdictBadge.textContent = "SAFE";
            }

            // Urgent Warning Banner
            if (data.urgent_warning) {
                liveUrgentWarningBanner.style.display = "flex";
                liveUrgentWarningText.textContent = data.urgent_warning;
            }

            // Red Flags / Tactics
            if (data.flags_detected && data.flags_detected.length > 0) {
                liveFlagsList.innerHTML = "";
                data.flags_detected.forEach(function (f) {
                    const pill = document.createElement("span");
                    pill.className = "flag-pill flag-danger";
                    pill.textContent = `⚠️ ${f.code}`;
                    liveFlagsList.appendChild(pill);
                });
            }

            // Speak warning aloud
            if (data.speak) {
                speakText(data.speak);
            }
        } catch (err) {
            console.warn("Error processing call chunk:", err);
        }
    }

    function toggleAutoplayLiveCall() {
        if (state.liveAutoplayTimer) {
            clearInterval(state.liveAutoplayTimer);
            state.liveAutoplayTimer = null;
            autoplayCallBtn.textContent = "▶️ Auto-Play Dialogue";
        } else {
            if (!state.liveCallId) {
                startLiveCallSession().then(() => {
                    startTimer();
                });
            } else {
                startTimer();
            }
            autoplayCallBtn.textContent = "⏸️ Pause Dialogue";
        }

        function startTimer() {
            feedNextLiveChunk();
            state.liveAutoplayTimer = setInterval(function () {
                feedNextLiveChunk();
            }, 3200);
        }
    }

    async function hangUpAndOpenCase() {
        if (state.liveAutoplayTimer) {
            clearInterval(state.liveAutoplayTimer);
            state.liveAutoplayTimer = null;
        }

        if (!state.liveCallId) {
            closeLiveCallModal();
            return;
        }

        try {
            const res = await fetch("/api/call-guard/end", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    call_id: state.liveCallId,
                    create_case: true,
                }),
            });
            const data = await res.json();
            if (data.case_id) {
                state.activeCaseId = data.case_id;
                caseIdBadge.textContent = `CASE #${data.case_id.toUpperCase()}`;
                viewReportBtn.disabled = false;
                appendAssistantMessage(
                    `🛑 Live Call Intercepted! ${data.speak || ""}`,
                    [{ name: "end_call_guard", arguments: { call_id: state.liveCallId }, result_summary: data }]
                );
            }
        } catch (err) {
            console.warn("Failed to end call guard:", err);
        }

        closeLiveCallModal();
    }

    if (liveCallBtn) liveCallBtn.addEventListener("click", openLiveCallModal);
    if (closeLiveCallModalBtn) closeLiveCallModalBtn.addEventListener("click", closeLiveCallModal);
    if (closeLiveCallFooterBtn) closeLiveCallFooterBtn.addEventListener("click", closeLiveCallModal);
    if (startLiveCallBtn) startLiveCallBtn.addEventListener("click", startLiveCallSession);
    if (nextChunkBtn) nextChunkBtn.addEventListener("click", () => feedNextLiveChunk());
    if (autoplayCallBtn) autoplayCallBtn.addEventListener("click", toggleAutoplayLiveCall);
    if (hangUpActionBtn) hangUpActionBtn.addEventListener("click", hangUpAndOpenCase);

    if (sendCustomChunkBtn && customChunkText) {
        sendCustomChunkBtn.addEventListener("click", function () {
            const txt = customChunkText.value.trim();
            if (txt) {
                customChunkText.value = "";
                feedNextLiveChunk(txt);
            }
        });
        customChunkText.addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
                e.preventDefault();
                const txt = customChunkText.value.trim();
                if (txt) {
                    customChunkText.value = "";
                    feedNextLiveChunk(txt);
                }
            }
        });
    }

    if (liveCallModal) {
        liveCallModal.addEventListener("click", function (e) {
            if (e.target === liveCallModal) closeLiveCallModal();
        });
    }

    viewReportBtn.addEventListener("click", openModal);
    closeModalBtn.addEventListener("click", closeModal);
    closeModalFooterBtn.addEventListener("click", closeModal);

    // Close when clicking on the backdrop outside the modal dialog
    reportModal.addEventListener("click", function (e) {
        if (e.target === reportModal) {
            closeModal();
        }
    });

    // Close when pressing the Escape key
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
            if (!reportModal.hidden) closeModal();
            if (drillModal && !drillModal.hidden) closeDrillModal();
        }
    });

    copyReportBtn.addEventListener("click", function () {
        if (state.reportMarkdown) {
            navigator.clipboard.writeText(state.reportMarkdown).then(function () {
                const originalText = copyReportBtn.textContent;
                copyReportBtn.textContent = "✓ Copied to Clipboard!";
                setTimeout(function () {
                    copyReportBtn.textContent = originalText;
                }, 2000);
            });
        }
    });

    // Initial check on startup
    if (state.isMockMode) {
        brainBadge.textContent = "Brain: Mock Mode";
    } else {
        brainBadge.textContent = "Brain: Live";
    }
})();
