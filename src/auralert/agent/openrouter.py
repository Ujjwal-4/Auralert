"""OpenRouter AI client for simulated Alexa+ brain.

Connects to OpenRouter.ai (supporting free models like Llama 3.3 70B, DeepSeek R1,
Gemini 2.0 Flash) with automatic tool calling to AURALERT's 10 MCP tools.
Falls back smoothly to deterministic router on errors or rate limits.
"""

import json
import logging
import os
from typing import Any

import httpx

from auralert.agent.fallback import CATEGORY_NAMES, handle_fallback_turn
from auralert.agent.mcp_client import mcp_client
from auralert.agent.schemas import AgentResponse, AgentUIState, ToolCallRecord
from auralert.agent.session import session_store

logger = logging.getLogger("auralert.openrouter")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_OPENROUTER_MODEL = "nvidia/nemotron-3.5-lightning:free"

SYSTEM_PROMPT = """You are AURALERT, a defensive voice-first cybersecurity assistant for Alexa+ (clearly a simulated experience).
Your purpose is to protect families, elders, and citizens from cyber fraud, phishing links, and deceptive calls.
Strict behavioral rules:
1. Keep spoken answers concise, calm, and voice-first: maximum 2 sentences per turn.
2. Always lead with the safest immediate action (e.g., "Hang up immediately", "Never share OTP").
3. Use the available tools to analyze messages, inspect links, open cases, log evidence, notify family, run drills, retrieve next steps, and generate cybercrime reports.
4. Never encourage confronting or calling back the scammer.
5. All link checks are 100% static; never visit external websites.
6. Clearly remind citizens to verify official contact details before filing complaints.
7. You are a simulated Alexa+ experience, not an official Alexa client.
"""


def _mcp_tools_to_openai_tools(mcp_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert MCP tool specifications into OpenAI/OpenRouter function tool format."""
    openai_tools = []
    for tool in mcp_tools:
        openai_tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
                },
            }
        )
    return openai_tools


async def run_openrouter_turn(
    session_id: str,
    message: str,
    region: str = "IN",
    api_key: str | None = None,
) -> AgentResponse:
    """Execute an agent turn via OpenRouter Chat Completions API with tool calling."""
    key = api_key or os.getenv("OPENROUTER_API_KEY", "").strip()
    if not key:
        return await handle_fallback_turn(session_id, message, region)

    model = os.getenv("OPENROUTER_MODEL", DEFAULT_OPENROUTER_MODEL).strip()
    session = session_store.get_or_create(session_id, region)
    session.messages.append({"role": "user", "content": message})

    # Prepare tools
    mcp_tools = await mcp_client.list_tools()
    openai_tools = _mcp_tools_to_openai_tools(mcp_tools)

    # Build conversation payload
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]

    # Include recent session turns (up to last 6 messages)
    for m in session.messages[-6:]:
        if isinstance(m.get("content"), str):
            messages.append({"role": m["role"], "content": m["content"]})

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "AURALERT for Alexa+",
    }

    payload = {
        "model": model,
        "messages": messages,
        "tools": openai_tools,
        "tool_choice": "auto",
        "reasoning": {"effort": "none"},
        "temperature": 0.1,
        "max_tokens": 800,
    }

    try:
        async with httpx.AsyncClient(timeout=12.0) as http_client:
            resp = await http_client.post(OPENROUTER_URL, headers=headers, json=payload)
            if resp.status_code != 200:
                logger.warning(
                    "OpenRouter API returned HTTP %s: %s. Falling back to local engine.",
                    resp.status_code,
                    resp.text[:200],
                )
                return await handle_fallback_turn(session_id, message, region)

            data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            return await handle_fallback_turn(session_id, message, region)

        msg_choice = choices[0].get("message", {})
        raw_content = msg_choice.get("content") or ""
        tool_calls_data = msg_choice.get("tool_calls", [])

        tool_records: list[ToolCallRecord] = []
        case_id = session.case_id
        last_tool_speak = ""
        ui_state = AgentUIState(case_id=case_id)

        # Execute any tool calls returned by OpenRouter model
        if tool_calls_data:
            for tc in tool_calls_data:
                func = tc.get("function", {})
                t_name = func.get("name")
                raw_args = func.get("arguments", "{}")

                try:
                    t_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except json.JSONDecodeError:
                    t_args = {}

                # Execute MCP tool locally
                tool_res = await mcp_client.call_tool(t_name, t_args)
                tool_records.append(
                    ToolCallRecord(name=t_name, arguments=t_args, result_summary=tool_res)
                )

                # Capture case ID
                if tool_res.get("case_id"):
                    case_id = tool_res["case_id"]
                    session_store.update_case_id(session_id, case_id)
                    ui_state.case_id = case_id

                # Capture speech confirmation from tool
                if tool_res.get("speak"):
                    last_tool_speak = tool_res["speak"]

                # Populate UI state from primary tools
                if t_name in ("analyze_message", "check_link"):
                    ui_state.risk_score = tool_res.get("risk_score", 0)
                    ui_state.verdict = tool_res.get("verdict", "suspicious")
                    cat = tool_res.get(
                        "category", "phishing_link" if t_name == "check_link" else "general_fraud"
                    )
                    ui_state.category = cat
                    ui_state.category_name = CATEGORY_NAMES.get(cat, cat.replace("_", " ").title())
                    ui_state.red_flags = tool_res.get("red_flags", []) or [
                        {"code": s.get("code", "SIGNAL"), "explanation": s.get("detail", "")}
                        for s in tool_res.get("signals", [])
                    ]

                    # Auto-open case and attach evidence if suspicious/scam
                    if ui_state.verdict in ("likely_scam", "suspicious"):
                        if not case_id:
                            open_res = await mcp_client.call_tool(
                                "open_case",
                                {"title": f"Suspected {ui_state.category_name}", "region": region},
                            )
                            case_id = open_res.get("case_id")
                            session_store.update_case_id(session_id, case_id)
                            ui_state.case_id = case_id
                            tool_records.append(
                                ToolCallRecord(
                                    name="open_case",
                                    arguments={"region": region},
                                    result_summary=open_res,
                                )
                            )

                        ev_res = await mcp_client.call_tool(
                            "add_evidence",
                            {
                                "case_id": case_id,
                                "kind": "link" if t_name == "check_link" else "message",
                                "content": t_args.get("url") or t_args.get("text") or message,
                            },
                        )
                        tool_records.append(
                            ToolCallRecord(
                                name="add_evidence",
                                arguments={"case_id": case_id},
                                result_summary=ev_res,
                            )
                        )

                        steps_res = await mcp_client.call_tool(
                            "next_steps",
                            {"case_id": case_id, "lost_money": False, "payment_method": "none"},
                        )
                        ui_state.steps = steps_res.get("steps", [])
                        tool_records.append(
                            ToolCallRecord(
                                name="next_steps",
                                arguments={"case_id": case_id},
                                result_summary=steps_res,
                            )
                        )

                elif t_name == "next_steps":
                    ui_state.steps = tool_res.get("steps", [])
                    ui_state.urgency = tool_res.get("urgency", "normal")
                elif t_name == "notify_family":
                    ui_state.family_alert = tool_res
                elif t_name in ("start_drill", "score_drill_response"):
                    ui_state.drill_state = tool_res
        else:
            # Fallback static audit if model responded without calling tools:
            # Guarantees that UI risk meter and verdict are NEVER undefined or stale!
            lower_msg = message.lower()
            if any(p in lower_msg for p in ("http://", "https://", "www.", ".top", ".xyz", ".cc")):
                words = message.split()
                url = next((w for w in words if "http" in w.lower() or "www" in w.lower()), message)
                analyzed = await mcp_client.call_tool("check_link", {"url": url})
                t_name = "check_link"
            else:
                analyzed = await mcp_client.call_tool(
                    "analyze_message",
                    {
                        "text": message,
                        "channel": "call" if "call" in lower_msg else "sms",
                        "region": region,
                    },
                )
                t_name = "analyze_message"

            tool_records.append(
                ToolCallRecord(name=t_name, arguments={"text": message}, result_summary=analyzed)
            )
            ui_state.risk_score = analyzed.get("risk_score", 0)
            ui_state.verdict = analyzed.get("verdict", "safe")
            cat = analyzed.get(
                "category",
                "legitimate_notification" if ui_state.verdict == "safe" else "general_fraud",
            )
            ui_state.category = cat
            ui_state.category_name = CATEGORY_NAMES.get(cat, cat.replace("_", " ").title())
            ui_state.red_flags = analyzed.get("red_flags", [])

        # Clean state separation: if verdict is safe, unbind from old scam cases and clear alert dispatches
        if ui_state.verdict == "safe":
            ui_state.case_id = None
            ui_state.family_alert = None
            ui_state.evidence = []
            report_md = None
        else:
            # Fetch latest case state and dynamic report if a case exists
            report_md = None
            active_cid = ui_state.case_id or case_id
            if active_cid:
                try:
                    full_case = await mcp_client.call_tool("get_case", {"case_id": active_cid})
                    ui_state.evidence = full_case.get("evidence", [])
                    rep_res = await mcp_client.call_tool("generate_report", {"case_id": active_cid})
                    report_md = rep_res.get("markdown")
                except Exception as e:
                    logger.debug("Failed to refresh case evidence: %s", e)

        # Spoken reply: prefer concise LLM voice response, or fallback to tool speak
        spoken_reply = raw_content.strip() if raw_content.strip() else last_tool_speak
        if not spoken_reply:
            spoken_reply = "I have evaluated your request and updated your case file."

        # Add assistant turn to session memory
        session.messages.append({"role": "assistant", "content": spoken_reply})

        return AgentResponse(
            reply=spoken_reply,
            tool_calls=tool_records,
            case_id=case_id,
            ui_state=ui_state,
            brain=f"openrouter ({model.split('/')[-1]})",
            report_markdown=report_md,
        )

    except (httpx.TimeoutException, httpx.RequestError, Exception) as err:
        logger.warning("OpenRouter execution failed (%s). Falling back smoothly.", err)
        return await handle_fallback_turn(session_id, message, region)
