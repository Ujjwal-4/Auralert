"""Simulated Alexa+ agent brain powered by Amazon Bedrock Converse API.

Falls back smoothly to deterministic intent router if AWS credentials
are missing, API limits are hit, or calls time out (>8s).
"""

import asyncio
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scamshield.agent.fallback import handle_fallback_turn
from scamshield.agent.mcp_client import mcp_client
from scamshield.agent.openrouter import run_openrouter_turn
from scamshield.agent.schemas import (
    AgentResponse,
    AgentUIState,
    ToolCallRecord,
    mcp_tool_list_to_bedrock_config,
)
from scamshield.agent.session import session_store

logger = logging.getLogger("scamshield.brain")

DEFAULT_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"
BEDROCK_TIMEOUT_SECONDS = 8.0
MAX_TOOL_CALLS_PER_TURN = 4

SYSTEM_PROMPT = """You are AURALERT, a defensive voice-first cybersecurity assistant for Alexa+ (clearly a simulated experience).
Your purpose is to protect families and citizens from financial fraud, phone scams, and deceptive links.
Strict behavioral rules:
1. Keep spoken answers concise, calm, and voice-first: maximum 2 sentences per turn.
2. Always lead with the safest immediate action first (e.g. "Hang up immediately", "Never share OTP").
3. Use the available MCP tools to inspect messages, check links, open cases, log evidence, retrieve next steps, and generate cybercrime reports.
4. Never encourage the user to confront, bait, or call back the scammer.
5. Never visit external websites. All link checking is static.
6. Clearly remind citizens to verify official contact details before filing complaints.
7. You are a simulated Alexa+ experience, not an official Alexa client.
"""


def build_bedrock_history(
    session_messages: list[dict[str, Any]], message: str
) -> list[dict[str, Any]]:
    """Convert stored session turns into a valid Bedrock Converse message list.

    Converse requires the first message to be from the user and roles to alternate,
    so consecutive same-role turns are merged and leading assistant turns are dropped.
    The current user message is always appended last.
    """
    turns: list[dict[str, Any]] = []
    for m in session_messages[-8:]:
        role = m.get("role")
        content = m.get("content")
        if role not in ("user", "assistant") or not isinstance(content, str) or not content.strip():
            continue
        if turns and turns[-1]["role"] == role:
            turns[-1]["content"][0]["text"] += "\n" + content
        else:
            turns.append({"role": role, "content": [{"text": content}]})

    while turns and turns[0]["role"] != "user":
        turns.pop(0)

    if turns and turns[-1]["role"] == "user":
        turns[-1]["content"][0]["text"] += "\n" + message
    else:
        turns.append({"role": "user", "content": [{"text": message}]})
    return turns


class AgentBrain:
    """Orchestrates Bedrock Converse model with deterministic fallback."""

    def status(self) -> dict[str, Any]:
        """Report which brains are configured (never exposes secrets)."""
        has_aws = bool(
            os.getenv("AWS_ACCESS_KEY_ID")
            or os.getenv("AWS_PROFILE")
            or os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        )
        return {
            "bedrock": {"configured": has_aws, "model_id": self.model_id, "region": self.region},
            "openrouter": {"configured": bool(os.getenv("OPENROUTER_API_KEY", "").strip())},
            "fallback": {"configured": True},
        }

    def __init__(self) -> None:
        self.model_id = os.getenv("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID)
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self._bedrock_client = None
        self._tool_config = None

    def _get_bedrock_client(self) -> Any:
        if self._bedrock_client is not None:
            return self._bedrock_client

        try:
            self._bedrock_client = boto3.client(
                "bedrock-runtime",
                region_name=self.region,
            )
            return self._bedrock_client
        except (BotoCoreError, ClientError, RuntimeError, ValueError) as e:
            logger.info("Bedrock client init failed: %s", e)
            return None

    async def _get_tool_config(self) -> dict[str, Any]:
        if self._tool_config is None:
            mcp_tools = await mcp_client.list_tools()
            self._tool_config = mcp_tool_list_to_bedrock_config(mcp_tools)
        return self._tool_config

    async def process_turn(
        self,
        session_id: str,
        message: str,
        region: str = "IN",
    ) -> AgentResponse:
        """Process a conversational turn using Bedrock, OpenRouter, or Fallback router."""
        session = session_store.get_or_create(session_id, region)
        text_lower = message.lower()

        # Priority 0: Deterministic critical operations (Elder Drill, Report Generation, Family Alert, Payment Loss)
        # These MUST be deterministic so elder drills and financial emergencies are 100% reliable and never loop
        is_drill_turn = bool(session.active_drill_id) or any(
            w in text_lower
            for w in (
                "start drill",
                "scam drill",
                "practice scam",
                "practice drill",
                "elder drill",
                "training mode",
                "start a drill",
            )
        )
        is_report_request = any(
            w in text_lower
            for w in (
                "generate report",
                "view report",
                "give me report",
                "complaint report",
                "file report",
            )
        )
        is_family_request = any(
            w in text_lower
            for w in (
                "notify family",
                "notify my family",
                "alert my son",
                "alert family",
                "warn family",
                "send family alert",
            )
        )
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
            )
        )

        if is_drill_turn or is_report_request or is_family_request or is_payment_loss:
            return await handle_fallback_turn(session_id, message, region)

        # 1. Primary: Amazon Bedrock (Official AWS Hackathon Cloud Brain)
        client = self._get_bedrock_client()
        has_aws = bool(
            os.getenv("AWS_ACCESS_KEY_ID")
            or os.getenv("AWS_PROFILE")
            or os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        )

        if client and has_aws:
            try:
                return await asyncio.wait_for(
                    self._run_bedrock_converse(client, session_id, message, region),
                    timeout=BEDROCK_TIMEOUT_SECONDS,
                )
            except (TimeoutError, ClientError, BotoCoreError, RuntimeError) as err:
                logger.warning("Bedrock invocation failed or timed out (%s). Falling back.", err)

        # 2. Secondary: OpenRouter AI (Free / Sandbox Cloud Models)
        openrouter_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        if openrouter_key:
            try:
                logger.info("Using OpenRouter cloud AI brain.")
                return await run_openrouter_turn(
                    session_id=session_id,
                    message=message,
                    region=region,
                    api_key=openrouter_key,
                )
            except Exception as err:
                logger.warning("OpenRouter execution failed (%s). Falling back.", err)

        # 3. Tertiary: Deterministic Fallback Router (Zero-Downtime Guarantee)
        logger.info(
            "Using deterministic fallback router (no AWS or OpenRouter credentials configured)."
        )
        return await handle_fallback_turn(session_id, message, region)

    async def _run_bedrock_converse(
        self,
        client: Any,
        session_id: str,
        message: str,
        region: str,
    ) -> AgentResponse:
        """Execute Bedrock Converse API loop with tool use."""
        session = session_store.get_or_create(session_id, region)
        tool_config = await self._get_tool_config()

        # Format conversation (with prior turns) for Bedrock Converse
        messages = build_bedrock_history(session.messages, message)
        session.messages.append({"role": "user", "content": message})

        system = [{"text": SYSTEM_PROMPT}]
        tool_calls_executed: list[ToolCallRecord] = []
        turn_count = 0
        final_reply = ""
        report_markdown = None
        latest_ui_state = AgentUIState(case_id=session.case_id)

        while turn_count < MAX_TOOL_CALLS_PER_TURN:
            turn_count += 1
            # Run blocking boto3 client in thread pool
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.converse(
                    modelId=self.model_id,
                    messages=messages,
                    system=system,
                    toolConfig=tool_config,
                ),
            )

            output = response.get("output", {})
            assistant_msg = output.get("message", {})
            content_blocks = assistant_msg.get("content", [])

            # Check for tool use requests
            tool_requests = [c["toolUse"] for c in content_blocks if "toolUse" in c]
            text_blocks = [c["text"] for c in content_blocks if "text" in c]

            if text_blocks:
                final_reply = " ".join(text_blocks)

            if not tool_requests:
                # Model finished its turn
                break

            # Execute tool calls via loopback MCP HTTP client
            tool_results = []
            for tr in tool_requests:
                tool_name = tr["name"]
                tool_args = tr.get("input", {})
                tool_id = tr["toolUseId"]

                res_data = await mcp_client.call_tool(tool_name, tool_args)
                tool_calls_executed.append(
                    ToolCallRecord(
                        name=tool_name,
                        arguments=tool_args,
                        result_summary=res_data,
                    )
                )

                if "case_id" in res_data:
                    session.case_id = res_data["case_id"]
                    session_store.update_case_id(session_id, res_data["case_id"])
                    latest_ui_state.case_id = res_data["case_id"]

                if "risk_score" in res_data:
                    latest_ui_state.risk_score = res_data["risk_score"]
                if "verdict" in res_data:
                    latest_ui_state.verdict = res_data["verdict"]
                if "red_flags" in res_data:
                    latest_ui_state.red_flags = res_data["red_flags"]
                if "steps" in res_data:
                    latest_ui_state.steps = res_data["steps"]
                if "markdown" in res_data:
                    report_markdown = res_data["markdown"]

                tool_results.append(
                    {
                        "toolResult": {
                            "toolUseId": tool_id,
                            "content": [{"json": res_data}],
                        }
                    }
                )

            messages.append(assistant_msg)
            messages.append({"role": "user", "content": tool_results})

        if not final_reply:
            final_reply = "I evaluated your input and updated your case file."

        session.messages.append({"role": "assistant", "content": final_reply})

        return AgentResponse(
            reply=final_reply,
            tool_calls=tool_calls_executed,
            case_id=session.case_id,
            ui_state=latest_ui_state,
            brain="bedrock",
            report_markdown=report_markdown,
        )


# Global brain instance
agent_brain = AgentBrain()
