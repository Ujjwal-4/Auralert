"""Schema conversion between MCP tools and Amazon Bedrock Converse toolSpec."""

from typing import Any

from pydantic import BaseModel, Field


class AgentRequest(BaseModel):
    """Input payload to POST /api/agent."""

    session_id: str = Field(..., description="Unique session identifier")
    message: str = Field(
        ..., min_length=1, max_length=20000, description="User spoken or typed input"
    )
    region: str = Field(default="IN", description="Jurisdiction ISO code (IN, US, UK)")


class ToolCallRecord(BaseModel):
    """Record of an executed tool call for transparency."""

    name: str
    arguments: dict[str, Any]
    result_summary: Any


class AgentUIState(BaseModel):
    """Live case file state returned to the UI."""

    case_id: str | None = None
    risk_score: int | None = None
    verdict: str | None = None
    category: str | None = None
    category_name: str | None = None
    red_flags: list[dict[str, Any]] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    urgency: str = "normal"
    family_alert: dict[str, Any] | None = None
    drill_state: dict[str, Any] | None = None


class AgentResponse(BaseModel):
    """Output payload from POST /api/agent."""

    reply: str
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    case_id: str | None = None
    ui_state: AgentUIState = Field(default_factory=AgentUIState)
    brain: str = Field(default="fallback", description="'bedrock' or 'fallback'")
    report_markdown: str | None = None


def mcp_tool_to_bedrock_spec(mcp_tool: dict[str, Any]) -> dict[str, Any]:
    """Convert an MCP tool definition from tools/list to a Bedrock Converse toolSpec.

    Bedrock Converse API expects:
    {
        "toolSpec": {
            "name": str,
            "description": str,
            "inputSchema": {
                "json": dict (JSON schema)
            }
        }
    }
    """
    name = mcp_tool.get("name", "")
    description = mcp_tool.get("description", "")
    input_schema = mcp_tool.get("inputSchema", {"type": "object", "properties": {}})

    return {
        "toolSpec": {
            "name": name,
            "description": description,
            "inputSchema": {
                "json": input_schema,
            },
        }
    }


def mcp_tool_list_to_bedrock_config(mcp_tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert a list of MCP tools into Bedrock toolConfig structure."""
    return {"tools": [mcp_tool_to_bedrock_spec(t) for t in mcp_tools]}
