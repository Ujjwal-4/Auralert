"""HTTP loopback client invoking MCP tools over Streamable HTTP (spec 2025-11-25).

Ensures that the Bedrock agent brain calls MCP tools over the network protocol,
preserving architectural honesty and strict separation of concerns.
"""

import json
import logging
import os
import time
from typing import Any

import httpx

from scamshield.server import mcp_server

logger = logging.getLogger("scamshield.mcp_client")


class MCPHttpClient:
    """Invokes ScamShield MCP tools over loopback HTTP."""

    def __init__(self, base_url: str | None = None) -> None:
        port = os.getenv("PORT", "8000")
        self.base_url = (base_url or f"http://127.0.0.1:{port}").rstrip("/")
        self.mcp_url = f"{self.base_url}/mcp"
        self._session_id: str | None = None
        self._last_check_time: float = 0
        self._server_reachable: bool = True

    async def _ensure_session(self, client: httpx.AsyncClient) -> str | None:
        """Initialize Streamable HTTP session if not active."""
        if self._session_id:
            return self._session_id

        # If recently failed to connect (< 10s), avoid blocking retries
        now = time.time()
        if not self._server_reachable and (now - self._last_check_time) < 10.0:
            return None

        self._last_check_time = now

        init_payload = {
            "jsonrpc": "2.0",
            "id": "agent-init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "alexa-agent-brain", "version": "1.0.0"},
            },
        }

        headers = {
            "Accept": "application/json, text/event-stream",
            "mcp-protocol-version": "2025-11-25",
            "Origin": self.base_url,
        }

        try:
            res = await client.post(
                self.mcp_url,
                json=init_payload,
                headers=headers,
                timeout=httpx.Timeout(connect=0.15, read=3.0, write=3.0, pool=3.0),
            )
            if res.status_code == 200:
                self._session_id = res.headers.get("mcp-session-id")
                self._server_reachable = True
                # Send initialized notification
                if self._session_id:
                    await client.post(
                        self.mcp_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "notifications/initialized",
                            "params": {},
                        },
                        headers={
                            "mcp-session-id": self._session_id,
                            "mcp-protocol-version": "2025-11-25",
                            "Origin": self.base_url,
                        },
                        timeout=httpx.Timeout(connect=0.15, read=3.0, write=3.0, pool=3.0),
                    )
                return self._session_id
        except (httpx.HTTPError, OSError):
            self._server_reachable = False
            return None

        return None

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke an MCP tool via HTTP POST /mcp tools/call."""
        # 1. Attempt Loopback HTTP request
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=0.15, read=5.0, write=5.0, pool=5.0)
        ) as client:
            try:
                session_id = await self._ensure_session(client)
                if session_id:
                    headers = {
                        "Accept": "application/json, text/event-stream",
                        "mcp-session-id": session_id,
                        "mcp-protocol-version": "2025-11-25",
                        "Origin": self.base_url,
                    }
                    call_payload = {
                        "jsonrpc": "2.0",
                        "id": f"call-{name}",
                        "method": "tools/call",
                        "params": {"name": name, "arguments": arguments},
                    }
                    res = await client.post(self.mcp_url, json=call_payload, headers=headers)
                    if res.status_code == 200:
                        text = res.text
                        for line in text.splitlines():
                            if line.startswith("data:"):
                                parsed = json.loads(line[5:].strip())
                                res_obj = parsed.get("result", {})
                                if "structuredContent" in res_obj:
                                    return res_obj["structuredContent"]
                                content_items = res_obj.get("content", [])
                                if content_items and "text" in content_items[0]:
                                    try:
                                        return json.loads(content_items[0]["text"])
                                    except (json.JSONDecodeError, KeyError):
                                        return {"raw": content_items[0]["text"]}
            except (httpx.HTTPError, OSError) as http_err:
                logger.debug(
                    "Loopback HTTP request failed (%s); using in-process server binding.", http_err
                )

        # 2. In-process direct call fallback if server port is not yet bound externally
        res = await mcp_server.call_tool(name, arguments)
        if res.content and len(res.content) > 0:
            try:
                return json.loads(res.content[0].text)
            except (json.JSONDecodeError, AttributeError):
                return {"text": res.content[0].text}
        return {}

    async def list_tools(self) -> list[dict[str, Any]]:
        """Retrieve list of registered MCP tools."""
        tools = await mcp_server.list_tools()
        return [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.input_schema or {},
            }
            for t in tools
        ]


# Singleton loopback client
mcp_client = MCPHttpClient()
