"""Main Starlette/FastAPI application for ScamShield.

Mounts:
- Streamable HTTP MCP server at /mcp (MCP spec 2025-11-25)
- Health check endpoint at /healthz
- Simulated Alexa+ agent endpoint at /api/agent (Bedrock / OpenRouter / fallback brain)
- Web simulator static assets from /web

Includes production security features:
- DNS-rebinding protection and Origin validation
- Request body size limitation (max 2MB)
- Sliding-window rate limiting on /mcp and /api/agent
- Privacy-preserving structured access logging (no user payload text stored)
"""

import json
import logging
import os
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.streamable_http import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.staticfiles import StaticFiles

from scamshield.agent.brain import agent_brain
from scamshield.cases import (
    check_repeat_offender_service,
    export_threat_intel_service,
    list_safe_words,
    set_safe_word_service,
    verify_safe_word_service,
)
from scamshield.detection import DEMO_SCENARIOS, call_guard_registry
from scamshield.server import mcp_server

# Setup structured logger
logger = logging.getLogger("scamshield.access")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

MAX_BODY_SIZE_BYTES = 2 * 1024 * 1024  # 2MB


class OriginValidationMiddleware(BaseHTTPMiddleware):
    """Enforces DNS-rebinding protection and Origin header verification on /mcp."""

    def __init__(self, app: Any, allowed_origins: list[str]) -> None:
        super().__init__(app)
        self.allowed_origins = {o.strip().rstrip("/") for o in allowed_origins if o.strip()}

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        if request.url.path.startswith("/mcp"):
            origin = request.headers.get("origin")
            if origin:
                normalized = origin.rstrip("/")
                if normalized not in self.allowed_origins and "*" not in self.allowed_origins:
                    return JSONResponse(
                        {"error": "Forbidden: invalid Origin header for MCP endpoint"},
                        status_code=403,
                    )
        return await call_next(request)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects request payloads exceeding size limits to prevent DoS."""

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_BODY_SIZE_BYTES:
                    return JSONResponse(
                        {"error": "Payload too large. Maximum request size is 2MB."},
                        status_code=413,
                    )
            except ValueError:
                pass
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window in-memory rate limiter per IP address for /mcp and /api/agent."""

    def __init__(self, app: Any, max_requests: int = 120, window_secs: int = 60) -> None:
        super().__init__(app)
        self.max_requests = max_requests
        self.window_secs = window_secs
        self.requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        if request.url.path.startswith(("/mcp", "/api/agent")):
            client_ip = request.client.host if request.client else "127.0.0.1"
            now = time.time()
            cutoff = now - self.window_secs
            timestamps = [t for t in self.requests[client_ip] if t > cutoff]
            if len(timestamps) >= self.max_requests:
                return JSONResponse(
                    {
                        "error": "Rate limit exceeded. Please wait a moment before sending more requests.",
                        "retry_after_seconds": int(self.window_secs - (now - timestamps[0])),
                    },
                    status_code=429,
                )
            timestamps.append(now)
            self.requests[client_ip] = timestamps
        return await call_next(request)


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Privacy-preserving structured access logger omitting sensitive user message text."""

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        start_time = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        client_ip = request.client.host if request.client else "unknown"
        # Log metadata only, never raw body content
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": duration_ms,
            "client_ip": client_ip,
        }
        logger.info("ACCESS: %s", log_entry)
        return response


def create_app() -> Any:
    """Build and configure the main ScamShield application."""
    allowed_origins_env = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000",
    )
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

    port = os.getenv("PORT", "8000")
    allowed_hosts_env = os.getenv(
        "ALLOWED_HOSTS",
        f"127.0.0.1,localhost,testserver,127.0.0.1:{port},localhost:{port},testserver:{port}",
    )
    allowed_hosts = [h.strip() for h in allowed_hosts_env.split(",") if h.strip()]

    # Security settings per MCP 2025-11-25 spec
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )

    # Create the official MCP Streamable HTTP Starlette application
    app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=transport_security,
    )

    # Middlewares in execution order
    app.add_middleware(StructuredLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, max_requests=120, window_secs=60)
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(OriginValidationMiddleware, allowed_origins=allowed_origins)

    # Health check endpoint
    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app.add_route("/healthz", healthz, methods=["GET"])
    app.add_route("/health", healthz, methods=["GET"])

    # Honest runtime report of which agent brains are configured (no secrets exposed)
    async def api_status(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "brains": agent_brain.status()})

    app.add_route("/api/status", api_status, methods=["GET"])

    # Real /api/agent endpoint powered by Bedrock Converse brain with fallback
    async def agent_endpoint(request: Request) -> JSONResponse:
        try:
            body = await request.json()
            session_id = body.get("session_id", "default-session")
            message = body.get("message", "").strip()
            region = body.get("region", "IN")

            if not message:
                return JSONResponse(
                    {
                        "reply": "Please tell or describe what you received.",
                        "tool_calls": [],
                        "brain": "fallback",
                    },
                    status_code=400,
                )

            agent_resp = await agent_brain.process_turn(
                session_id=session_id,
                message=message,
                region=region,
            )
            return JSONResponse(agent_resp.model_dump())
        except (ValueError, KeyError, RuntimeError, json.JSONDecodeError) as e:
            logger.error("Error in /api/agent: %s", e)
            return JSONResponse(
                {
                    "reply": "I encountered an issue processing that. Please try again.",
                    "tool_calls": [],
                    "brain": "fallback",
                },
                status_code=500,
            )

    app.add_route("/api/agent", agent_endpoint, methods=["POST"])

    # Live Call Guard Endpoints
    async def call_guard_presets(request: Request) -> JSONResponse:
        return JSONResponse(DEMO_SCENARIOS)

    async def call_guard_start(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            body = {}
        region = body.get("region", "IN")
        language = body.get("language", "en")
        sess = call_guard_registry.start_session(region=region, language=language)
        return JSONResponse(
            {
                "call_id": sess.call_id,
                "region": sess.region,
                "language": sess.language,
                "cumulative_risk_score": 0,
                "status": "listening",
            }
        )

    async def call_guard_chunk(request: Request) -> JSONResponse:
        body = await request.json()
        call_id = body.get("call_id", "default-call")
        chunk_text = body.get("text", "")
        speaker = body.get("speaker", "caller")
        language = body.get("language", "en")
        res = call_guard_registry.process_chunk(
            call_id=call_id, chunk_text=chunk_text, speaker=speaker, language=language
        )
        return JSONResponse(res)

    async def call_guard_end(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            body = {}
        call_id = body.get("call_id", "")
        create_case = body.get("create_case", True)
        res = call_guard_registry.end_session(call_id=call_id, create_case_file=create_case)
        return JSONResponse(res)

    app.add_route("/api/call-guard/presets", call_guard_presets, methods=["GET"])
    app.add_route("/api/call-guard/start", call_guard_start, methods=["POST"])
    app.add_route("/api/call-guard/chunk", call_guard_chunk, methods=["POST"])
    app.add_route("/api/call-guard/end", call_guard_end, methods=["POST"])

    # Family Safe-Word Endpoints
    async def safe_word_set(request: Request) -> JSONResponse:
        body = await request.json()
        res = set_safe_word_service(
            contact_name=body.get("contact_name", "Family"),
            safe_word=body.get("safe_word", ""),
            relationship=body.get("relationship", "Family"),
            hint=body.get("hint"),
        )
        return JSONResponse(res)

    async def safe_word_verify(request: Request) -> JSONResponse:
        body = await request.json()
        res = verify_safe_word_service(
            contact_name=body.get("contact_name", ""),
            candidate_word=body.get("candidate_word", ""),
        )
        return JSONResponse(res)

    async def safe_word_list(request: Request) -> JSONResponse:
        return JSONResponse({"contacts": list_safe_words()})

    app.add_route("/api/safe-word/set", safe_word_set, methods=["POST"])
    app.add_route("/api/safe-word/verify", safe_word_verify, methods=["POST"])
    app.add_route("/api/safe-word/list", safe_word_list, methods=["GET"])

    # Threat Intelligence & Repeat Offender Endpoints
    async def indicators_check(request: Request) -> JSONResponse:
        indicator = request.query_params.get("indicator", "")
        itype = request.query_params.get("type", "auto")
        res = check_repeat_offender_service(indicator=indicator, indicator_type=itype)
        return JSONResponse(res)

    async def indicators_export(request: Request) -> JSONResponse:
        res = export_threat_intel_service(format="json")
        return JSONResponse(
            res,
            headers={"Content-Disposition": 'attachment; filename="scamshield-threat-intel.json"'},
        )

    app.add_route("/api/indicators/check", indicators_check, methods=["GET"])
    app.add_route("/api/indicators/export", indicators_export, methods=["GET"])

    # Serve static simulator web client
    web_dir = Path(__file__).resolve().parent.parent.parent / "web"
    if web_dir.exists():
        index_file = web_dir / "index.html"

        no_cache_headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        }

        async def serve_index(request: Request) -> Any:
            if index_file.exists():
                return FileResponse(str(index_file), headers=no_cache_headers)
            return JSONResponse({"status": "ScamShield web simulator"})

        css_file = web_dir / "styles.css"
        js_file = web_dir / "app.js"

        async def serve_css(request: Request) -> Any:
            return FileResponse(str(css_file), media_type="text/css", headers=no_cache_headers)

        async def serve_js(request: Request) -> Any:
            return FileResponse(
                str(js_file),
                media_type="application/javascript",
                headers=no_cache_headers,
            )

        app.add_route("/", serve_index, methods=["GET"])
        app.add_route("/styles.css", serve_css, methods=["GET"])
        app.add_route("/app.js", serve_js, methods=["GET"])
        app.mount("/web", StaticFiles(directory=str(web_dir), html=True), name="web")

    return app


# Root application instance for ASGI servers (uvicorn scamshield.app:app)
app = create_app()
