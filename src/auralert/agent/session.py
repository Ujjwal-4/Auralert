"""Session state management with TTL for multi-turn conversation memory."""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Default session inactivity TTL: 30 minutes
SESSION_TTL_SECONDS = 1800


@dataclass
class SessionState:
    session_id: str
    region: str = "IN"
    case_id: str | None = None
    active_drill_id: str | None = None
    messages: list[dict[str, Any]] = field(default_factory=list)
    last_active: float = field(default_factory=time.time)


class SessionStore:
    """Thread-safe in-memory session cache with automatic expiration."""

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, SessionState] = {}

    def get_or_create(self, session_id: str, region: str = "IN") -> SessionState:
        now = time.time()
        # Clean expired sessions occasionally
        self._cleanup(now)

        if session_id in self._sessions:
            sess = self._sessions[session_id]
            sess.last_active = now
            sess.region = region
            return sess

        sess = SessionState(session_id=session_id, region=region, last_active=now)
        self._sessions[session_id] = sess
        return sess

    def update_case_id(self, session_id: str, case_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id].case_id = case_id
            self._sessions[session_id].last_active = time.time()

    def add_message(self, session_id: str, role: str, content: Any) -> None:
        if session_id in self._sessions:
            self._sessions[session_id].messages.append(
                {
                    "role": role,
                    "content": content,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
            self._sessions[session_id].last_active = time.time()

    def _cleanup(self, now: float) -> None:
        expired = [
            sid for sid, s in self._sessions.items() if (now - s.last_active) > self.ttl_seconds
        ]
        for sid in expired:
            del self._sessions[sid]


# Global session cache
session_store = SessionStore()
