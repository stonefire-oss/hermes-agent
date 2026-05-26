"""
WeLink platform adapter for Hermes Agent.

This adapter connects Hermes to WeLink via the ai-gateway WebSocket bridge.
It implements the message-bridge protocol specification for bidirectional
communication between Hermes (as the agent engine) and the ai-gateway.

Protocol Overview:
- WebSocket connection to ai-gateway (Java/Spring WebFlux)
- AK/SK authentication via WebSocket subprotocol header
- State machine: DISCONNECTED -> CONNECTING -> CONNECTED -> READY
- Upstream events: tool_event, tool_done, tool_error, session_created, status_response
- Downstream actions: chat, create_session, close_session, permission_reply,
                       abort_session, question_reply, status_query

Reference: docs/协议规范.md (ai-gateway <-> message-bridge protocol)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import platform
import random
import socket
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

DEFAULT_GATEWAY_URL = "ws://localhost:8081/ws/agent"
DEFAULT_CHANNEL = "welink"
DEFAULT_HEARTBEAT_INTERVAL_MS = 30000
DEFAULT_RECONNECT_BASE_MS = 1000
DEFAULT_RECONNECT_MAX_MS = 30000
DEFAULT_RECONNECT_MAX_ELAPSED_MS = 600000  # 10 minutes
DEFAULT_SDK_TIMEOUT_MS = 10000
MAX_MESSAGE_LENGTH = 4000  # WeLink typical limit

# WebSocket close codes that indicate rejection (no reconnect)
GATEWAY_REJECTION_CLOSE_CODES = {4403, 4408, 4409}

# Known tool types for register message
KNOWN_TOOL_TYPES = {"openx", "uniassistant", "codeagent", "welink"}

# Supported upstream event types (whitelist)
SUPPORTED_UPSTREAM_EVENT_TYPES = {
    "message.updated",
    "message.part.updated",
    "message.part.delta",
    "message.part.removed",
    "session.created",
    "session.status",
    "session.idle",
    "session.updated",
    "session.error",
    "permission.updated",
    "permission.asked",
    "permission.replied",
    "question.asked",
}

# Skill Provider Event types (protocol: "cloud")
SKILL_PROVIDER_EVENT_TYPES = {
    "text.delta",
    "text.done",
    "thinking.delta",
    "thinking.done",
    "tool.update",
    "question",
    "permission.ask",
    "permission.reply",
    "step.start",
    "step.done",
    "session.status",
    "session.error",
}

# Downstream invoke actions
INVOKE_ACTIONS = {
    "chat",
    "create_session",
    "close_session",
    "permission_reply",
    "abort_session",
    "question_reply",
}

# Error codes
ERROR_CODES = {
    "GATEWAY_UNREACHABLE": "Plugin is disconnected or connecting",
    "AGENT_NOT_READY": "Plugin is connected but not ready",
    "SDK_TIMEOUT": "Engine SDK call timed out",
    "SDK_UNREACHABLE": "Engine SDK is unreachable",
    "INVALID_PAYLOAD": "Invalid payload schema",
    "UNSUPPORTED_ACTION": "Action not registered",
}


# =============================================================================
# Enums
# =============================================================================

class ConnectionState(Enum):
    """Connection state machine states."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    READY = "ready"


class ErrorCode(Enum):
    """Error codes for tool_error messages."""
    GATEWAY_UNREACHABLE = "GATEWAY_UNREACHABLE"
    AGENT_NOT_READY = "AGENT_NOT_READY"
    SDK_TIMEOUT = "SDK_TIMEOUT"
    SDK_UNREACHABLE = "SDK_UNREACHABLE"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ReconnectConfig:
    """Reconnection policy configuration."""
    base_ms: int = DEFAULT_RECONNECT_BASE_MS
    max_ms: int = DEFAULT_RECONNECT_MAX_MS
    exponential: bool = True
    jitter: str = "full"  # "none" or "full"
    max_elapsed_ms: int = DEFAULT_RECONNECT_MAX_ELAPSED_MS


@dataclass
class BridgeConfig:
    """Complete bridge configuration."""
    enabled: bool = True
    debug: bool = False
    gateway_url: str = DEFAULT_GATEWAY_URL
    channel: str = DEFAULT_CHANNEL
    heartbeat_interval_ms: int = DEFAULT_HEARTBEAT_INTERVAL_MS
    reconnect: ReconnectConfig = field(default_factory=ReconnectConfig)
    sdk_timeout_ms: int = DEFAULT_SDK_TIMEOUT_MS
    ak: str = ""
    sk: str = ""
    tool_type: str = "welink"
    tool_version: str = "1.0.0"


@dataclass
class SessionMapping:
    """Mapping between welinkSessionId and toolSessionId."""
    welink_session_id: str
    tool_session_id: str
    created_at: float = field(default_factory=time.time)
    title: Optional[str] = None


@dataclass
class SubagentMapping:
    """Mapping between parent and child sessions for subagent tracking."""
    parent_session_id: str
    child_session_id: str
    agent_name: str
    created_at: float = field(default_factory=time.time)


# =============================================================================
# Authentication
# =============================================================================

class AkSkAuth:
    """AK/SK authentication for WebSocket handshake."""

    def __init__(self, ak: str, sk: str):
        self.ak = ak
        self.sk = sk

    def generate_auth_payload(self) -> Dict[str, str]:
        """Generate authentication payload for WebSocket subprotocol header.

        Returns a dict with:
        - ak: Access Key (plaintext)
        - ts: Unix timestamp in seconds (string)
        - nonce: Random UUID
        - sign: HMAC-SHA256(SK, AK+ts+nonce) in Base64
        """
        ts = str(int(time.time()))  # Unix seconds, not milliseconds!
        nonce = str(uuid.uuid4())

        # HMAC-SHA256 with standard Base64 (contains +/=)
        message = f"{self.ak}{ts}{nonce}"
        signature = hmac.new(
            self.sk.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        sign = base64.b64encode(signature).decode("utf-8")

        return {
            "ak": self.ak,
            "ts": ts,
            "nonce": nonce,
            "sign": sign,
        }

    def build_auth_subprotocol(self) -> str:
        """Build the WebSocket subprotocol header value.

        Format: auth.<base64url(JSON.stringify(payload))>

        Note: The outer envelope uses Base64URL (no +/=), but the inner
        sign field uses standard Base64.
        """
        payload = self.generate_auth_payload()
        payload_json = json.dumps(payload, separators=(",", ":"))

        # Base64URL encoding: replace + with -, / with _, remove trailing =
        b64 = base64.b64encode(payload_json.encode("utf-8")).decode("utf-8")
        b64url = b64.replace("+", "-").replace("/", "_").rstrip("=")

        return f"auth.{b64url}"


# =============================================================================
# Reconnect Policy
# =============================================================================

class ReconnectPolicy:
    """Exponential backoff reconnect policy with jitter."""

    def __init__(self, config: ReconnectConfig):
        self.config = config
        self._attempt = 0
        self._window_start: Optional[float] = None
        self._manually_disconnected = False

    def reset(self) -> None:
        """Reset attempt counter and window start."""
        self._attempt = 0
        self._window_start = None

    def mark_manual_disconnect(self) -> None:
        """Mark that disconnect was intentional (no reconnect)."""
        self._manually_disconnected = True

    def should_reconnect(self) -> bool:
        """Check if we should attempt reconnect."""
        if self._manually_disconnected:
            return False
        return not self.is_exhausted()

    def is_exhausted(self) -> bool:
        """Check if reconnect budget is exhausted."""
        if self._window_start is None:
            return False
        elapsed_ms = (time.time() - self._window_start) * 1000
        return elapsed_ms >= self.config.max_elapsed_ms

    def get_next_delay_ms(self) -> Optional[int]:
        """Get delay for next reconnect attempt.

        Returns None if exhausted or manually disconnected.
        """
        if self._manually_disconnected or self.is_exhausted():
            return None

        if self._window_start is None:
            self._window_start = time.time()

        self._attempt += 1

        # Exponential backoff: base * 2^(attempt-1), capped at max
        if self.config.exponential:
            delay = min(
                self.config.base_ms * (2 ** (self._attempt - 1)),
                self.config.max_ms,
            )
        else:
            delay = self.config.base_ms

        # Apply jitter
        if self.config.jitter == "full":
            delay = random.randint(0, delay)

        # Check if this delay would exceed the window
        elapsed_ms = (time.time() - self._window_start) * 1000
        if elapsed_ms + delay >= self.config.max_elapsed_ms:
            logger.warning(
                "gateway.reconnect.exhausted",
                extra={"elapsed_ms": elapsed_ms, "attempt": self._attempt},
            )
            return None

        return delay


# =============================================================================
# Gateway Connection
# =============================================================================

class GatewayConnection:
    """WebSocket connection to ai-gateway following the message-bridge protocol."""

    def __init__(
        self,
        config: BridgeConfig,
        on_downstream_message: Callable[[Dict[str, Any]], None],
        on_state_change: Callable[[ConnectionState], None],
    ):
        self.config = config
        self._on_downstream_message = on_downstream_message
        self._on_state_change = on_state_change

        self._state = ConnectionState.DISCONNECTED
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None

        self._auth = AkSkAuth(config.ak, config.sk)
        self._reconnect_policy = ReconnectPolicy(config.reconnect)

        # Session mappings
        self._session_mappings: Dict[str, SessionMapping] = {}
        self._subagent_mappings: Dict[str, SubagentMapping] = {}

        # Message tracking for debugging
        self._last_message_summary: Optional[Dict[str, Any]] = None
        self._recent_outbound_summaries: List[Dict[str, Any]] = []

        # Device metadata for register
        self._device_name = socket.gethostname()
        self._mac_address = self._get_mac_address()
        self._os = platform.system().lower()

    def _get_mac_address(self) -> str:
        """Get MAC address for register message."""
        try:
            # Try to get a real MAC address
            for name, addrs in socket.ifaddr(socket.AF_LINK):
                for addr in addrs:
                    if addr.addr:
                        return addr.addr
        except Exception:
            pass
        # Fallback placeholder
        return "00:00:00:00:00:00"

    @property
    def state(self) -> ConnectionState:
        return self._state

    def _set_state(self, new_state: ConnectionState) -> None:
        if self._state != new_state:
            old_state = self._state
            self._state = new_state
            logger.debug(
                "gateway.state_change",
                extra={"old": old_state.value, "new": new_state.value},
            )
            self._on_state_change(new_state)

    def state_to_error_code(self) -> Optional[ErrorCode]:
        """Map current state to error code for invoke rejection."""
        if self._state == ConnectionState.DISCONNECTED:
            return ErrorCode.GATEWAY_UNREACHABLE
        if self._state == ConnectionState.CONNECTING:
            return ErrorCode.GATEWAY_UNREACHABLE
        if self._state == ConnectionState.CONNECTED:
            return ErrorCode.AGENT_NOT_READY
        return None

    async def connect(self) -> bool:
        """Establish WebSocket connection to gateway.

        Returns True if connection succeeded and we reached READY state.
        """
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available - cannot connect to gateway")
            return False

        self._set_state(ConnectionState.CONNECTING)
        self._reconnect_policy.reset()

        try:
            # Create session
            self._session = aiohttp.ClientSession()

            # Build auth subprotocol header
            auth_subprotocol = self._auth.build_auth_subprotocol()

            logger.debug(
                "gateway.connecting",
                extra={"url": self.config.gateway_url, "auth": "present"},
            )

            # Connect with auth subprotocol
            self._ws = await self._session.ws_connect(
                self.config.gateway_url,
                protocols=[auth_subprotocol],
                heartbeat=None,  # We handle heartbeat ourselves
            )

            self._set_state(ConnectionState.CONNECTED)

            # Send register message immediately
            await self._send_register()

            # Start receive loop
            self._receive_task = asyncio.create_task(self._receive_loop())

            # Wait for register_ok (with timeout)
            try:
                await asyncio.wait_for(
                    self._wait_for_ready(),
                    timeout=10.0,
                )
            except asyncio.TimeoutError:
                logger.warning("gateway.register.timeout")
                await self.disconnect()
                return False

            return self._state == ConnectionState.READY

        except Exception as e:
            logger.error("gateway.connect.failed", exc_info=True)
            self._set_state(ConnectionState.DISCONNECTED)
            if self._session:
                await self._session.close()
                self._session = None
            return False

    async def _wait_for_ready(self) -> None:
        """Wait until we reach READY state (register_ok received)."""
        while self._state != ConnectionState.READY:
            await asyncio.sleep(0.1)

    async def _send_register(self) -> None:
        """Send register message to gateway."""
        register_msg = {
            "type": "register",
            "deviceName": self._device_name,
            "macAddress": self._mac_address,
            "os": self._os,
            "toolType": self.config.tool_type,
            "toolVersion": self.config.tool_version,
        }
        await self._send_raw(register_msg)
        logger.debug("gateway.register.sent")

    async def _send_raw(self, msg: Dict[str, Any]) -> None:
        """Send raw JSON message via WebSocket."""
        if self._ws is None or self._ws.closed:
            logger.warning("gateway.send.closed")
            return

        payload = json.dumps(msg, separators=(",", ":"))
        payload_bytes = len(payload.encode("utf-8"))

        # Log all payloads for debugging - print full message with event type
        event_type = msg.get("event", {}).get("type", "") if msg.get("type") == "tool_event" else ""
        logger.info("gateway.send_raw.full", extra={"payload": payload, "type": msg.get("type"), "event_type": event_type})
        if msg.get("type") == "tool_event":
            print(f"[GATEWAY SEND tool_event] type={event_type} payload={payload}")
        else:
            print(f"[GATEWAY SEND {msg.get('type')}] {payload[:500]}")

        # Log large payloads
        if payload_bytes >= 1_000_000:  # 1 MB
            logger.warning(
                "gateway.send.large_payload",
                extra={"bytes": payload_bytes, "type": msg.get("type")},
            )

        await self._ws.send_str(payload)

        # Track for debugging
        self._last_message_summary = {
            "direction": "sent",
            "type": msg.get("type"),
            "payload_bytes": payload_bytes,
        }

        # Track business messages (not control)
        if msg.get("type") not in ("register", "heartbeat"):
            self._recent_outbound_summaries.append({
                "type": msg.get("type"),
                "toolSessionId": msg.get("toolSessionId"),
                "payload_bytes": payload_bytes,
            })
            # Keep only last 3
            if len(self._recent_outbound_summaries) > 3:
                self._recent_outbound_summaries.pop(0)

    async def _receive_loop(self) -> None:
        """Receive messages from gateway."""
        if self._ws is None:
            return

        try:
            async for msg in self._ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._handle_message(msg.data)
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    logger.debug("gateway.ws.closed")
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error("gateway.ws.error", extra={"error": self._ws.exception()})
                    break
        except asyncio.CancelledError:
            logger.debug("gateway.receive.cancelled")
        except Exception as e:
            logger.error("gateway.receive.error", exc_info=True)

        # Connection closed - handle reconnect
        await self._handle_close()

    async def _handle_message(self, data: str) -> None:
        """Handle incoming message from gateway."""
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            logger.warning("gateway.message.invalid_json")
            return

        msg_type = msg.get("type")

        # Track for debugging
        self._last_message_summary = {
            "direction": "received",
            "type": msg_type,
            "payload_bytes": len(data.encode("utf-8")),
        }

        # Handle control messages
        if msg_type == "register_ok":
            await self._handle_register_ok()
        elif msg_type == "register_rejected":
            await self._handle_register_rejected(msg)
        else:
            # Business messages - pass to handler
            self._on_downstream_message(msg)

    async def _handle_register_ok(self) -> None:
        """Handle register_ok from gateway."""
        logger.info("gateway.register.ok")
        self._set_state(ConnectionState.READY)
        self._reconnect_policy.reset()

        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def _handle_register_rejected(self, msg: Dict[str, Any]) -> None:
        """Handle register_rejected from gateway."""
        reason = msg.get("reason", "unknown")
        logger.warning("gateway.register.rejected", extra={"reason": reason})
        self._reconnect_policy.mark_manual_disconnect()
        await self.disconnect()

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat messages."""
        interval_s = self.config.heartbeat_interval_ms / 1000

        try:
            while self._state == ConnectionState.READY and self._ws and not self._ws.closed:
                heartbeat = {
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }
                # Send directly, bypass state check (heartbeat is allowed in CONNECTED)
                if self._ws and not self._ws.closed:
                    await self._ws.send_str(json.dumps(heartbeat, separators=(",", ":")))
                    logger.info("gateway.heartbeat.sent")
                await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            logger.debug("gateway.heartbeat.cancelled")
        except Exception as e:
            logger.error("gateway.heartbeat.error", exc_info=True)

    async def _handle_close(self) -> None:
        """Handle WebSocket close and potentially reconnect."""
        if self._state == ConnectionState.DISCONNECTED:
            return

        close_code = self._ws.close_code if self._ws else None

        logger.warning(
            "gateway.close",
            extra={
                "code": close_code,
                "state": self._state.value,
                "last_message": self._last_message_summary,
                "recent_outbound": self._recent_outbound_summaries,
            },
        )

        # Check if we should reconnect
        if close_code in GATEWAY_REJECTION_CLOSE_CODES:
            logger.warning("gateway.close.rejected", extra={"code": close_code})
            self._reconnect_policy.mark_manual_disconnect()

        self._set_state(ConnectionState.DISCONNECTED)

        # Cancel tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

        # Attempt reconnect if appropriate
        if self._reconnect_policy.should_reconnect():
            self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        """Attempt reconnection with exponential backoff."""
        while self._reconnect_policy.should_reconnect():
            delay_ms = self._reconnect_policy.get_next_delay_ms()
            if delay_ms is None:
                logger.warning("gateway.reconnect.exhausted")
                break

            delay_s = delay_ms / 1000
            logger.debug(
                "gateway.reconnect.attempt",
                extra={"delay_ms": delay_ms, "attempt": self._reconnect_policy._attempt},
            )

            await asyncio.sleep(delay_s)

            if await self.connect():
                logger.info("gateway.reconnect.success")
                return

        # Exhausted - stay disconnected
        self._set_state(ConnectionState.DISCONNECTED)

    async def disconnect(self) -> None:
        """Disconnect from gateway."""
        self._reconnect_policy.mark_manual_disconnect()

        # Cancel tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
            self._receive_task = None

        if self._reconnect_task:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None

        # Close WebSocket
        if self._ws and not self._ws.closed:
            await self._ws.close()
            self._ws = None

        # Close session
        if self._session:
            await self._session.close()
            self._session = None

        self._set_state(ConnectionState.DISCONNECTED)

    async def send_tool_event(
        self,
        tool_session_id: str,
        event_type: str,
        properties: Dict[str, Any],
        subagent_session_id: Optional[str] = None,
        subagent_name: Optional[str] = None,
    ) -> bool:
        """Send upstream tool_event message.

        Args:
            tool_session_id: Parent session ID
            event_type: Event type from SUPPORTED_UPSTREAM_EVENT_TYPES
            properties: Event properties
            subagent_session_id: Child session ID if from subagent
            subagent_name: Agent name if from subagent

        Returns True if sent successfully.
        """
        if self._state != ConnectionState.READY:
            logger.warning(
                "gateway.send.not_ready",
                extra={"state": self._state.value},
            )
            return False

        if event_type not in SUPPORTED_UPSTREAM_EVENT_TYPES:
            logger.warning(
                "event.extraction_failed",
                extra={"code": "unsupported_event", "type": event_type},
            )
            return False

        msg = {
            "type": "tool_event",
            "toolSessionId": tool_session_id,
            "event": {
                "type": event_type,
                "properties": properties,
            },
        }

        # Add subagent fields if present (must be paired)
        if subagent_session_id and subagent_name:
            msg["subagentSessionId"] = subagent_session_id
            msg["subagentName"] = subagent_name

        await self._send_raw(msg)
        return True

    async def send_skill_event(
        self,
        tool_session_id: str,
        event_type: str,
        properties: Dict[str, Any],
    ) -> bool:
        """Send upstream tool_event with Skill Provider Event protocol (protocol: "cloud").

        Args:
            tool_session_id: Session ID
            event_type: Event type from SKILL_PROVIDER_EVENT_TYPES
            properties: Event properties (messageId, partId, content, etc.)

        Returns True if sent successfully.
        """
        if self._state != ConnectionState.READY:
            logger.warning(
                "gateway.send.not_ready",
                extra={"state": self._state.value},
            )
            return False

        if event_type not in SKILL_PROVIDER_EVENT_TYPES:
            logger.warning(
                "event.extraction_failed",
                extra={"code": "unsupported_skill_event", "type": event_type},
            )
            return False

        # Skill Provider Event format: add protocol: "cloud"
        msg = {
            "type": "tool_event",
            "toolSessionId": tool_session_id,
            "event": {
                "protocol": "cloud",
                "type": event_type,
                "properties": properties,
            },
        }

        await self._send_raw(msg)
        return True

    async def send_tool_done(
        self,
        tool_session_id: str,
        welink_session_id: Optional[str] = None,
        usage: Optional[Dict[str, int]] = None,
    ) -> bool:
        """Send tool_done to mark session idle."""
        if self._state != ConnectionState.READY:
            return False

        msg = {
            "type": "tool_done",
            "toolSessionId": tool_session_id,
        }
        if welink_session_id:
            msg["welinkSessionId"] = welink_session_id
        if usage:
            msg["usage"] = usage

        await self._send_raw(msg)
        return True

    async def send_tool_error(
        self,
        error: str,
        error_code: Optional[ErrorCode] = None,
        welink_session_id: Optional[str] = None,
        tool_session_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """Send tool_error message."""
        if self._state != ConnectionState.READY:
            return False

        msg = {
            "type": "tool_error",
            "error": error,
        }
        if error_code:
            msg["errorCode"] = error_code.value
        if welink_session_id:
            msg["welinkSessionId"] = welink_session_id
        if tool_session_id:
            msg["toolSessionId"] = tool_session_id
        if reason:
            msg["reason"] = reason

        await self._send_raw(msg)
        return True

    async def send_session_created(
        self,
        welink_session_id: str,
        tool_session_id: str,
        session_info: Dict[str, Any],
    ) -> bool:
        """Send session_created response for create_session action."""
        if self._state != ConnectionState.READY:
            return False

        msg = {
            "type": "session_created",
            "welinkSessionId": welink_session_id,
            "toolSessionId": tool_session_id,
            "session": {
                "sessionId": tool_session_id,
                "session": session_info,
            },
        }

        await self._send_raw(msg)
        return True

    async def send_status_response(self, online: bool) -> bool:
        """Send status_response for status_query."""
        # status_response is allowed even in non-READY states
        msg = {
            "type": "status_response",
            "opencodeOnline": online,
        }

        if self._ws and not self._ws.closed:
            await self._ws.send_str(json.dumps(msg, separators=(",", ":")))
            logger.info("gateway.status_response.sent", extra={"online": online})
            return True
        return False

    def record_session_mapping(
        self,
        welink_session_id: str,
        tool_session_id: str,
        title: Optional[str] = None,
    ) -> None:
        """Record mapping between welink and tool session IDs."""
        self._session_mappings[welink_session_id] = SessionMapping(
            welink_session_id=welink_session_id,
            tool_session_id=tool_session_id,
            title=title,
        )

    def get_tool_session_id(self, welink_session_id: str) -> Optional[str]:
        """Get tool_session_id for a welink_session_id."""
        mapping = self._session_mappings.get(welink_session_id)
        return mapping.tool_session_id if mapping else None

    def get_welink_session_id(self, tool_session_id: str) -> Optional[str]:
        """Get welink_session_id for a tool_session_id (reverse lookup)."""
        for mapping in self._session_mappings.values():
            if mapping.tool_session_id == tool_session_id:
                return mapping.welink_session_id
        return None

    def record_subagent_mapping(
        self,
        parent_session_id: str,
        child_session_id: str,
        agent_name: str,
    ) -> None:
        """Record subagent session mapping."""
        self._subagent_mappings[child_session_id] = SubagentMapping(
            parent_session_id=parent_session_id,
            child_session_id=child_session_id,
            agent_name=agent_name,
        )

    def get_parent_session_id(self, child_session_id: str) -> Optional[str]:
        """Get parent session ID for a child session."""
        mapping = self._subagent_mappings.get(child_session_id)
        return mapping.parent_session_id if mapping else None


# =============================================================================
# WeLink Adapter
# =============================================================================

