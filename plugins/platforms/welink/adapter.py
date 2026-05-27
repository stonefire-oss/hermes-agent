"""
WeLink platform adapter for Hermes Agent.

This adapter connects Hermes to WeLink via the ai-gateway WebSocket bridge.
It implements the message-bridge protocol specification for bidirectional
communication between Hermes (as the agent engine) and the ai-gateway.

Protocol layer classes are imported from protocol.py.

Reference: docs/协议规范.md (ai-gateway <-> message-bridge protocol)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None  # type: ignore[assignment]

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    SessionSource,
)

# Import protocol layer classes from protocol.py
from plugins.platforms.welink.protocol import (
    BridgeConfig,
    ConnectionState,
    ErrorCode,
    GatewayConnection,
    MAX_MESSAGE_LENGTH,
    ReconnectConfig,
    SessionMapping,
    SubagentMapping,
    DEFAULT_GATEWAY_URL,
    DEFAULT_CHANNEL,
)

logger = logging.getLogger(__name__)


# =============================================================================
# WeLink Adapter
# =============================================================================


# =============================================================================
# Security Configuration
# =============================================================================

class SecurityConfig:
    """Security configuration for access control.
    
    Attributes:
        allowed_users: List of allowed user accounts (sendUserAccount).
            - Empty list = no users allowed (deny all) - DEFAULT
            - Contains "ALL" = all users allowed (allow all)
        allowed_groups: List of allowed group IDs (groupId from imGroupId).
            - Empty list = no groups allowed (deny all)
            - Contains "ALL" = all groups allowed (allow all) - DEFAULT
    
    Note: User and group checks are case-insensitive.
    """
    
    def __init__(
        self,
        allowed_users: Optional[List[str]] = None,
        allowed_groups: Optional[List[str]] = None,
    ):
        # Normalize to lowercase for case-insensitive comparison
        self.allowed_users = [u.lower() for u in (allowed_users or [])]
        self.allowed_groups = [g.lower() for g in (allowed_groups or ["ALL"])]
    
    def is_user_allowed(self, send_user_account: str) -> bool:
        """Check if user is allowed to use the bot (case-insensitive)."""
        if "all" in self.allowed_users:
            return True
        return send_user_account.lower() in self.allowed_users
    
    def is_group_allowed(self, im_group_id: Optional[str]) -> bool:
        """Check if group is allowed (case-insensitive)."""
        if "all" in self.allowed_groups:
            return True
        if not im_group_id:
            return True
        group_id = im_group_id.split("#")[0].lower() if "#" in im_group_id else im_group_id.lower()
        return group_id in self.allowed_groups



class WeLinkAdapter(BasePlatformAdapter):
    """WeLink platform adapter connecting Hermes to ai-gateway.

    This adapter acts as a bridge between Hermes Agent and the WeLink
    messaging platform via the ai-gateway WebSocket protocol.

    Flow:
    1. User sends message in WeLink
    2. WeLink backend -> ai-gateway -> this adapter (via WebSocket)
    3. Adapter processes via Hermes Agent
    4. Agent response -> adapter -> ai-gateway -> WeLink backend -> user
    """

    MAX_MESSAGE_LENGTH = MAX_MESSAGE_LENGTH

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.WELINK)

        # Parse bridge configuration from PlatformConfig
        self._bridge_config = self._parse_bridge_config(config)

        # Parse security configuration (access control)
        self._access_control = self._parse_access_control(config)

        # Gateway connection
        self._gateway: Optional[GatewayConnection] = None

        # Session tracking
        self._sessions: Dict[str, Dict[str, Any]] = {}

        # Pending actions waiting for user response (clarify, permission, etc.)
        self._pending_actions: Dict[str, asyncio.Future] = {}
        
        # Store session info for each confirm_id (needed for slash_confirm resolution)
        self._confirm_session_keys: Dict[str, Dict[str, str]] = {}
        # Store welink_session_id for each session_key (for slash_confirm)
        self._session_welink_ids: Dict[str, str] = {}

        # Agent message handler (set by gateway runner)
        self._agent_handler: Optional[Callable] = None

        logger.info(
            "welink.adapter.init",
            extra={
                "gateway_url": self._bridge_config.gateway_url,
                "channel": self._bridge_config.channel,
            },
        )

    def _parse_bridge_config(self, config: PlatformConfig) -> BridgeConfig:
        """Parse BridgeConfig from PlatformConfig."""
        extra = config.extra or {}

        return BridgeConfig(
            enabled=config.enabled,
            debug=extra.get("debug", False),
            gateway_url=extra.get("gateway_url") or os.getenv("WELINK_GATEWAY_URL") or DEFAULT_GATEWAY_URL,
            channel=extra.get("channel") or os.getenv("WELINK_CHANNEL") or DEFAULT_CHANNEL,
            heartbeat_interval_ms=int(extra.get("heartbeat_interval_ms") or os.getenv("WELINK_HEARTBEAT_INTERVAL_MS") or 30000),
            sdk_timeout_ms=int(extra.get("sdk_timeout_ms") or os.getenv("WELINK_SDK_TIMEOUT_MS") or 10000),
            ak=extra.get("ak") or os.getenv("WELINK_AK") or "",
            sk=extra.get("sk") or os.getenv("WELINK_SK") or "",
            tool_type=extra.get("tool_type") or "welink",
            tool_version=extra.get("tool_version") or "1.0.0",
            reconnect=ReconnectConfig(
                base_ms=int(extra.get("reconnect_base_ms") or os.getenv("WELINK_RECONNECT_BASE_MS") or 1000),
                max_ms=int(extra.get("reconnect_max_ms") or 30000),
                exponential=True,
                jitter="full",
                max_elapsed_ms=int(extra.get("reconnect_max_elapsed_ms") or 600000),
            ),
        )

    def _parse_access_control(self, config: PlatformConfig) -> SecurityConfig:
        """Parse SecurityConfig from PlatformConfig.
        
        Configuration in config.yaml under platforms.welink.extra.security:
            security:
                allowed_users: ["y00453483"]  # or ["ALL"]
                allowed_groups: ["ALL"]
        """
        extra = config.extra or {}
        security = extra.get("security", {})
        
        # Parse allowed_users (default: empty = deny all)
        allowed_users_raw = security.get("allowed_users", [])
        if isinstance(allowed_users_raw, str):
            allowed_users = [allowed_users_raw]
        else:
            allowed_users = list(allowed_users_raw) if allowed_users_raw else []
        
        # Parse allowed_groups (default: ["ALL"] = allow all)
        allowed_groups_raw = security.get("allowed_groups", ["ALL"])
        if isinstance(allowed_groups_raw, str):
            allowed_groups = [allowed_groups_raw]
        else:
            allowed_groups = list(allowed_groups_raw) if allowed_groups_raw else ["ALL"]
        
        return SecurityConfig(
            allowed_users=allowed_users,
            allowed_groups=allowed_groups,
        )


    async def connect(self) -> bool:
        """Connect to ai-gateway WebSocket."""
        if not AIOHTTP_AVAILABLE:
            logger.error("welink.connect.aiohttp_missing")
            return False

        if not self._bridge_config.ak or not self._bridge_config.sk:
            logger.error("welink.connect.no_credentials")
            return False

        self._gateway = GatewayConnection(
            config=self._bridge_config,
            on_downstream_message=self._handle_downstream_message,
            on_state_change=self._handle_state_change,
        )

        success = await self._gateway.connect()
        if success:
            logger.info("welink.connect.success")
        else:
            logger.error("welink.connect.failed")

        return success

    async def disconnect(self) -> None:
        """Disconnect from ai-gateway."""
        if self._gateway:
            await self._gateway.disconnect()
            self._gateway = None

    def _handle_state_change(self, new_state: ConnectionState) -> None:
        """Handle gateway connection state changes."""
        logger.info("welink.state_change", extra={"state": new_state.value})

    def _handle_downstream_message(self, msg: Dict[str, Any]) -> None:
        """Handle incoming message from ai-gateway."""
        msg_type = msg.get("type")

        if msg_type == "invoke":
            self._handle_invoke(msg)
        elif msg_type == "status_query":
            self._handle_status_query(msg)
        else:
            logger.warning(
                "welink.downstream.unknown_type",
                extra={"type": msg_type},
            )

    def _handle_invoke(self, msg: Dict[str, Any]) -> None:
        """Handle invoke action from gateway."""
        if self._gateway is None or self._gateway.state != ConnectionState.READY:
            logger.warning("welink.invoke.not_ready")
            return

        action = msg.get("action")
        welink_session_id = msg.get("welinkSessionId")
        payload = msg.get("payload", {})



        # Route to action handler
        if action == "chat":
            asyncio.create_task(self._handle_chat_action(welink_session_id, payload))
        elif action == "create_session":
            asyncio.create_task(self._handle_create_session_action(welink_session_id, payload))
        elif action == "close_session":
            asyncio.create_task(self._handle_close_session_action(welink_session_id, payload))
        elif action == "permission_reply":
            asyncio.create_task(self._handle_permission_reply_action(welink_session_id, payload))
        elif action == "abort_session":
            asyncio.create_task(self._handle_abort_session_action(welink_session_id, payload))
        elif action == "question_reply":
            asyncio.create_task(self._handle_question_reply_action(welink_session_id, payload))
        else:
            logger.warning("welink.invoke.unknown_action", extra={"action": action})
            asyncio.create_task(
                self._gateway.send_tool_error(
                    error=f"Unknown action: {action}",
                    error_code=ErrorCode.UNSUPPORTED_ACTION,
                    welink_session_id=welink_session_id,
                )
            )

    async def _handle_chat_action(self, welink_session_id: Optional[str], payload: Dict[str, Any]) -> None:
        """Handle chat action - user message to process."""
        tool_session_id = payload.get("toolSessionId")
        send_user_account = payload.get("sendUserAccount", "")
        im_group_id = payload.get("imGroupId")  # Only present for group messages

        # Security check: verify user and group authorization
        is_group_msg = im_group_id is not None

        if is_group_msg:
            # Group message: check both group and user
            if not self._access_control.is_group_allowed(im_group_id):
                logger.warning(
                    "welink.security.group_denied: group_id=%s user=%s",
                    im_group_id, send_user_account
                )
                await self.send(
                    chat_id=tool_session_id,
                    content="未授权用户禁止使用",
                    metadata={"welink_session_id": welink_session_id},
                )
                return
            if not self._access_control.is_user_allowed(send_user_account):
                logger.warning(
                    "welink.security.user_denied_in_group: user=%s group=%s",
                    send_user_account, im_group_id
                )
                await self.send(
                    chat_id=tool_session_id,
                    content="未授权用户禁止使用",
                    metadata={"welink_session_id": welink_session_id},
                )
                return
        else:
            # DM message: check user only
            if not self._access_control.is_user_allowed(send_user_account):
                logger.warning(
                    "welink.security.user_denied: user=%s",
                    send_user_account
                )
                await self.send(
                    chat_id=tool_session_id,
                    content="未授权用户禁止使用",
                    metadata={"welink_session_id": welink_session_id},
                )
                return

        logger.info(
            "welink.security.allowed: user=%s group=%s",
            send_user_account, im_group_id or "DM"
        )

        text = payload.get("text", "")

        if not tool_session_id:
            await self._send_invoke_error(
                welink_session_id,
                ErrorCode.INVALID_PAYLOAD,
                "toolSessionId is required for chat",
            )
            return

        if not text:
            await self._send_invoke_error(
                welink_session_id,
                ErrorCode.INVALID_PAYLOAD,
                "text is required for chat",
                tool_session_id,
            )
            return

        # Create MessageEvent for Hermes agent
        source = SessionSource(
            platform=Platform.WELINK,
            chat_id=tool_session_id,
            user_id=welink_session_id or "unknown",
            thread_id=None,
        )
        
        # Store welink_session_id for this session (needed for slash_confirm)
        session_key = f"agent:main:welink:dm:{tool_session_id}"
        if welink_session_id:
            self._session_welink_ids[session_key] = welink_session_id

        event = MessageEvent(
            source=source,
            message_type=MessageType.TEXT,
            text=text,
            message_id=str(uuid.uuid4()),
        )

        # Dispatch to agent handler and send response
        if self._message_handler:
            try:
                response = await self._message_handler(event)
                logger.info("welink.chat.response: chat_id=%s response_len=%d", tool_session_id, len(response) if response else 0)
                
                if response:
                    await self.send(
                        chat_id=tool_session_id,
                        content=response,
                        metadata={"welink_session_id": welink_session_id},
                    )
                else:
                    logger.info("welink.chat.empty_response: chat_id=%s", tool_session_id)
                    await self._gateway.send_tool_done(
                        tool_session_id=tool_session_id,
                        welink_session_id=welink_session_id,
                    )
            except Exception as e:
                logger.error("welink.chat.agent_error", exc_info=True)
                await self._send_invoke_error(
                    welink_session_id,
                    ErrorCode.SDK_UNREACHABLE,
                    str(e),
                    tool_session_id,
                )
        else:
            logger.warning("welink.chat.no_handler")
            await self.send(
                chat_id=tool_session_id,
                content=f"Echo: {text}",
                metadata={"welink_session_id": welink_session_id},
            )

    async def _handle_create_session_action(self, welink_session_id: Optional[str], payload: Dict[str, Any]) -> None:
        """Handle create_session action."""
        tool_session_id = welink_session_id or str(uuid.uuid4())

        if self._gateway:
            await self._gateway.send_session_created(
                welink_session_id=welink_session_id or "",
                tool_session_id=tool_session_id,
                session_info={"title": "New Session"},
            )

    async def _handle_close_session_action(self, welink_session_id: Optional[str], payload: Dict[str, Any]) -> None:
        """Handle close_session action."""
        tool_session_id = payload.get("toolSessionId")
        if tool_session_id:
            self._sessions.pop(tool_session_id, None)

    async def _handle_permission_reply_action(self, welink_session_id: Optional[str], payload: Dict[str, Any]) -> None:
        """Handle permission_reply action - resolves pending slash_confirm.
        
        Gateway schema returns permissionId and response ('once', 'always', 'cancel').
        We need to call slash_confirm.resolve() to execute the actual command.
        """
        # Try multiple possible field names: permissionId (Gateway schema), id (sent), requestId (legacy)
        permission_id = payload.get("permissionId") or payload.get("id") or payload.get("requestId")
        response = payload.get("response", "once")  # 'once', 'always', or 'cancel'
        
        # Get session_key and welink_session_id from stored mapping (set during send_slash_confirm)
        session_info = self._confirm_session_keys.get(permission_id)
        session_key = session_info.get("session_key") if session_info else None
        stored_welink_session_id = session_info.get("welink_session_id") if session_info else None
        
        logger.info("welink.permission_reply.lookup: permission_id=%s session_key=%s welink_session_id=%s stored_keys=%s", 
                    permission_id, session_key, stored_welink_session_id, list(self._confirm_session_keys.keys())[:5])
        
        if permission_id and session_key:
            # Call slash_confirm.resolve to execute the command handler
            from tools import slash_confirm as slash_confirm_mod
            
            # Debug: check what's in slash_confirm._pending
            pending = slash_confirm_mod.get_pending(session_key)
            logger.info("welink.slash_confirm.pending_check: session_key=%s pending=%s", 
                        session_key, pending)
            
            result = await slash_confirm_mod.resolve(session_key, permission_id, response)
            logger.info("welink.permission_reply.resolved: permission_id=%s response=%s result=%s", 
                        permission_id, response, result[:50] if result else "None")
            
            # Send the result to the user
            if result:
                # Extract chat_id from session_key: "agent:main:welink:dm:ses_xxx"
                chat_id = session_key.split(":")[-1] if ":" in session_key else session_key
                await self.send(chat_id, result, metadata={"welink_session_id": stored_welink_session_id})
                logger.info("welink.permission_reply.sent: chat_id=%s result_len=%d welink_session_id=%s", 
                            chat_id, len(result), stored_welink_session_id)
            
            # Also clean up local pending_actions if present (legacy fallback)
            if permission_id in self._pending_actions:
                self._pending_actions.pop(permission_id, None)
            
            # Clean up session_key mapping
            self._confirm_session_keys.pop(permission_id, None)
        else:
            logger.warning("welink.permission_reply.missing_permissionId")

    async def _handle_abort_session_action(self, welink_session_id: Optional[str], payload: Dict[str, Any]) -> None:
        """Handle abort_session action."""
        tool_session_id = payload.get("toolSessionId")
        logger.info("welink.abort_session: tool_session_id=%s", tool_session_id)

    async def _handle_question_reply_action(self, welink_session_id: Optional[str], payload: Dict[str, Any]) -> None:
        """Handle question_reply action - resolves pending clarify.

        Gateway-schema defines question_reply payload as:
        { questionId: string, answer: string }

        questionId maps to the clarify_id we sent in send_clarify.
        This method bridges the WeLink question_reply to Hermes gateway's
        clarify primitive by calling resolve_gateway_clarify().
        """

        # Try multiple possible field names for question ID
        # WeLink uses 'toolCallId', OpenCode uses 'id', Legacy uses 'questionId'
        question_id = payload.get("toolCallId") or payload.get("questionId") or payload.get("id") or payload.get("callID")
        answer = payload.get("answer", "")

        if not question_id:
            logger.warning("welink.question_reply.missing_questionId")
            return

        # Resolve the gateway clarify primitive (unblocks agent thread)
        from tools.clarify_gateway import resolve_gateway_clarify
        resolved = resolve_gateway_clarify(question_id, answer)

        if resolved:
            logger.info("welink.question_reply.resolved: question_id=%s answer=%s", question_id, answer)
        else:
            logger.warning("welink.question_reply.not_found: question_id=%s (no pending clarify)", question_id)

        # Also clean up local pending_actions if present (legacy fallback)
        if question_id in self._pending_actions:
            self._pending_actions.pop(question_id, None)

    def _handle_status_query(self, msg: Dict[str, Any]) -> None:
        """Handle status_query from gateway."""
        if self._gateway:
            asyncio.create_task(self._gateway.send_status_response(True))

    async def _send_invoke_error(
        self,
        welink_session_id: Optional[str],
        error_code: ErrorCode,
        error_msg: str,
        tool_session_id: Optional[str] = None,
    ) -> None:
        """Send tool_error for invoke failure."""
        if self._gateway:
            await self._gateway.send_tool_error(
                error=error_msg,
                error_code=error_code,
                welink_session_id=welink_session_id,
                tool_session_id=tool_session_id,
            )

    # =========================================================================
    # BasePlatformAdapter Methods
    # =========================================================================

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SendResult:
        """Send message to WeLink via gateway skill event.

        Uses Skill Provider Event protocol (protocol: "cloud") with:
        - step.start: marks message start
        - text.delta: streaming text content
        - text.done: marks text complete
        - step.done: marks message done
        - tool_done: final signal
        """
        if self._gateway is None or self._gateway.state != ConnectionState.READY:
            logger.warning("welink.send.not_connected")
            return SendResult(success=False, error="Gateway not connected")

        welink_session_id = metadata.get("welink_session_id") if metadata else None

        # Truncate if needed
        text = content
        if len(text) > self.MAX_MESSAGE_LENGTH:
            text = self.truncate_message(text, self.MAX_MESSAGE_LENGTH)

        # Generate IDs for Skill Provider Event format
        message_id = str(uuid.uuid4())
        part_id = f"prt_{message_id[:8]}"

        # Send step.start
        await self._gateway.send_skill_event(
            tool_session_id=chat_id,
            event_type="step.start",
            properties={"messageId": message_id},
        )

        # Send text.delta
        await self._gateway.send_skill_event(
            tool_session_id=chat_id,
            event_type="text.delta",
            properties={
                "messageId": message_id,
                "partId": part_id,
                "content": text,
            },
        )

        # Send text.done
        await self._gateway.send_skill_event(
            tool_session_id=chat_id,
            event_type="text.done",
            properties={
                "messageId": message_id,
                "partId": part_id,
                "content": text,
            },
        )

        # Send step.done
        await self._gateway.send_skill_event(
            tool_session_id=chat_id,
            event_type="step.done",
            properties={"messageId": message_id},
        )

        # Send tool_done
        await self._gateway.send_tool_done(
            tool_session_id=chat_id,
            welink_session_id=welink_session_id,
        )

        logger.info("welink.send.success: message_id=%s", message_id)
        return SendResult(success=True, message_id=message_id)

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Send typing indicator via session.status event."""
        if self._gateway and self._gateway.state == ConnectionState.READY:
            await self._gateway.send_tool_event(
                tool_session_id=chat_id,
                event_type="session.status",
                properties={
                    "sessionID": chat_id,
                    "status": {"type": "busy"},
                },
            )

    async def send_image(self, chat_id: str, image_url: str, caption: str = "", **kwargs) -> SendResult:
        """Send image to WeLink."""
        text = f"[Image: {image_url}]"
        if caption:
            text += f"\n{caption}"
        return await self.send(chat_id, text, **kwargs)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        """Get chat info for session."""
        session = self._sessions.get(chat_id)
        if session:
            return {
                "name": session.get("title", "WeLink Chat"),
                "type": "private",
                "chat_id": chat_id,
            }
        return {
            "name": "WeLink Chat",
            "type": "private",
            "chat_id": chat_id,
        }

    # =========================================================================
    # Clarify / Permission / Slash Confirm UI Methods
    # =========================================================================

    async def send_clarify(
        self,
        chat_id: str,
        question: str,
        choices: Optional[list],
        clarify_id: str,
        session_key: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a clarify prompt to WeLink via OpenCode provider event protocol.

        Uses `send_tool_event` with event_type="question.asked" to render WeLink's
        selection UI. The user's response comes back via `question_reply` action,
        which is handled by `_handle_question_reply_action`.

        Args:
            chat_id: Session ID to send to
            question: The question text to display
            choices: List of choices for multiple-choice mode, or None/empty for open-ended
            clarify_id: Unique ID for this clarify request (used to match response)
            session_key: Session key for gateway routing
            metadata: Additional metadata

        Returns:
            SendResult indicating success/failure
        """
        if self._gateway is None or self._gateway.state != ConnectionState.READY:
            logger.warning("welink.clarify.not_connected")
            return SendResult(success=False, error="Gateway not connected")

        logger.info("welink.clarify.send: clarify_id=%s choices=%s", clarify_id, choices)

        # Generate UUIDs for OpenCode protocol required fields
        message_id = str(uuid.uuid4())
        call_id = f"call_{message_id[:8]}"

        # Build question properties using OpenCode provider event format
        # Reference: /opt/welink-wecode-legacy-skill-plugin/packages/gateway-schema/src/contract/schemas/tool-event/opencode-provider-event/question.ts
        # OpenCode format: sessionID, id (questionId), questions[], tool{messageID, callID}
        question_item = {
            "question": question,
        }

        # Add choices if provided (multiple-choice mode)
        if choices:
            question_item["options"] = [{"label": choice} for choice in choices]
            # Add "Other" option for free-text input
            question_item["options"].append({"label": "Other (type your answer)"})

        properties = {
            "sessionID": chat_id,
            "id": clarify_id,  # OpenCode format: question id
            "questionId": clarify_id,  # WeLink expected field for reply correlation
            "questions": [question_item],
            "tool": {
                "messageID": message_id,
                "callID": clarify_id,  # Use clarify_id as callID for correlation
            },
        }

        # Send question.asked event via OpenCode provider protocol
        success = await self._gateway.send_tool_event(
            tool_session_id=chat_id,
            event_type="question.asked",
            properties=properties,
        )

        if success:
            logger.info("welink.clarify.sent: clarify_id=%s format=opencode", clarify_id)
            # Track pending clarify for response matching
            self._pending_actions[clarify_id] = asyncio.get_running_loop().create_future()
            return SendResult(success=True, message_id=clarify_id)
        else:
            logger.error("welink.clarify.send_failed")
            return SendResult(success=False, error="Failed to send question.asked event")

    async def permission_callback(
        self,
        chat_id: str,
        permission_id: str,
        command: str,
        reason: str,
        session_key: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Request permission for a dangerous command via skill event protocol.

        Uses `send_skill_event` with event_type="permission.ask" to render WeLink's
        approval UI. The user's response comes back via `permission_reply` action.

        Args:
            chat_id: Session ID to send to
            permission_id: Unique ID for this permission request
            command: The dangerous command that needs approval
            reason: Why this command is considered dangerous
            session_key: Session key for gateway routing
            metadata: Additional metadata

        Returns:
            Tuple of (approved: bool, choice: Optional[str])
            - approved=True, choice="once" or "always" if approved
            - approved=False, choice="cancel" if rejected
            - approved=False, choice=None if timeout/error
        """
        if self._gateway is None or self._gateway.state != ConnectionState.READY:
            logger.warning("welink.permission.not_connected")
            return (False, None)

        logger.info("welink.permission.ask: permission_id=%s command=%s", permission_id, command)

        # Build permission properties for skill event
        properties = {
            "id": permission_id,
            "command": command,
            "reason": reason,
            "sessionKey": session_key,
            "options": [
                {"id": "once", "text": "Approve Once"},
                {"id": "always", "text": "Always Approve"},
                {"id": "cancel", "text": "Cancel"},
            ],
        }

        # Send permission.ask event
        success = await self._gateway.send_skill_event(
            tool_session_id=chat_id,
            event_type="permission.ask",
            properties=properties,
        )

        if not success:
            logger.error("welink.permission.send_failed")
            return (False, None)

        # Track pending permission request
        future = asyncio.get_running_loop().create_future()
        self._pending_actions[permission_id] = future

        # Wait for response with timeout
        try:
            response = await asyncio.wait_for(future, timeout=60.0)
            choice = response.get("choice", "cancel")
            logger.info("welink.permission.reply: permission_id=%s choice=%s", permission_id, choice)

            if choice == "once":
                return (True, "once")
            elif choice == "always":
                return (True, "always")
            else:
                return (False, "cancel")
        except asyncio.TimeoutError:
            logger.warning("welink.permission.timeout: permission_id=%s", permission_id)
            self._pending_actions.pop(permission_id, None)
            return (False, None)
        except Exception as e:
            logger.error("welink.permission.error: %s", e)
            self._pending_actions.pop(permission_id, None)
            return (False, None)

    async def send_slash_confirm(
        self,
        chat_id: str,
        title: str,
        message: str,
        session_key: str,
        confirm_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a three-option slash-command confirmation prompt.

        Used by gateway's slash-confirm primitive for commands with expensive
        side effects (e.g., /reload-mcp).

        Uses `send_skill_event` with event_type="permission.ask" to render
        WeLink's approval UI with three buttons.

        Args:
            chat_id: Session ID to send to
            title: Title for the confirmation dialog
            message: Message explaining what will happen
            session_key: Session key for gateway routing
            confirm_id: Unique ID for this confirmation
            metadata: Additional metadata

        Returns:
            SendResult indicating success/failure
        """
        if self._gateway is None or self._gateway.state != ConnectionState.READY:
            logger.warning("welink.slash_confirm.not_connected")
            return SendResult(success=False, error="Gateway not connected")

        # Store session_key and welink_session_id for later resolution
        # Get welink_session_id from metadata or from stored mapping
        welink_session_id = metadata.get("welink_session_id") if metadata else None
        if not welink_session_id:
            welink_session_id = self._session_welink_ids.get(session_key)
        self._confirm_session_keys[confirm_id] = {
            "session_key": session_key,
            "welink_session_id": welink_session_id,
        }
        logger.info("welink.slash_confirm.send: confirm_id=%s title=%s session_key=%s welink_session_id=%s", 
                    confirm_id, title, session_key, welink_session_id)

        # Build confirmation properties using permission.ask event type
        # Use permissionId for Gateway schema compatibility, keep id for fallback
        properties = {
            "permissionId": confirm_id,  # Gateway schema expected field
            "id": confirm_id,            # Fallback for compatibility
            "title": title,
            "text": message,
            "sessionKey": session_key,
            "options": [
                {"id": "once", "text": "Approve Once"},
                {"id": "always", "text": "Always Approve"},
                {"id": "cancel", "text": "Cancel"},
            ],
        }

        # Send permission.ask event
        success = await self._gateway.send_skill_event(
            tool_session_id=chat_id,
            event_type="permission.ask",
            properties=properties,
        )

        if success:
            logger.info("welink.slash_confirm.sent: confirm_id=%s", confirm_id)
            self._pending_actions[confirm_id] = asyncio.get_running_loop().create_future()
            return SendResult(success=True, message_id=confirm_id)
        else:
            logger.error("welink.slash_confirm.send_failed")
            return SendResult(success=False, error="Failed to send confirmation event")

    def set_agent_handler(self, handler: Callable) -> None:
        """Set the agent message handler."""
        self._agent_handler = handler


# =============================================================================
# Plugin Entry Point
# =============================================================================

def check_requirements() -> bool:
    """Check if WeLink adapter dependencies are available."""
    return AIOHTTP_AVAILABLE


def validate_config(config: PlatformConfig) -> bool:
    """Validate WeLink configuration. Returns True if valid."""
    extra = config.extra or {}

    ak = extra.get("ak") or os.getenv("WELINK_AK")
    sk = extra.get("sk") or os.getenv("WELINK_SK")

    return bool(ak and sk)


def is_connected(config: PlatformConfig) -> bool:
    """Check if WeLink is connected."""
    return bool(config.enabled and (config.extra.get("ak") or os.getenv("WELINK_AK")))


def _env_enablement() -> Optional[Dict[str, Any]]:
    """Seed PlatformConfig.extra from environment variables."""
    ak = os.getenv("WELINK_AK")
    sk = os.getenv("WELINK_SK")

    if not ak or not sk:
        return None

    extra = {
        "ak": ak,
        "sk": sk,
        "gateway_url": os.getenv("WELINK_GATEWAY_URL", DEFAULT_GATEWAY_URL),
        "channel": os.getenv("WELINK_CHANNEL", DEFAULT_CHANNEL),
    }

    home_channel = os.getenv("WELINK_HOME_CHANNEL")
    if home_channel:
        extra["home_channel"] = home_channel

    return extra


def _apply_yaml_config(yaml_cfg: Dict[str, Any], platform_cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Apply YAML config to PlatformConfig.extra."""
    if not isinstance(platform_cfg, dict):
        return None

    extra = platform_cfg.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}

    seeded = {}

    for key in ["ak", "sk", "gateway_url", "channel", "tool_type", "tool_version",
                "heartbeat_interval_ms", "reconnect_base_ms", "reconnect_max_ms",
                "sdk_timeout_ms", "debug"]:
        if key in extra:
            seeded[key] = extra[key]
        elif key in platform_cfg:
            seeded[key] = platform_cfg[key]

    for key, value in extra.items():
        if key not in seeded:
            seeded[key] = value

    return seeded if seeded else None


async def _standalone_send(config: PlatformConfig, chat_id: str, message: str) -> Dict[str, Any]:
    """Standalone send for cron delivery outside gateway process."""
    return {
        "success": False,
        "error": "WeLink standalone send requires running gateway",
    }


def register(ctx):
    """Plugin entry point: called by the Hermes plugin system."""
    ctx.register_platform(
        name="welink",
        label="WeLink (华为企业通信)",
        adapter_factory=lambda cfg: WeLinkAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=["WELINK_AK", "WELINK_SK"],
        install_hint="pip install aiohttp",
        env_enablement_fn=_env_enablement,
        apply_yaml_config_fn=_apply_yaml_config,
        cron_deliver_env_var="WELINK_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send,
        allowed_users_env="WELINK_ALLOWED_USERS",
        allow_all_env="WELINK_ALLOW_ALL_USERS",
        max_message_length=MAX_MESSAGE_LENGTH,
        emoji="💬",
        pii_safe=False,
        allow_update_command=True,
        platform_hint=(
            "You are chatting via WeLink (华为企业通信). WeLink supports basic "
            "text messages. Keep responses concise and professional. "
            f"Messages are limited to ~{MAX_MESSAGE_LENGTH} characters."
        ),
    )