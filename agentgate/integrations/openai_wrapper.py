"""
Drop-in OpenAI client wrapper with agentgate enforcement.

Every tool call the LLM wants to make is checked against the user's
agentgate profile before execution. Denied calls raise GateError.

Usage:
  from agentgate.integrations.openai_wrapper import GatedOpenAI, GateError
  from agentgate import AgentGate

  client = GatedOpenAI(
      gate=gate,
      token=session_token.token,
      openai_api_key="sk-..."
  )

  # Works exactly like openai.OpenAI() — just call chat.completions.create()
  # When a tool_call arrives in the response, call:
  result = client.execute_tool_call(tool_call, your_tool_fn)
  # This enforces before execution and raises GateError if denied.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional


class GateError(Exception):
    """Raised when agentgate denies a tool call."""
    def __init__(self, tool_name: str, reason: str):
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"agentgate denied '{tool_name}': {reason}")


class GatedOpenAI:
    """
    Thin wrapper around openai.OpenAI that enforces agentgate on tool calls.

    - Passes all __getattr__ calls through to the underlying OpenAI client
    - Adds execute_tool_call() which checks gate before dispatching
    """
    def __init__(
        self,
        gate,
        token: str,
        openai_api_key: Optional[str] = None,
        **openai_kwargs,
    ):
        try:
            import openai
        except ImportError:
            raise ImportError("openai package required: pip install openai")
        self._gate = gate
        self._token = token
        self._client = openai.OpenAI(api_key=openai_api_key, **openai_kwargs)

    def __getattr__(self, name: str):
        return getattr(self._client, name)

    def execute_tool_call(
        self,
        tool_call,  # openai.types.chat.ChatCompletionMessageToolCall
        tool_fn: Callable,
        token_count: int = 0,
    ) -> Any:
        """
        Check agentgate permission then execute the tool function.

        Args:
            tool_call: The tool_call object from OpenAI's response
            tool_fn: The actual Python function to call
            token_count: Optional LLM token count for quota tracking

        Returns:
            Whatever tool_fn returns

        Raises:
            GateError: if agentgate denies the call
        """
        from agentgate.models import EnforceRequest

        tool_name = tool_call.function.name
        result = self._gate.enforce(
            EnforceRequest(
                token=self._token,
                tool_name=tool_name,
                token_count=token_count,
            )
        )
        if not result.granted:
            raise GateError(tool_name=tool_name, reason=result.deny_reason or "denied")

        import json
        try:
            args = json.loads(tool_call.function.arguments)
        except Exception:
            args = {}

        return tool_fn(**args)

    def enforce(self, tool_name: str, token_count: int = 0) -> bool:
        """
        Explicit enforcement check without executing anything.
        Returns True if allowed, raises GateError if denied.
        """
        from agentgate.models import EnforceRequest
        result = self._gate.enforce(
            EnforceRequest(token=self._token, tool_name=tool_name, token_count=token_count)
        )
        if not result.granted:
            raise GateError(tool_name=tool_name, reason=result.deny_reason or "denied")
        return True


class GatedAnthropic:
    """
    Same pattern for Anthropic SDK.
    """
    def __init__(self, gate, token: str, anthropic_api_key: Optional[str] = None, **kwargs):
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")
        self._gate = gate
        self._token = token
        self._client = anthropic.Anthropic(api_key=anthropic_api_key, **kwargs)

    def __getattr__(self, name: str):
        return getattr(self._client, name)

    def execute_tool_use(
        self,
        tool_use_block,  # anthropic.types.ToolUseBlock
        tool_fn: Callable,
        token_count: int = 0,
    ) -> Any:
        """
        Check agentgate permission then execute for Anthropic tool_use blocks.
        """
        from agentgate.models import EnforceRequest

        tool_name = tool_use_block.name
        result = self._gate.enforce(
            EnforceRequest(token=self._token, tool_name=tool_name, token_count=token_count)
        )
        if not result.granted:
            raise GateError(tool_name=tool_name, reason=result.deny_reason or "denied")

        return tool_fn(**tool_use_block.input)
