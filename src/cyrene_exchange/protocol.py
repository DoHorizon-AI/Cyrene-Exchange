###############################################################################
# 📄 File: src/cyrene_exchange/protocol.py
# Module: Cyrene Exchange
# Role: Exchange Product implementation.
#
# This header documents ownership; normalized requests retain structured tools.
#
# 模块：Cyrene Exchange
# 职责：Exchange Product 实现。
# 本头部说明归属；标准化请求保留结构化工具元数据。
###############################################################################
"""OpenAI-compatible request normalization for Exchange Product semantics.

The transport-facing protocol keeps structured tool metadata intact so a
provider adapter can decide whether its canonical capability contract carries
it.  Exchange must not silently discard fields that change an agent turn.

中文:针对 Exchange Product 语义的 OpenAI 兼容请求规范化。

中文:面向传输的协议会保留结构化工具元数据,以便提供方适配器判断其规范能力契约是否支持。Exchange 不得静默丢弃会改变 Agent 轮次的字段。
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class ProtocolError(ValueError):
    """An incoming request cannot be normalized.

    中文:传入请求无法规范化。"""


def _require_non_empty_string(value: Any, field_name: str) -> str:
    """Validate and return a required non-empty JSON string.

    中文:验证并返回必需的非空 JSON 字符串。"""

    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(f"{field_name} must be a non-empty string")
    return value.strip()


def _normalize_tool(raw_tool: Any, index: int) -> dict[str, Any]:
    """Validate one OpenAI function tool while preserving its JSON schema.

    中文:验证一个 OpenAI function 工具,同时保留其 JSON schema。"""

    if not isinstance(raw_tool, Mapping):
        raise ProtocolError(f"tools[{index}] must be an object")
    if raw_tool.get("type") != "function":
        raise ProtocolError(f"tools[{index}].type must be 'function'")
    raw_function = raw_tool.get("function")
    if not isinstance(raw_function, Mapping):
        raise ProtocolError(f"tools[{index}].function must be an object")

    function: dict[str, Any] = dict(raw_function)
    function["name"] = _require_non_empty_string(raw_function.get("name"), f"tools[{index}].function.name")
    for field in ("description",):
        value = raw_function.get(field)
        if value is not None:
            if not isinstance(value, str):
                raise ProtocolError(f"tools[{index}].function.{field} must be a string")
            function[field] = value
    parameters = raw_function.get("parameters")
    if parameters is not None:
        if not isinstance(parameters, Mapping):
            raise ProtocolError(f"tools[{index}].function.parameters must be an object")
        # The JSON Schema is provider-owned.  Preserve it byte-for-byte at
        # the object level instead of attempting to interpret schema keywords.
        # 中文:JSON Schema 由提供方所有;应在对象层面逐字节保留,不要尝试解释其中的 schema 关键字。
        function["parameters"] = dict(parameters)
    strict = raw_function.get("strict")
    if strict is not None:
        if not isinstance(strict, bool):
            raise ProtocolError(f"tools[{index}].function.strict must be a boolean")
        function["strict"] = strict

    normalized: dict[str, Any] = dict(raw_tool)
    normalized["type"] = "function"
    normalized["function"] = function
    return normalized


def _normalize_tool_choice(value: Any) -> str | dict[str, Any]:
    """Validate an OpenAI tool choice without reducing named choices to text.

    中文:验证 OpenAI 工具选择,不将具名选择简化为文本。"""

    if isinstance(value, str):
        if value not in {"none", "auto", "required"}:
            raise ProtocolError("tool_choice must be 'none', 'auto', or 'required'")
        return value
    if not isinstance(value, Mapping):
        raise ProtocolError("tool_choice must be a string or an object")
    if value.get("type") != "function":
        raise ProtocolError("tool_choice.type must be 'function'")
    function = value.get("function")
    if not isinstance(function, Mapping):
        raise ProtocolError("tool_choice.function must be an object")
    name = _require_non_empty_string(function.get("name"), "tool_choice.function.name")
    return {"type": "function", "function": {"name": name}}


def _normalize_stream_options(value: Any) -> dict[str, Any]:
    """Validate the deliberately small streaming option surface.

    中文:验证刻意保持精简的流式选项接口。"""

    if not isinstance(value, Mapping):
        raise ProtocolError("stream_options must be an object")
    unknown = set(value) - {"include_usage"}
    if unknown:
        names = ", ".join(sorted(str(item) for item in unknown))
        raise ProtocolError(f"stream_options contains unsupported fields: {names}")
    include_usage = value.get("include_usage", False)
    if not isinstance(include_usage, bool):
        raise ProtocolError("stream_options.include_usage must be a boolean")
    return {"include_usage": include_usage}


def _normalize_tool_calls(raw_tool_calls: Any, message_index: int) -> list[dict[str, Any]]:
    """Validate assistant tool calls and retain argument fragments exactly.

    中文:验证助手工具调用,并原样保留参数片段。"""

    if not isinstance(raw_tool_calls, Sequence) or isinstance(raw_tool_calls, (str, bytes)):
        raise ProtocolError(f"messages[{message_index}].tool_calls must be an array")
    if not raw_tool_calls:
        raise ProtocolError(f"messages[{message_index}].tool_calls must not be empty")

    calls: list[dict[str, Any]] = []
    for call_index, raw_call in enumerate(raw_tool_calls):
        field_prefix = f"messages[{message_index}].tool_calls[{call_index}]"
        if not isinstance(raw_call, Mapping):
            raise ProtocolError(f"{field_prefix} must be an object")
        call_id = _require_non_empty_string(raw_call.get("id"), f"{field_prefix}.id")
        call_type = raw_call.get("type", "function")
        if not isinstance(call_type, str) or call_type != "function":
            raise ProtocolError(f"{field_prefix}.type must be 'function'")
        raw_function = raw_call.get("function")
        if not isinstance(raw_function, Mapping):
            raise ProtocolError(f"{field_prefix}.function must be an object")
        name = _require_non_empty_string(raw_function.get("name"), f"{field_prefix}.function.name")
        arguments = raw_function.get("arguments", "")
        if not isinstance(arguments, str):
            raise ProtocolError(f"{field_prefix}.function.arguments must be a string")
        function = dict(raw_function)
        function["name"] = name
        function["arguments"] = arguments
        call = dict(raw_call)
        call["id"] = call_id
        call["type"] = "function"
        call["function"] = function
        calls.append(call)
    return calls


def _normalize_message(raw_message: Mapping[str, Any], index: int) -> dict[str, Any]:
    """Validate one text chat message, including tool result history.

    中文:验证一条文本聊天消息,包括工具结果历史。"""

    role = raw_message.get("role")
    if role not in {"system", "user", "assistant", "tool"}:
        raise ProtocolError(f"messages[{index}].role is invalid")

    has_tool_calls = "tool_calls" in raw_message
    if has_tool_calls and role != "assistant":
        raise ProtocolError(f"messages[{index}].tool_calls is only valid for assistant messages")
    content = raw_message.get("content")
    if "content" not in raw_message and not has_tool_calls:
        raise ProtocolError(f"messages[{index}].content is required")
    if content is not None and not isinstance(content, str):
        raise ProtocolError(f"messages[{index}].content must be text or null")
    if content is None and role != "assistant":
        raise ProtocolError(f"messages[{index}].content must be text for {role} messages")

    message: dict[str, Any] = dict(raw_message)
    message["role"] = role
    message["content"] = content
    for field in ("name", "tool_call_id"):
        value = message.get(field)
        if value is not None and not isinstance(value, str):
            raise ProtocolError(f"messages[{index}].{field} must be a string when provided")
    if role == "tool":
        _require_non_empty_string(message.get("tool_call_id"), f"messages[{index}].tool_call_id")
    if has_tool_calls:
        message["tool_calls"] = _normalize_tool_calls(raw_message["tool_calls"], index)
    return message


@dataclass(frozen=True)
class NormalizedInferenceRequest:
    """The provider-neutral request owned by Exchange Product Core.

    中文:由 Exchange Product Core 所有的提供方无关请求。"""

    model: str
    messages: tuple[dict[str, Any], ...]
    stream: bool
    temperature: float | None = None
    max_tokens: int | None = None
    tools: tuple[dict[str, Any], ...] = ()
    tool_choice: str | dict[str, Any] | None = None
    parallel_tool_calls: bool | None = None
    stream_options: dict[str, Any] | None = None

    # ════════════════════════════════════════════════════════════════════════
    # 🔧 FUNCTION: NormalizedInferenceRequest.from_openai
    #
    #   Validates an OpenAI-compatible payload and produces the provider-neutral
    #   request consumed by Exchange Product Core.
    #
    #   校验 OpenAI 兼容载荷，并生成 Exchange Product Core 消费的 provider-neutral 请求。
    # ════════════════════════════════════════════════════════════════════════
    @classmethod
    def from_openai(cls, payload: Mapping[str, Any]) -> "NormalizedInferenceRequest":
        if not isinstance(payload, Mapping):
            raise ProtocolError("request body must be a JSON object")

        model = payload.get("model")
        if not isinstance(model, str) or not model.strip():
            raise ProtocolError("model must be a non-empty string")

        raw_messages = payload.get("messages")
        if not isinstance(raw_messages, Sequence) or isinstance(raw_messages, (str, bytes)):
            raise ProtocolError("messages must be a non-empty array")
        if not raw_messages:
            raise ProtocolError("messages must be a non-empty array")

        messages: list[dict[str, Any]] = []
        for index, raw_message in enumerate(raw_messages):
            if not isinstance(raw_message, Mapping):
                raise ProtocolError(f"messages[{index}] must be an object")
            messages.append(_normalize_message(raw_message, index))

        stream = payload.get("stream", False)
        if not isinstance(stream, bool):
            raise ProtocolError("stream must be a boolean")

        temperature = payload.get("temperature")
        if temperature is not None:
            if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
                raise ProtocolError("temperature must be a number")
            if not 0 <= float(temperature) <= 2:
                raise ProtocolError("temperature must be between 0 and 2")
            temperature = float(temperature)

        max_tokens = payload.get("max_tokens")
        if max_tokens is not None:
            if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens <= 0:
                raise ProtocolError("max_tokens must be a positive integer")

        raw_tools = payload.get("tools", ())
        if not isinstance(raw_tools, Sequence) or isinstance(raw_tools, (str, bytes)):
            raise ProtocolError("tools must be an array")
        tools = tuple(_normalize_tool(raw_tool, index) for index, raw_tool in enumerate(raw_tools))

        raw_tool_choice = payload.get("tool_choice")
        tool_choice = None if raw_tool_choice is None else _normalize_tool_choice(raw_tool_choice)

        parallel_tool_calls = payload.get("parallel_tool_calls")
        if parallel_tool_calls is not None and not isinstance(parallel_tool_calls, bool):
            raise ProtocolError("parallel_tool_calls must be a boolean")

        raw_stream_options = payload.get("stream_options")
        stream_options = None if raw_stream_options is None else _normalize_stream_options(raw_stream_options)
        if stream_options is not None and not stream:
            raise ProtocolError("stream_options is only valid when stream is true")
        return cls(
            model=model.strip(),
            messages=tuple(messages),
            stream=stream,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            tool_choice=tool_choice,
            parallel_tool_calls=parallel_tool_calls,
            stream_options=stream_options,
        )

    def to_provider_dict(self) -> dict[str, Any]:
        """Return only normalized request data for a capability implementation.

        中文:只向能力实现返回规范化后的请求数据。"""

        result: dict[str, Any] = {
            "model": self.model,
            "messages": [dict(message) for message in self.messages],
            "stream": self.stream,
        }
        if self.temperature is not None:
            result["temperature"] = self.temperature
        if self.max_tokens is not None:
            result["max_tokens"] = self.max_tokens
        if self.tools:
            result["tools"] = [dict(tool) for tool in self.tools]
        if self.tool_choice is not None:
            result["tool_choice"] = dict(self.tool_choice) if isinstance(self.tool_choice, dict) else self.tool_choice
        if self.parallel_tool_calls is not None:
            result["parallel_tool_calls"] = self.parallel_tool_calls
        if self.stream_options is not None:
            result["stream_options"] = dict(self.stream_options)
        return result
