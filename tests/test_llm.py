"""Tests for the LLM backends. None of them need the anthropic package."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

from redteam.llm import (
    DEFAULT_MODEL,
    AnthropicBackend,
    FakeBackend,
    LLMError,
    LLMRefusal,
    make_backend,
)
from redteam.llm.anthropic_backend import INSTALL_HINT

SCHEMA: dict[str, Any] = {"type": "object", "properties": {"ok": {"type": "boolean"}}}


def _text(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _response(
    content: list[Any],
    stop_reason: str = "end_turn",
    stop_details: Any = None,
) -> SimpleNamespace:
    return SimpleNamespace(stop_reason=stop_reason, stop_details=stop_details, content=content)


def _stub_client(response: SimpleNamespace) -> SimpleNamespace:
    """A client whose beta.messages.create records its kwargs and returns `response`."""
    calls: list[dict[str, Any]] = []

    def create(**kwargs: Any) -> SimpleNamespace:
        calls.append(kwargs)
        return response

    client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
    client.calls = calls  # type: ignore[attr-defined]
    return client


def _block_anthropic_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `import anthropic` fail deterministically."""
    monkeypatch.setitem(sys.modules, "anthropic", None)


# FakeBackend


def test_fake_returns_queued_responses_in_order_and_records_calls() -> None:
    fake = FakeBackend([{"a": 1}, {"b": 2}])
    fake.queue({"c": 3})

    assert fake.name == "fake"
    assert fake.complete_json(system="s1", prompt="p1", schema=SCHEMA) == {"a": 1}
    assert fake.complete_json(system="s2", prompt="p2", schema=SCHEMA) == {"b": 2}
    assert fake.complete_json(system="s3", prompt="p3", schema=SCHEMA) == {"c": 3}
    assert fake.calls == [
        {"system": "s1", "prompt": "p1", "schema": SCHEMA},
        {"system": "s2", "prompt": "p2", "schema": SCHEMA},
        {"system": "s3", "prompt": "p3", "schema": SCHEMA},
    ]


def test_fake_raises_queued_exception() -> None:
    fake = FakeBackend([ValueError("boom")])
    with pytest.raises(ValueError, match="boom"):
        fake.complete_json(system="s", prompt="p", schema=SCHEMA)


def test_fake_raises_when_empty() -> None:
    fake = FakeBackend()
    with pytest.raises(LLMError, match="FakeBackend has no queued responses"):
        fake.complete_json(system="s", prompt="p", schema=SCHEMA)


def test_fake_returns_copies() -> None:
    original = {"nested": {"x": 1}}
    fake = FakeBackend([original, {"nested": {"x": 1}}])

    first = fake.complete_json(system="s", prompt="p", schema=SCHEMA)
    first["nested"]["x"] = 99
    second = fake.complete_json(system="s", prompt="p", schema=SCHEMA)

    assert second == {"nested": {"x": 1}}
    assert original == {"nested": {"x": 1}}


# AnthropicBackend with a stub client


def test_anthropic_returns_parsed_object_and_sends_expected_kwargs() -> None:
    client = _stub_client(_response([_text('{"ok": true}')]))
    backend = AnthropicBackend(client=client)

    result = backend.complete_json(system="sys", prompt="hello", schema=SCHEMA)

    assert result == {"ok": True}
    assert backend.name == "anthropic"
    (kwargs,) = client.calls
    assert kwargs["model"] == "claude-opus-5-5"
    assert kwargs["fallbacks"] == "default"
    assert kwargs["system"] == "sys"
    assert kwargs["messages"] == [{"role": "user", "content": "hello"}]
    assert kwargs["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert kwargs["output_config"]["effort"] == "medium"


def test_anthropic_skips_leading_non_text_block() -> None:
    thinking = SimpleNamespace(type="thinking", thinking="hmm")
    client = _stub_client(_response([thinking, _text('{"ok": true}')]))

    result = AnthropicBackend(client=client).complete_json(system="s", prompt="p", schema=SCHEMA)

    assert result == {"ok": True}


def test_anthropic_refusal_raises_with_category() -> None:
    details = SimpleNamespace(category="cyber")
    client = _stub_client(_response([], stop_reason="refusal", stop_details=details))

    with pytest.raises(LLMRefusal) as excinfo:
        AnthropicBackend(client=client).complete_json(system="s", prompt="p", schema=SCHEMA)

    assert excinfo.value.category == "cyber"


def test_anthropic_refusal_without_details_has_no_category() -> None:
    client = _stub_client(_response([], stop_reason="refusal"))

    with pytest.raises(LLMRefusal) as excinfo:
        AnthropicBackend(client=client).complete_json(system="s", prompt="p", schema=SCHEMA)

    assert excinfo.value.category is None


def test_anthropic_max_tokens_raises() -> None:
    client = _stub_client(_response([_text("{")], stop_reason="max_tokens"))

    with pytest.raises(LLMError, match="max_tokens"):
        AnthropicBackend(client=client).complete_json(system="s", prompt="p", schema=SCHEMA)


def test_anthropic_invalid_json_raises() -> None:
    client = _stub_client(_response([_text("not json")]))

    with pytest.raises(LLMError, match="not valid JSON"):
        AnthropicBackend(client=client).complete_json(system="s", prompt="p", schema=SCHEMA)


def test_anthropic_json_list_raises() -> None:
    client = _stub_client(_response([_text("[1, 2]")]))

    with pytest.raises(LLMError, match="not an object"):
        AnthropicBackend(client=client).complete_json(system="s", prompt="p", schema=SCHEMA)


def test_anthropic_without_text_block_raises() -> None:
    client = _stub_client(_response([SimpleNamespace(type="thinking", thinking="x")]))

    with pytest.raises(LLMError, match="no text block"):
        AnthropicBackend(client=client).complete_json(system="s", prompt="p", schema=SCHEMA)


# Construction without the SDK


def test_missing_anthropic_package_raises_with_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _block_anthropic_import(monkeypatch)

    with pytest.raises(LLMError) as excinfo:
        AnthropicBackend()

    assert INSTALL_HINT in str(excinfo.value)


# make_backend


def test_make_backend_offline_returns_none() -> None:
    assert make_backend("offline") is None


def test_make_backend_anthropic_builds_real_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_anthropic_import(monkeypatch)

    with pytest.raises(LLMError, match="anthropic package is not installed"):
        make_backend("anthropic", model="claude-haiku-5-5")


def test_make_backend_unknown_name_raises_value_error() -> None:
    with pytest.raises(ValueError, match="offline, anthropic"):
        make_backend("gpt")


def test_default_model_constant() -> None:
    assert DEFAULT_MODEL == "claude-opus-5-5"
