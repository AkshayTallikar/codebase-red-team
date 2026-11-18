"""Claude through the official anthropic SDK, with structured JSON output."""

from __future__ import annotations

import json
from typing import Any

from redteam.llm.base import LLMError, LLMRefusal

# Agents make many small, structured calls per round, so a fast model is the default.
# Pass --model to the CLI to run the agents on a larger one.
DEFAULT_MODEL = "claude-haiku-5-5"
INSTALL_HINT = "pip install 'codebase-red-team[anthropic]'"


class AnthropicBackend:
    """Calls Claude and returns the JSON object it produces.

    Structured outputs guarantee schema-valid JSON. Security-flavoured prompts can
    occasionally trip a safety classifier; that surfaces as LLMRefusal, and the
    agents fall back to their offline strategies.
    """

    name = "anthropic"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        client: Any = None,
        max_tokens: int = 16000,
        effort: str = "medium",
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self.client = client if client is not None else _default_client()

    def complete_json(self, *, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Ask the model for a JSON object that matches `schema`."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            output_config={
                "effort": self.effort,
                "format": {"type": "json_schema", "schema": schema},
            },
        )
        if response.stop_reason == "refusal":
            details = response.stop_details
            category = getattr(details, "category", None) if details is not None else None
            raise LLMRefusal("the model refused the request", category=category)
        if response.stop_reason == "max_tokens":
            raise LLMError("response hit max_tokens")

        text_blocks = [block for block in response.content if block.type == "text"]
        if not text_blocks:
            raise LLMError("response has no text block")
        try:
            parsed = json.loads(text_blocks[0].text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"response is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise LLMError("response JSON is not an object")
        return parsed


def _default_client() -> Any:
    """Build the real SDK client, or explain how to install the optional dependency."""
    try:
        import anthropic
    except ImportError as exc:
        raise LLMError(
            f"the anthropic package is not installed; install it with {INSTALL_HINT}"
        ) from exc
    return anthropic.Anthropic()
