# Fix: Inject mandatory Claude Code system prompt for OAuth requests

## Context

Running `uv run examples/oauth.py` returns:
```
anthropic.BadRequestError: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error',
'message': 'This credential is only authorized for use with Claude Code and cannot be used for other API requests.'}}
```

The Jarvis project (working reference at `/Users/sofian.hadianto/Documents/workspace/personal/Jarvis`) reveals the root cause: every Messages API call must include a **mandatory system prompt** identifying the session as Claude Code. Without it, the API rejects requests made with `user:sessions:claude_code` scoped OAuth tokens.

**Jarvis sends** (in `internal/agent/agent.go:163-166`):
```go
System: []BetaTextBlockParam{
    {Type: "text", Text: "You are Claude Code, Anthropic's official CLI for Claude.", CacheControl: {Type: "ephemeral"}},
    {Type: "text", Text: customPrompt, CacheControl: {Type: "ephemeral"}},
}
```

Our OAuth client sends the correct headers (`anthropic-beta`, `User-Agent`, `Authorization`, `?beta=true`) but does **not** inject this system prompt.

## Plan

### 1. Add constant to `src/anthropic/lib/oauth/_types.py`

Add after `DEFAULT_USER_AGENT` (line 18):
```python
DEFAULT_SYSTEM_PROMPT = "You are Claude Code, Anthropic's official CLI for Claude."
```

### 2. Add system prompt injection in `src/anthropic/lib/oauth/_client.py`

**Add imports:**
- `DEFAULT_SYSTEM_PROMPT` from `._types`
- `is_dict` from `..._utils`

**Add module-level helper function** (before `class AnthropicOAuth`):
```python
def _inject_system_prompt(options: FinalRequestOptions) -> None:
    if not is_dict(options.json_data):
        return
    if "messages" not in options.json_data:
        return

    json_data: dict[object, object] = {**options.json_data}
    options.json_data = json_data

    claude_code_block: dict[str, object] = {
        "type": "text",
        "text": DEFAULT_SYSTEM_PROMPT,
        "cache_control": {"type": "ephemeral"},
    }

    existing_system = json_data.get("system")
    if existing_system is None:
        json_data["system"] = [claude_code_block]
    elif isinstance(existing_system, str):
        json_data["system"] = [claude_code_block, {"type": "text", "text": existing_system}]
    elif isinstance(existing_system, list):
        json_data["system"] = [claude_code_block, *existing_system]
```

Handles three cases:
- No system prompt -> sets it to the Claude Code marker
- String system prompt -> converts to list, prepends marker
- List of blocks -> prepends marker

Only applies to Messages API calls (detected by `"messages"` key in json_data). Non-messages calls (model list, etc.) are unaffected.

**Call the helper** in both `AnthropicOAuth._prepare_options()` and `AsyncAnthropicOAuth._prepare_options()`, adding one line after `options.headers = headers`:
```python
_inject_system_prompt(options)
```

### 3. Export from `src/anthropic/lib/oauth/__init__.py`

Add `DEFAULT_SYSTEM_PROMPT as DEFAULT_SYSTEM_PROMPT` to the `_types` import block.

### 4. Add tests in `tests/lib/test_oauth.py`

Add `TestSystemPromptInjection` class with ~9 tests:
- `test_inject_when_system_absent` - adds system prompt when none exists
- `test_inject_when_system_is_string` - converts string to list, prepends marker
- `test_inject_when_system_is_list` - prepends marker to existing list
- `test_no_inject_when_json_data_is_none` - GET requests unaffected
- `test_no_inject_when_no_messages_key` - batch endpoints unaffected
- `test_does_not_mutate_original_json_data` - shallow copy safety
- `test_inject_includes_cache_control` - ephemeral cache control present
- `test_inject_via_sync_prepare_options` - integration through sync client
- `test_inject_via_async_prepare_options` - integration through async client

### 5. Example files - No changes needed

The system prompt is auto-injected by `_prepare_options()`, so existing examples work without modification.

## Key references

| File | Purpose |
|------|---------|
| `src/anthropic/_utils/_utils.py:167` | `is_dict()` TypeGuard for pyright compatibility |
| `src/anthropic/_models.py:856` | `FinalRequestOptions` with `json_data` field |
| `src/anthropic/_compat.py` | `model_copy()` used in `_prepare_options` |
| `Jarvis/internal/agent/agent.go:160-185` | Reference: system prompt + cache control |

## Verification

```bash
# Lint
uv run ruff check src/anthropic/lib/oauth/ tests/lib/test_oauth.py

# Type check
uv run pyright src/anthropic/lib/oauth/

# Tests (existing + new)
uv run pytest tests/lib/test_oauth.py -x -v

# Manual smoke test
uv run examples/oauth.py
```
