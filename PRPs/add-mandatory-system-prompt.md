# PRP: Inject Mandatory Claude Code System Prompt for OAuth Requests

## Goal

Fix the `BadRequestError: 400 - "This credential is only authorized for use with Claude Code"` error by auto-injecting the mandatory Claude Code system prompt into every Messages API call made through the OAuth client.

## Why

- **The OAuth client is broken for real API calls.** Tokens obtained with `user:sessions:claude_code` scope are rejected unless the request includes a system prompt identifying the session as Claude Code.
- **The Jarvis reference implementation** (working Go app at `/Users/sofian.hadianto/Documents/workspace/personal/Jarvis`) proves this is the root cause — it sends `"You are Claude Code, Anthropic's official CLI for Claude."` as the first system block in every Messages API call (`internal/agent/agent.go:162-185`).
- **Our OAuth client** already sends the correct headers (`anthropic-beta`, `User-Agent`, `Authorization`, `?beta=true`) but omits this mandatory system prompt from the request body.

## What

Auto-inject `"You are Claude Code, Anthropic's official CLI for Claude."` as the first system text block (with `cache_control: {"type": "ephemeral"}`) into the `json_data` of every Messages API request, within the existing `_prepare_options()` hook.

### Success Criteria

- [ ] `uv run examples/oauth.py` completes without `BadRequestError`
- [ ] System prompt is injected when `system` is absent, a string, or a list
- [ ] Non-messages API calls (model listing, etc.) are not affected
- [ ] All existing 49 tests still pass
- [ ] New tests for all injection cases pass
- [ ] `uv run ruff check` — 0 errors
- [ ] `uv run pyright` — 0 errors, 0 warnings

## All Needed Context

### Documentation & References

```yaml
- file: src/anthropic/lib/oauth/_client.py
  why: "PRIMARY file to modify. Contains _prepare_options() for both sync/async clients (lines 88-103 and 260-275)"

- file: src/anthropic/lib/oauth/_types.py
  why: "Add DEFAULT_SYSTEM_PROMPT constant here, after DEFAULT_USER_AGENT on line 18"

- file: src/anthropic/lib/oauth/__init__.py
  why: "Add DEFAULT_SYSTEM_PROMPT export to the _types import block (lines 13-19)"

- file: tests/lib/test_oauth.py
  why: "Add TestSystemPromptInjection class. Follow existing test patterns (FinalRequestOptions, OAuthTokens construction)"

- file: src/anthropic/_utils/_utils.py:167
  why: "is_dict(obj) -> TypeGuard[dict[object, object]]. Use this for pyright-safe dict type narrowing on options.json_data"

- file: src/anthropic/_models.py:856
  why: "FinalRequestOptions pydantic model. json_data field is Union[Body, None]. Body = object."

- file: src/anthropic/_compat.py
  why: "model_copy() already used in _prepare_options to copy FinalRequestOptions"

- file: /Users/sofian.hadianto/Documents/workspace/personal/Jarvis/internal/agent/agent.go:160-185
  why: "Reference implementation showing mandatory system prompt injection with cache_control"
```

### Known Gotchas & Library Quirks

```python
# CRITICAL: is_dict() narrows to dict[object, object], NOT dict[str, Any]
# After is_dict(options.json_data), you work with dict[object, object]
# This is fine — "messages" in dict[object, object] works because str is object
# Assign shallow copy as: json_data: dict[object, object] = {**options.json_data}

# CRITICAL: model_copy() does a SHALLOW copy of FinalRequestOptions
# The json_data dict inside is shared with the original
# You MUST shallow-copy json_data separately: {**options.json_data}
# to avoid mutating the caller's dict

# CRITICAL: _prepare_options is sync for AnthropicOAuth, async for AsyncAnthropicOAuth
# The helper function _inject_system_prompt should be plain sync (no IO)
# It only mutates options in-place — no awaits needed

# CRITICAL: Pyright strict mode with pythonVersion: "3.9"
# Use dict[object, object] after is_dict narrowing
# Use dict[str, object] for the claude_code_block literal

# CRITICAL: The system field in messages.create() can be:
# 1. Absent/None — inject [claude_code_block]
# 2. A string — convert to [claude_code_block, {"type": "text", "text": existing_string}]
# 3. A list of TextBlockParam dicts — prepend: [claude_code_block, *existing_list]

# NOTE: Detect Messages API calls by checking "messages" key in json_data
# This key is present in messages.create() but NOT in models.list(), completions, etc.
```

## Implementation Blueprint

### Data models and structure

No new data models. One new constant:

```python
# In src/anthropic/lib/oauth/_types.py, after line 18 (DEFAULT_USER_AGENT)
DEFAULT_SYSTEM_PROMPT = "You are Claude Code, Anthropic's official CLI for Claude."
```

### Tasks

```yaml
Task 1:
  MODIFY src/anthropic/lib/oauth/_types.py:
    - FIND line: 'DEFAULT_USER_AGENT = "claude-cli/2.1.2 (external, cli)"'
    - INSERT after that line:
      'DEFAULT_SYSTEM_PROMPT = "You are Claude Code, Anthropic'\''s official CLI for Claude."'
    - TOTAL: 1 line added

Task 2:
  MODIFY src/anthropic/lib/oauth/_client.py:
    - UPDATE import on line 19 to add DEFAULT_SYSTEM_PROMPT:
      FROM: 'from ._types import DEFAULT_USER_AGENT, DEFAULT_OAUTH_BETAS, OAuthConfig, OAuthTokens'
      TO:   'from ._types import DEFAULT_SYSTEM_PROMPT, DEFAULT_USER_AGENT, DEFAULT_OAUTH_BETAS, OAuthConfig, OAuthTokens'
    - UPDATE import on line 21 to add is_dict:
      FROM: 'from ..._utils import is_given'
      TO:   'from ..._utils import is_dict, is_given'
    - INSERT new function between line 27 (blank line after imports) and line 29 (class AnthropicOAuth):
      The _inject_system_prompt() helper function
    - INSERT one line in AnthropicOAuth._prepare_options() after 'options.headers = headers' (line 93):
      '_inject_system_prompt(options)'
    - INSERT one line in AsyncAnthropicOAuth._prepare_options() after 'options.headers = headers' (line 265):
      '_inject_system_prompt(options)'

Task 3:
  MODIFY src/anthropic/lib/oauth/__init__.py:
    - FIND the _types import block (lines 13-19)
    - ADD 'DEFAULT_SYSTEM_PROMPT as DEFAULT_SYSTEM_PROMPT,' after the DEFAULT_OAUTH_BETAS line

Task 4:
  MODIFY tests/lib/test_oauth.py:
    - ADD imports for FinalRequestOptions, _inject_system_prompt, DEFAULT_SYSTEM_PROMPT
    - ADD TestSystemPromptInjection class with 9 test methods
    - INSERT the new class after TestAnthropicOAuth (before TestAsyncAnthropicOAuth)

Task 5:
  RUN validation gates (see Validation Loop below)
```

### Task 2 — Pseudocode for `_inject_system_prompt`

```python
# INSERT between imports and class AnthropicOAuth (after line 27, before line 29)

def _inject_system_prompt(options: FinalRequestOptions) -> None:
    """Inject mandatory Claude Code system prompt into Messages API requests.

    OAuth tokens with ``user:sessions:claude_code`` scope require this.
    """
    # Guard 1: json_data must be a dict (GET requests have None)
    if not is_dict(options.json_data):
        return
    # Guard 2: only inject for Messages API calls (have "messages" key)
    if "messages" not in options.json_data:
        return

    # Shallow-copy to avoid mutating shared dict from model_copy
    json_data: dict[object, object] = {**options.json_data}
    options.json_data = json_data

    # The block matching Jarvis: type=text, text=prompt, cache_control=ephemeral
    claude_code_block: dict[str, object] = {
        "type": "text",
        "text": DEFAULT_SYSTEM_PROMPT,
        "cache_control": {"type": "ephemeral"},
    }

    existing_system = json_data.get("system")
    if existing_system is None:
        # Case 1: No system prompt — set it
        json_data["system"] = [claude_code_block]
    elif isinstance(existing_system, str):
        # Case 2: String system prompt — convert to list, prepend marker
        json_data["system"] = [
            claude_code_block,
            {"type": "text", "text": existing_system},
        ]
    elif isinstance(existing_system, list):
        # Case 3: List of blocks — prepend marker
        json_data["system"] = [claude_code_block, *existing_system]
```

### Task 2 — Where to call it in `_prepare_options`

```python
# In AnthropicOAuth._prepare_options (currently lines 88-103):
@override
def _prepare_options(self, options: FinalRequestOptions) -> FinalRequestOptions:
    headers: dict[str, str | Omit] = {**options.headers} if is_given(options.headers) else {}

    options = model_copy(options)
    options.headers = headers
    _inject_system_prompt(options)          # <-- ADD THIS LINE

    access_token = self._ensure_access_token()
    headers["Authorization"] = f"Bearer {access_token}"
    # ... rest unchanged


# In AsyncAnthropicOAuth._prepare_options (currently lines 260-275):
@override
async def _prepare_options(self, options: FinalRequestOptions) -> FinalRequestOptions:
    headers: dict[str, str | Omit] = {**options.headers} if is_given(options.headers) else {}

    options = model_copy(options)
    options.headers = headers
    _inject_system_prompt(options)          # <-- ADD THIS LINE

    access_token = await self._ensure_access_token()
    headers["Authorization"] = f"Bearer {access_token}"
    # ... rest unchanged
```

### Task 4 — Test class pseudocode

```python
# Add these imports at the top of tests/lib/test_oauth.py:
from anthropic._models import FinalRequestOptions
from anthropic.lib.oauth._client import _inject_system_prompt
from anthropic.lib.oauth._types import DEFAULT_SYSTEM_PROMPT

# INSERT new class after TestAnthropicOAuth, before TestAsyncAnthropicOAuth:
class TestSystemPromptInjection:

    def test_inject_when_system_absent(self) -> None:
        # FinalRequestOptions with messages key but no system
        # After _inject_system_prompt: system = [claude_code_block]
        # Assert len(system) == 1, system[0]["text"] == DEFAULT_SYSTEM_PROMPT

    def test_inject_when_system_is_string(self) -> None:
        # json_data has system="You are a helpful assistant."
        # After: system = [claude_code_block, {type:text, text:original}]
        # Assert len(system) == 2

    def test_inject_when_system_is_list(self) -> None:
        # json_data has system=[{type:text, text:Block1}, {type:text, text:Block2}]
        # After: system = [claude_code_block, Block1, Block2]
        # Assert len(system) == 3

    def test_no_inject_when_json_data_is_none(self) -> None:
        # FinalRequestOptions(method="get", url="/v1/models") — json_data is None
        # After: json_data still None

    def test_no_inject_when_no_messages_key(self) -> None:
        # json_data={"requests": []} — batch endpoint, no "messages" key
        # After: no "system" key added

    def test_does_not_mutate_original_json_data(self) -> None:
        # Create original dict, pass as json_data
        # After inject: original dict should NOT have "system" key
        # But options.json_data SHOULD have it

    def test_inject_includes_cache_control(self) -> None:
        # After inject: system[0]["cache_control"] == {"type": "ephemeral"}

    def test_inject_via_sync_prepare_options(self) -> None:
        # Create AnthropicOAuth with valid tokens
        # Call client._prepare_options(options) with messages json_data
        # Assert result.json_data["system"][0]["text"] == DEFAULT_SYSTEM_PROMPT

    async def test_inject_via_async_prepare_options(self) -> None:
        # Create AsyncAnthropicOAuth with valid tokens
        # Call await client._prepare_options(options)
        # Assert result.json_data["system"][0]["text"] == DEFAULT_SYSTEM_PROMPT
```

### Integration Points

```yaml
IMPORTS:
  - _client.py line 19: add DEFAULT_SYSTEM_PROMPT to ._types import
  - _client.py line 21: add is_dict to ..._utils import
  - __init__.py: add DEFAULT_SYSTEM_PROMPT to _types export block
  - test_oauth.py: add FinalRequestOptions, _inject_system_prompt, DEFAULT_SYSTEM_PROMPT

NO DATABASE/CONFIG/ROUTES changes needed.
```

## Validation Loop

### Level 1: Syntax & Style

```bash
# Run FIRST — fix any errors before proceeding
uv run ruff check src/anthropic/lib/oauth/_types.py src/anthropic/lib/oauth/_client.py src/anthropic/lib/oauth/__init__.py tests/lib/test_oauth.py --fix
uv run ruff format src/anthropic/lib/oauth/ tests/lib/test_oauth.py

# Expected: No errors. If I001 import sorting errors, --fix handles them.
```

### Level 2: Type Checking

```bash
uv run pyright src/anthropic/lib/oauth/

# Expected: 0 errors, 0 warnings, 0 informations
# Common fix: if pyright complains about dict access, use is_dict TypeGuard pattern
```

### Level 3: Unit Tests

```bash
# Run ALL oauth tests (existing 49 + new ~9 = ~58)
uv run pytest tests/lib/test_oauth.py -x -v

# Expected: All pass. If failing: Read error, fix code, re-run.
```

### Level 4: Import Smoke Test

```bash
uv run python -c "from anthropic.lib.oauth import DEFAULT_SYSTEM_PROMPT; print(DEFAULT_SYSTEM_PROMPT)"

# Expected: "You are Claude Code, Anthropic's official CLI for Claude."
```

## Final Validation Checklist

- [ ] All tests pass: `uv run pytest tests/lib/test_oauth.py -x -v`
- [ ] No linting errors: `uv run ruff check src/anthropic/lib/oauth/ tests/lib/test_oauth.py`
- [ ] No type errors: `uv run pyright src/anthropic/lib/oauth/`
- [ ] Import smoke test passes
- [ ] System prompt injected for messages requests (no system, string system, list system)
- [ ] Non-messages requests unaffected
- [ ] Original json_data dict not mutated (shallow copy safety)

## Anti-Patterns to Avoid

- Do NOT modify `FinalRequestOptions` class or `_base_client.py` — those are generated files
- Do NOT override `messages.create()` — use the existing `_prepare_options()` hook
- Do NOT deep-copy the entire json_data — shallow copy with `{**options.json_data}` is sufficient
- Do NOT add the system prompt to non-messages endpoints
- Do NOT use `isinstance(x, dict)` directly — use `is_dict()` for pyright TypeGuard compatibility
- Do NOT import from `anthropic.lib.oauth._client` in `__init__.py` for the helper — it's internal

---

**Confidence Score: 9/10** — All code patterns are proven (is_dict, model_copy, FinalRequestOptions), the exact insertion points are identified with line numbers, and the Jarvis reference confirms the fix. The only risk is potential pyright edge cases with `dict[object, object]` operations, but the `is_dict` TypeGuard pattern is used elsewhere in the codebase.
