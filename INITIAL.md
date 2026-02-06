# Plan: Implement OAuth Flow for Anthropic Python SDK

## Context

The Anthropic Python SDK currently supports API key and bearer token authentication but lacks OAuth support for users with regular Claude subscriptions. The Go SDK fork (`sofianhadi1983/anthropic-sdk-go`) has an OAuth module, and the Jarvis app demonstrates the full flow: browser-based authorization with PKCE, token exchange, token storage, auto-refresh, and API calls using the beta messages endpoint with OAuth-specific headers.

This plan ports that OAuth flow to the Python SDK, following existing SDK patterns (Foundry's `_prepare_options()` override for auth injection, Vertex's token refresh pattern).

## Files to Create

### 1. `src/anthropic/lib/oauth/_types.py` — Data types and constants

Defines:
- `DEFAULT_OAUTH_BETAS` — `["oauth-2025-04-20", "interleaved-thinking-2025-05-14", "claude-code-20250219", "fine-grained-tool-streaming-2025-05-14"]`
- `DEFAULT_CLIENT_ID` — `"9d1c250a-e61b-44d9-88ed-5944d1962f5e"`
- `DEFAULT_REDIRECT_URI` — `"https://console.anthropic.com/oauth/code/callback"`
- `DEFAULT_TOKEN_URL` — `"https://console.anthropic.com/v1/oauth/token"`
- `DEFAULT_AUTHORIZE_URL` — `"https://claude.ai/oauth/authorize"`
- `DEFAULT_SCOPES` — `"org:create_api_key user:profile user:inference"`
- `DEFAULT_USER_AGENT` — `"claude-cli/2.1.2 (external, cli)"`
- `EXPIRY_BUFFER_SECONDS` — `300` (5 minutes)

Dataclasses:
- `OAuthConfig` — `client_id`, `redirect_uri`, `token_url`, `authorize_url`, `scopes` (all with defaults from constants above)
- `OrganizationInfo` — `uuid`, `name`
- `AccountInfo` — `uuid`, `email_address`
- `OAuthTokens` — `access_token`, `refresh_token`, `expires_at` (float/unix timestamp), `token_type`, `scope`, `organization: OrganizationInfo | None`, `account: AccountInfo | None`
  - Property `is_expired` — checks `time.time() + EXPIRY_BUFFER_SECONDS >= expires_at`
  - Classmethod `from_token_response(data: dict, ...)` — builds from the raw token endpoint JSON response, computing `expires_at = time.time() + expires_in`

### 2. `src/anthropic/lib/oauth/_auth.py` — OAuth flow functions

Functions:
- `generate_pkce() -> tuple[str, str]` — generates random `code_verifier` (64 bytes, base64url), computes `code_challenge` (SHA-256, base64url). **Dynamic per request** (not hardcoded).
- `build_authorization_url(config: OAuthConfig | None = None) -> tuple[str, OAuthState]` — constructs the full authorization URL with query params: `code=true`, `client_id`, `response_type=code`, `redirect_uri`, `scope`, `code_challenge`, `code_challenge_method=S256`, `state`. Returns the URL and an `OAuthState` object (holds `code_verifier` and `state`).
- `parse_auth_code(raw: str) -> tuple[str, str]` — parses `"code#state"` format, raises `OAuthFlowError` on invalid input.
- `exchange_code_for_tokens(code, state, oauth_state, config) -> OAuthTokens` — POST to token URL with JSON body `{code, state, grant_type: "authorization_code", client_id, redirect_uri, code_verifier}`. Headers: `Content-Type: application/json`, `User-Agent: claude-cli/2.1.2 (external, cli)`. Validates `state == oauth_state.state`. Uses `httpx.Client` for the HTTP call. Returns `OAuthTokens.from_token_response(...)`.
- `async_exchange_code_for_tokens(...)` — async variant using `httpx.AsyncClient`.
- `refresh_access_token(refresh_token, config) -> OAuthTokens` — POST to token URL with `{grant_type: "refresh_token", client_id, refresh_token}`. Same headers. Uses `httpx.Client`.
- `async_refresh_access_token(...)` — async variant.
- `open_browser(url: str) -> bool` — cross-platform browser opener using `webbrowser.open()`.

Helper type:
- `OAuthState` — dataclass with `code_verifier: str`, `state: str`
- `OAuthFlowError(AnthropicError)` — exception for OAuth-specific errors

### 3. `src/anthropic/lib/oauth/_token_storage.py` — Token persistence

JSON file-based storage at `~/.anthropic/oauth_tokens.json`:
- `TokenStorage(path: str | None = None)` — defaults to `~/.anthropic/oauth_tokens.json`
  - `save(tokens: OAuthTokens) -> None` — writes JSON with `0600` permissions, creates parent dirs
  - `load() -> OAuthTokens | None` — reads and deserializes, returns `None` if file doesn't exist
  - `clear() -> None` — deletes the file
  - `exists() -> bool`
  - Uses `threading.Lock` for thread-safety
- `TokenStorageError(AnthropicError)` — storage-specific error
- `load_tokens_from_env() -> OAuthTokens | None` — checks `ANTHROPIC_OAUTH_ACCESS_TOKEN` then `ANTHROPIC_ACCESS_TOKEN`, plus `ANTHROPIC_REFRESH_TOKEN` and `ANTHROPIC_TOKEN_EXPIRES_AT`

### 4. `src/anthropic/lib/oauth/_client.py` — Main client classes

**`AnthropicOAuth(Anthropic)`** — inherits from `Anthropic` (Foundry pattern), giving full access to all resources (`messages`, `beta`, `models`, `completions`) automatically.

Constructor:
- `oauth_tokens: OAuthTokens | None`
- `oauth_config: OAuthConfig | None` (defaults to `OAuthConfig()`)
- `token_storage: TokenStorage | None`
- `betas: list[str] | None` (defaults to `DEFAULT_OAUTH_BETAS`)
- `user_agent: str | None` (defaults to `DEFAULT_USER_AGENT`)
- Standard httpx/timeout/retry params
- Passes `auth_token="oauth"` placeholder to `super().__init__()` to bypass validation

Overrides (following Foundry pattern from `src/anthropic/lib/foundry.py:246`):
- `auth_headers` → returns `{}` (auth injected per-request instead)
- `_validate_headers` → no-op (we handle auth ourselves)
- `default_headers` → adds `anthropic-beta` header with OAuth betas, overrides `User-Agent`
- `_prepare_options(options)` → injects `Authorization: Bearer {access_token}` via `_ensure_access_token()`, appends `?beta=true` to URLs

Token management:
- `_ensure_access_token() -> str` — returns current token if valid, otherwise refreshes using `refresh_access_token()`. Thread-safe via `threading.Lock` with double-check pattern. Persists refreshed tokens to storage if configured.

Class methods:
- `from_env(**kwargs)` — loads from env vars via `load_tokens_from_env()`
- `from_storage(storage_path=None, **kwargs)` — loads from file storage
- `authorize_interactive(config=None) -> OAuthTokens` (static) — opens browser, prompts for code#state, exchanges for tokens

Properties: `oauth_tokens`, `oauth_config`

`copy()` / `with_options` — preserves OAuth state through `_extra_kwargs` pattern (as done in `foundry.py:225`).

**`AsyncAnthropicOAuth(AsyncAnthropic)`** — async variant with:
- `async _ensure_access_token()` using `async_refresh_access_token()`
- `async _prepare_options()` override
- Same class methods (`from_env`, `from_storage`)

### 5. `src/anthropic/lib/oauth/__init__.py` — Public exports

Re-exports all public types:
- `AnthropicOAuth`, `AsyncAnthropicOAuth`
- `OAuthConfig`, `OAuthTokens`, `AccountInfo`, `OrganizationInfo`
- `OAuthState`, `OAuthFlowError`
- `TokenStorage`, `TokenStorageError`, `load_tokens_from_env`
- `build_authorization_url`, `exchange_code_for_tokens`, `refresh_access_token`, `parse_auth_code`, `open_browser`
- `async_exchange_code_for_tokens`, `async_refresh_access_token`
- `DEFAULT_OAUTH_BETAS`

## Files to Modify

### 6. `src/anthropic/__init__.py` — Add export (line ~104)

Add after the Foundry import line:
```python
from .lib.oauth import AnthropicOAuth as AnthropicOAuth, AsyncAnthropicOAuth as AsyncAnthropicOAuth
```

## Files to Create (Tests)

### 7. `tests/lib/test_oauth.py`

Test classes following the pattern in `tests/lib/test_azure.py`:

- `TestOAuthTypes` — `is_expired` property, `from_token_response`
- `TestOAuthAuth` — `generate_pkce` produces valid values, `build_authorization_url` returns valid URL with all params, `parse_auth_code` valid/invalid, `exchange_code_for_tokens` with mocked httpx (using `respx`), state mismatch error, `refresh_access_token` with mock
- `TestTokenStorage` — save/load round-trip (using `tmp_path`), load returns None for missing, clear removes file
- `TestLoadTokensFromEnv` — env var loading with `monkeypatch`
- `TestAnthropicOAuth` — initialization with tokens, `from_env`, `from_storage`, `_ensure_access_token` returns valid token, `_ensure_access_token` refreshes expired token (mock refresh), `_prepare_options` injects Authorization header and `?beta=true`, `default_headers` includes betas and User-Agent, `copy` preserves OAuth state
- `TestAsyncAnthropicOAuth` — async variants

## No New Dependencies Required

The module uses only:
- `httpx` (already required) — for token exchange/refresh HTTP calls
- `hashlib`, `secrets`, `base64`, `webbrowser`, `json`, `threading`, `time`, `os`, `pathlib`, `dataclasses` — all stdlib

No changes to `pyproject.toml` optional dependencies needed.

## Implementation Order

1. `_types.py` (no deps on other new files)
2. `_token_storage.py` (depends on `_types`)
3. `_auth.py` (depends on `_types`)
4. `_client.py` (depends on all above)
5. `__init__.py` (re-exports)
6. Update `src/anthropic/__init__.py`
7. `tests/lib/test_oauth.py`

## Key Reference Files

- `src/anthropic/lib/foundry.py` — primary pattern: inheriting from `Anthropic`/`AsyncAnthropic`, `_prepare_options()` override, `copy()` with `_extra_kwargs`
- `src/anthropic/lib/vertex/_client.py` — token refresh pattern (`_ensure_access_token`)
- `src/anthropic/_client.py` — parent classes, `auth_headers`, `_validate_headers`
- `src/anthropic/_compat.py:model_copy` — used for copying `FinalRequestOptions`
- `tests/lib/test_azure.py` — test pattern reference

## Verification

1. **Unit tests**: `UV_PYTHON=">=3.9.0" uv run --isolated --all-extras pytest tests/lib/test_oauth.py -v`
2. **Type checking**: `uv run pyright src/anthropic/lib/oauth/`
3. **Lint**: `uv run ruff check src/anthropic/lib/oauth/ tests/lib/test_oauth.py`
4. **Import check**: `uv run python -c "from anthropic import AnthropicOAuth, AsyncAnthropicOAuth; print('OK')"`
5. **Integration smoke test** (manual, requires real Claude account):
   ```python
   from anthropic.lib.oauth import AnthropicOAuth, OAuthTokens, TokenStorage

   # Run interactive auth
   tokens = AnthropicOAuth.authorize_interactive()
   print(f"Account: {tokens.account}")
   print(f"Org: {tokens.organization}")

   # Save tokens
   storage = TokenStorage()
   storage.save(tokens)

   # Create client and make API call
   client = AnthropicOAuth(oauth_tokens=tokens, token_storage=storage)
   response = client.messages.create(
       model="claude-sonnet-4-5-20250929",
       max_tokens=100,
       messages=[{"role": "user", "content": "Hello!"}],
   )
   print(response.content[0].text)
   ```
