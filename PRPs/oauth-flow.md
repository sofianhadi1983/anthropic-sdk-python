name: "OAuth Flow for Anthropic Python SDK"
description: |

## Purpose
Implement OAuth authentication flow for the Anthropic Python SDK, enabling users with regular Claude subscriptions to authenticate via browser-based OAuth with PKCE, token exchange, token storage, auto-refresh, and API calls using OAuth-specific headers and betas.

## Core Principles
1. **Context is King**: Include ALL necessary documentation, examples, and caveats
2. **Validation Loops**: Provide executable tests/lints the AI can run and fix
3. **Information Dense**: Use keywords and patterns from the codebase
4. **Progressive Success**: Start simple, validate, then enhance
5. **Global rules**: Be sure to follow all rules in CLAUDE.md

---

## Goal
Create an OAuth module at `src/anthropic/lib/oauth/` providing `AnthropicOAuth` and `AsyncAnthropicOAuth` client classes that inherit from `Anthropic`/`AsyncAnthropic`, handle OAuth token lifecycle (PKCE auth flow, token exchange, token persistence, auto-refresh), and inject OAuth-specific headers/betas on every request.

## Why
- Users with regular Claude subscriptions need OAuth-based authentication (not API keys)
- Enables browser-based authorization with PKCE security
- Auto-refresh of tokens prevents expired-token errors during long sessions
- Follows established SDK patterns (Foundry, Vertex, Bedrock) for platform integrations

## What
User-visible behavior:
- `AnthropicOAuth` / `AsyncAnthropicOAuth` clients that work identically to `Anthropic` / `AsyncAnthropic` but use OAuth tokens
- Interactive browser-based authorization flow via `authorize_interactive()`
- Token persistence to `~/.anthropic/oauth_tokens.json`
- Automatic token refresh when tokens expire
- Environment variable support (`ANTHROPIC_OAUTH_ACCESS_TOKEN`, `ANTHROPIC_ACCESS_TOKEN`, `ANTHROPIC_REFRESH_TOKEN`, `ANTHROPIC_TOKEN_EXPIRES_AT`)
- OAuth-specific beta headers automatically injected

### Success Criteria
- [ ] `AnthropicOAuth` and `AsyncAnthropicOAuth` can be instantiated with OAuth tokens
- [ ] Tokens are automatically refreshed when expired
- [ ] OAuth betas and User-Agent headers are injected on every request
- [ ] `?beta=true` is appended to request URLs
- [ ] Token storage saves/loads/clears tokens from `~/.anthropic/oauth_tokens.json` with `0600` permissions
- [ ] Environment variable loading works
- [ ] `copy()` / `with_options` preserves OAuth state
- [ ] All unit tests pass
- [ ] Type checking passes (pyright)
- [ ] Linting passes (ruff)
- [ ] Import from `anthropic` top-level works: `from anthropic import AnthropicOAuth, AsyncAnthropicOAuth`

## All Needed Context

### Documentation & References
```yaml
# MUST READ - Include these in your context window
- file: src/anthropic/lib/foundry.py
  why: |
    PRIMARY PATTERN to follow. Shows how to:
    - Inherit from Anthropic/AsyncAnthropic (lines 90, 267)
    - Override _prepare_options() to inject auth headers (lines 246-264, 425-443)
    - Override copy() with _extra_kwargs pattern (lines 195-231, 371-408)
    - Use BaseFoundryClient mixin pattern (line 36)
    - Pass placeholder auth to bypass validation in super().__init__()
    CRITICAL: AnthropicFoundry passes `api_key=api_key` to super().__init__() - for OAuth we pass `auth_token="oauth"` placeholder

- file: src/anthropic/lib/vertex/_client.py
  why: |
    TOKEN REFRESH PATTERN. Shows how to:
    - Implement _ensure_access_token() for sync (lines 158-174)
    - Implement async _ensure_access_token() (lines 303-319)
    - Use _prepare_request() for auth injection (lines 151-156, 296-301)
    - Vertex uses _prepare_request() while Foundry uses _prepare_options() - we use _prepare_options() like Foundry

- file: src/anthropic/_client.py
  why: |
    PARENT CLASS. Shows:
    - auth_headers property (lines 157-158) - returns {X-Api-Key + Authorization}
    - _validate_headers (lines 185-198) - raises TypeError if no auth
    - default_headers (lines 176-182) - includes anthropic-version header
    - copy() method signature (lines 200-251) - _extra_kwargs pattern
    - __init__ params: api_key, auth_token, base_url, timeout, max_retries, default_headers, default_query, http_client

- file: src/anthropic/_base_client.py
  why: |
    BASE MACHINERY. Key hooks:
    - _prepare_options() at line 984 (sync) and 1619 (async) - hook for mutating request options
    - auth_headers property at line 677 - returns {} by default
    - default_headers property at line 681 - includes auth_headers spread
    - _validate_headers() at line 697 - no-op by default

- file: src/anthropic/_exceptions.py
  why: |
    AnthropicError base class (line 21-22) for our custom exceptions
    OAuthFlowError and TokenStorageError should inherit from AnthropicError

- file: src/anthropic/_compat.py
  why: |
    model_copy function (line 122-125) for copying FinalRequestOptions
    Used in _prepare_options() to create a mutable copy of options

- file: src/anthropic/_models.py
  why: |
    FinalRequestOptions class (line 856) - the options object mutated in _prepare_options()
    Fields: method, url, params, headers, json_data, etc.

- file: tests/lib/test_azure.py
  why: |
    TEST PATTERN. Shows how to:
    - Test client initialization with various args
    - Test env var fallback with monkeypatch
    - Test error cases (missing credentials)
    - Test token provider functions
    - Use pytest.mark.asyncio for async tests

- file: src/anthropic/lib/bedrock/__init__.py
  why: Module __init__.py export pattern (single line re-export)

- file: src/anthropic/lib/vertex/__init__.py
  why: Module __init__.py export pattern (single line re-export)

- file: src/anthropic/__init__.py
  why: |
    TOP-LEVEL EXPORTS. Line 104 shows Foundry import pattern:
    from .lib.foundry import AnthropicFoundry as AnthropicFoundry, AsyncAnthropicFoundry as AsyncAnthropicFoundry
    We add similar line after it for OAuth.

- url: https://github.com/lundberg/respx
  why: |
    RESPX for mocking httpx calls in tests.
    Usage: respx.post("url").respond(json={...}, status_code=200)
    Already a dev dependency in pyproject.toml
```

### Current Codebase Tree (relevant parts)
```bash
src/anthropic/
  __init__.py              # Top-level exports (line 104 = Foundry import)
  _client.py               # Anthropic / AsyncAnthropic parent classes
  _base_client.py          # SyncAPIClient / AsyncAPIClient / BaseClient
  _exceptions.py           # AnthropicError base
  _compat.py               # model_copy helper
  _models.py               # FinalRequestOptions
  lib/
    foundry.py             # AnthropicFoundry pattern (PRIMARY REFERENCE)
    bedrock/
      __init__.py
      _client.py
    vertex/
      __init__.py
      _client.py           # Token refresh pattern
    streaming/
    tools/
tests/
  conftest.py              # pytest config, async test auto-marking
  lib/
    test_azure.py          # Foundry test pattern (PRIMARY TEST REFERENCE)
```

### Desired Codebase Tree (files to add/modify)
```bash
src/anthropic/lib/oauth/           # NEW directory
  __init__.py                      # Re-exports all public types
  _types.py                        # Constants, dataclasses (OAuthConfig, OAuthTokens, etc.)
  _auth.py                         # OAuth flow functions (PKCE, URL building, token exchange)
  _token_storage.py                # JSON file-based token persistence
  _client.py                       # AnthropicOAuth / AsyncAnthropicOAuth client classes

src/anthropic/__init__.py          # MODIFY: add OAuth import line after Foundry import

tests/lib/test_oauth.py           # NEW: comprehensive unit tests
```

### Known Gotchas of our codebase & Library Quirks
```python
# CRITICAL: Anthropic.__init__() requires either api_key or auth_token to be set,
# otherwise _validate_headers() raises TypeError. For OAuth, we must:
# 1. Pass auth_token="oauth" as placeholder to super().__init__()
# 2. Override auth_headers to return {} (auth injected per-request in _prepare_options)
# 3. Override _validate_headers to be a no-op

# CRITICAL: model_copy from _compat.py is used to copy FinalRequestOptions
# NOT the pydantic model_copy directly. Import: from ..._compat import model_copy

# CRITICAL: _prepare_options() is sync in SyncAPIClient (line 984) and async in
# AsyncAPIClient (line 1619). The sync client's override must be a regular method,
# the async client's override must be async.

# CRITICAL: FinalRequestOptions.headers is Union[Headers, NotGiven].
# Must check is_given(options.headers) before spreading. Pattern from foundry.py:247:
#   headers: dict[str, str | Omit] = {**options.headers} if is_given(options.headers) else {}

# CRITICAL: Tests use auto-marking for async tests (conftest.py:26-30),
# so @pytest.mark.asyncio is NOT needed on individual tests.

# CRITICAL: Use `from __future__ import annotations` at top of every new file.

# CRITICAL: The SDK supports both Pydantic v1 and v2. Don't use Pydantic features
# that are v2-only. Use plain dataclasses for our types, not Pydantic models.

# CRITICAL: Line length is 120 characters (ruff config).

# CRITICAL: respx is available as dev dependency for mocking httpx calls in tests.
# Usage pattern: respx.post("https://url").respond(json={...}, status_code=200)
# Use respx.mock decorator or context manager.

# CRITICAL: For the copy() method, follow Foundry pattern (foundry.py:195-231):
# - Accept same params as parent plus OAuth-specific ones
# - Pass OAuth state via _extra_kwargs dict to super().copy()

# NOTE: Foundry inherits from BOTH BaseFoundryClient and Anthropic (MRO).
# For OAuth, we DON'T need a BaseClient mixin - direct inheritance from
# Anthropic/AsyncAnthropic is sufficient since we don't need to override
# _make_status_error or restrict endpoints.
```

## Implementation Blueprint

### Data Models and Structure

```python
# _types.py - All plain dataclasses, no Pydantic dependency
import dataclasses
import time

# Constants
DEFAULT_OAUTH_BETAS = ["oauth-2025-04-20", "interleaved-thinking-2025-05-14",
                       "claude-code-20250219", "fine-grained-tool-streaming-2025-05-14"]
DEFAULT_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
DEFAULT_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
DEFAULT_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
DEFAULT_AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
DEFAULT_SCOPES = "org:create_api_key user:profile user:inference"
DEFAULT_USER_AGENT = "claude-cli/2.1.2 (external, cli)"
EXPIRY_BUFFER_SECONDS = 300

@dataclasses.dataclass
class OAuthConfig:
    client_id: str = DEFAULT_CLIENT_ID
    redirect_uri: str = DEFAULT_REDIRECT_URI
    token_url: str = DEFAULT_TOKEN_URL
    authorize_url: str = DEFAULT_AUTHORIZE_URL
    scopes: str = DEFAULT_SCOPES

@dataclasses.dataclass
class OrganizationInfo:
    uuid: str
    name: str

@dataclasses.dataclass
class AccountInfo:
    uuid: str
    email_address: str

@dataclasses.dataclass
class OAuthTokens:
    access_token: str
    refresh_token: str
    expires_at: float  # unix timestamp
    token_type: str = "bearer"
    scope: str = ""
    organization: OrganizationInfo | None = None
    account: AccountInfo | None = None

    @property
    def is_expired(self) -> bool:
        return time.time() + EXPIRY_BUFFER_SECONDS >= self.expires_at

    @classmethod
    def from_token_response(cls, data: dict, ...) -> OAuthTokens:
        # Compute expires_at = time.time() + data["expires_in"]
        # Extract organization/account if present
        ...
```

### List of tasks to be completed in order

```yaml
Task 1:
CREATE src/anthropic/lib/oauth/_types.py:
  - Define all constants (DEFAULT_OAUTH_BETAS, DEFAULT_CLIENT_ID, etc.)
  - Define OAuthConfig dataclass with defaults
  - Define OrganizationInfo, AccountInfo dataclasses
  - Define OAuthTokens dataclass with is_expired property and from_token_response classmethod
  - CRITICAL: Use `from __future__ import annotations` for forward references
  - CRITICAL: All fields with `| None` type need default=None for Python 3.9 compat

Task 2:
CREATE src/anthropic/lib/oauth/_auth.py:
  - Define OAuthState dataclass (code_verifier: str, state: str)
  - Define OAuthFlowError(AnthropicError) exception
  - Implement generate_pkce() -> tuple[str, str] using secrets + hashlib
  - Implement build_authorization_url(config=None) -> tuple[str, OAuthState]
  - Implement parse_auth_code(raw: str) -> tuple[str, str]
  - Implement exchange_code_for_tokens() using httpx.Client
  - Implement async_exchange_code_for_tokens() using httpx.AsyncClient
  - Implement refresh_access_token() using httpx.Client
  - Implement async_refresh_access_token() using httpx.AsyncClient
  - Implement open_browser(url) using webbrowser.open()
  - DEPENDS ON: Task 1 (_types.py)

Task 3:
CREATE src/anthropic/lib/oauth/_token_storage.py:
  - Define TokenStorageError(AnthropicError) exception
  - Implement TokenStorage class with threading.Lock
  - Methods: save(), load(), clear(), exists()
  - JSON file at ~/.anthropic/oauth_tokens.json with 0600 permissions
  - Implement load_tokens_from_env() function
  - DEPENDS ON: Task 1 (_types.py)

Task 4:
CREATE src/anthropic/lib/oauth/_client.py:
  - MIRROR PATTERN FROM: src/anthropic/lib/foundry.py
  - Implement AnthropicOAuth(Anthropic):
    - __init__: accept oauth_tokens, oauth_config, token_storage, betas, user_agent
    - Pass auth_token="oauth" placeholder to super().__init__()
    - Override auth_headers -> return {}
    - Override _validate_headers -> no-op
    - Override default_headers -> add anthropic-beta with OAuth betas, override User-Agent
    - Override _prepare_options -> inject Authorization Bearer, append ?beta=true
    - _ensure_access_token() with threading.Lock and double-check pattern
    - copy() with _extra_kwargs for OAuth state (FOLLOW foundry.py:195-231)
    - Class methods: from_env, from_storage, authorize_interactive
  - Implement AsyncAnthropicOAuth(AsyncAnthropic):
    - Same structure but async _prepare_options and async _ensure_access_token
    - Use asyncio.Lock instead of threading.Lock
  - DEPENDS ON: Tasks 1, 2, 3
  - CRITICAL: Import model_copy from ..._compat, is_given from ..._utils, Omit from ..._types

Task 5:
CREATE src/anthropic/lib/oauth/__init__.py:
  - Re-export all public types (follow bedrock/__init__.py pattern but with more exports)
  - DEPENDS ON: Task 4

Task 6:
MODIFY src/anthropic/__init__.py:
  - FIND line: from .lib.foundry import AnthropicFoundry as AnthropicFoundry, AsyncAnthropicFoundry as AsyncAnthropicFoundry
  - ADD AFTER that line:
    from .lib.oauth import AnthropicOAuth as AnthropicOAuth, AsyncAnthropicOAuth as AsyncAnthropicOAuth
  - DEPENDS ON: Task 5

Task 7:
CREATE tests/lib/test_oauth.py:
  - MIRROR PATTERN FROM: tests/lib/test_azure.py
  - TestOAuthTypes: is_expired, from_token_response
  - TestOAuthAuth: generate_pkce, build_authorization_url, parse_auth_code, exchange (with respx), refresh (with respx)
  - TestTokenStorage: save/load/clear round-trip with tmp_path
  - TestLoadTokensFromEnv: env var loading with monkeypatch
  - TestAnthropicOAuth: init, from_env, from_storage, _ensure_access_token, _prepare_options, default_headers, copy
  - TestAsyncAnthropicOAuth: async variants
  - DEPENDS ON: All previous tasks
  - CRITICAL: Do NOT use @pytest.mark.asyncio - it is auto-applied by conftest.py
  - CRITICAL: Use respx for mocking httpx POST calls in exchange/refresh tests
```

### Per-task pseudocode

#### Task 1: _types.py
```python
from __future__ import annotations
import dataclasses
import time

# All constants defined at module level
DEFAULT_OAUTH_BETAS: list[str] = [...]
# ... other constants ...

@dataclasses.dataclass
class OAuthConfig:
    client_id: str = DEFAULT_CLIENT_ID
    # ... other fields with defaults ...

@dataclasses.dataclass
class OrganizationInfo:
    uuid: str
    name: str

@dataclasses.dataclass
class AccountInfo:
    uuid: str
    email_address: str

@dataclasses.dataclass
class OAuthTokens:
    access_token: str
    refresh_token: str
    expires_at: float
    token_type: str = "bearer"
    scope: str = ""
    organization: OrganizationInfo | None = None
    account: AccountInfo | None = None

    @property
    def is_expired(self) -> bool:
        return time.time() + EXPIRY_BUFFER_SECONDS >= self.expires_at

    @classmethod
    def from_token_response(cls, data: dict[str, object]) -> OAuthTokens:
        expires_at = time.time() + int(data.get("expires_in", 3600))
        org_data = data.get("organization")
        org = OrganizationInfo(**org_data) if isinstance(org_data, dict) else None
        acct_data = data.get("account")
        acct = AccountInfo(**acct_data) if isinstance(acct_data, dict) else None
        return cls(
            access_token=str(data["access_token"]),
            refresh_token=str(data.get("refresh_token", "")),
            expires_at=expires_at,
            token_type=str(data.get("token_type", "bearer")),
            scope=str(data.get("scope", "")),
            organization=org,
            account=acct,
        )
```

#### Task 2: _auth.py
```python
from __future__ import annotations
import base64, hashlib, secrets, urllib.parse, webbrowser
import dataclasses
import httpx
from ..._exceptions import AnthropicError
from ._types import OAuthConfig, OAuthTokens, DEFAULT_USER_AGENT

class OAuthFlowError(AnthropicError): pass

@dataclasses.dataclass
class OAuthState:
    code_verifier: str
    state: str

def generate_pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge

def build_authorization_url(config: OAuthConfig | None = None) -> tuple[str, OAuthState]:
    cfg = config or OAuthConfig()
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    params = {
        "code": "true", "client_id": cfg.client_id, "response_type": "code",
        "redirect_uri": cfg.redirect_uri, "scope": cfg.scopes,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
    }
    url = f"{cfg.authorize_url}?{urllib.parse.urlencode(params)}"
    return url, OAuthState(code_verifier=verifier, state=state)

def parse_auth_code(raw: str) -> tuple[str, str]:
    # Parse "code#state" format
    if "#" not in raw:
        raise OAuthFlowError("Invalid auth code format. Expected 'code#state'.")
    code, state = raw.split("#", 1)
    if not code or not state:
        raise OAuthFlowError("Invalid auth code format. Both code and state are required.")
    return code, state

def exchange_code_for_tokens(
    code: str, state: str, oauth_state: OAuthState, config: OAuthConfig | None = None
) -> OAuthTokens:
    cfg = config or OAuthConfig()
    if state != oauth_state.state:
        raise OAuthFlowError("State mismatch - possible CSRF attack")
    # POST to cfg.token_url with JSON body
    with httpx.Client() as client:
        resp = client.post(cfg.token_url, json={...}, headers={...})
        resp.raise_for_status()
        return OAuthTokens.from_token_response(resp.json())

# async variant, refresh_access_token, async_refresh_access_token follow same pattern
```

#### Task 4: _client.py (most critical)
```python
from __future__ import annotations
import threading
from typing import Any, Mapping
from typing_extensions import Self, override
import httpx

from ..._types import NOT_GIVEN, Omit, Timeout, NotGiven
from ..._utils import is_given
from ..._client import Anthropic, AsyncAnthropic
from ..._compat import model_copy
from ..._models import FinalRequestOptions
from ..._base_client import DEFAULT_MAX_RETRIES
from ._types import OAuthConfig, OAuthTokens, DEFAULT_OAUTH_BETAS, DEFAULT_USER_AGENT
from ._auth import refresh_access_token, OAuthFlowError, OAuthState, build_authorization_url, parse_auth_code, exchange_code_for_tokens, open_browser
from ._token_storage import TokenStorage, load_tokens_from_env

class AnthropicOAuth(Anthropic):
    def __init__(
        self,
        *,
        oauth_tokens: OAuthTokens | None = None,
        oauth_config: OAuthConfig | None = None,
        token_storage: TokenStorage | None = None,
        betas: list[str] | None = None,
        user_agent: str | None = None,
        base_url: str | httpx.URL | None = None,
        timeout: float | Timeout | None | NotGiven = NOT_GIVEN,
        max_retries: int = DEFAULT_MAX_RETRIES,
        default_headers: Mapping[str, str] | None = None,
        default_query: Mapping[str, object] | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        # CRITICAL: pass auth_token="oauth" placeholder to bypass parent validation
        super().__init__(
            auth_token="oauth",
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            default_headers=default_headers,
            default_query=default_query,
            http_client=http_client,
        )
        self._oauth_tokens = oauth_tokens
        self._oauth_config = oauth_config or OAuthConfig()
        self._token_storage = token_storage
        self._oauth_betas = betas if betas is not None else list(DEFAULT_OAUTH_BETAS)
        self._oauth_user_agent = user_agent or DEFAULT_USER_AGENT
        self._token_lock = threading.Lock()

    @property
    @override
    def auth_headers(self) -> dict[str, str]:
        return {}  # Auth injected per-request in _prepare_options

    @override
    def _validate_headers(self, headers: Any, custom_headers: Any) -> None:
        return  # No-op, we handle auth ourselves

    @property
    @override
    def default_headers(self) -> dict[str, str | Omit]:
        headers = super().default_headers
        headers["anthropic-beta"] = ",".join(self._oauth_betas)
        headers["User-Agent"] = self._oauth_user_agent
        return headers

    @override
    def _prepare_options(self, options: FinalRequestOptions) -> FinalRequestOptions:
        # PATTERN from foundry.py:246-264
        headers: dict[str, str | Omit] = {**options.headers} if is_given(options.headers) else {}
        options = model_copy(options)
        options.headers = headers
        access_token = self._ensure_access_token()
        headers["Authorization"] = f"Bearer {access_token}"
        # Append ?beta=true to URL
        if "?" in options.url:
            options.url = f"{options.url}&beta=true"
        else:
            options.url = f"{options.url}?beta=true"
        return options

    def _ensure_access_token(self) -> str:
        # Double-check locking pattern
        tokens = self._oauth_tokens
        if tokens is not None and not tokens.is_expired:
            return tokens.access_token
        with self._token_lock:
            # Re-check after acquiring lock
            tokens = self._oauth_tokens
            if tokens is not None and not tokens.is_expired:
                return tokens.access_token
            if tokens is None or not tokens.refresh_token:
                raise OAuthFlowError("No valid OAuth tokens available. Run authorize_interactive() first.")
            new_tokens = refresh_access_token(tokens.refresh_token, self._oauth_config)
            self._oauth_tokens = new_tokens
            if self._token_storage is not None:
                self._token_storage.save(new_tokens)
            return new_tokens.access_token

    @override
    def copy(self, *, ..., _extra_kwargs: Mapping[str, Any] = {}) -> Self:
        # FOLLOW foundry.py:195-231 pattern
        return super().copy(
            ...,
            _extra_kwargs={
                "oauth_tokens": ... or self._oauth_tokens,
                "oauth_config": ... or self._oauth_config,
                "token_storage": ... or self._token_storage,
                "betas": ... or self._oauth_betas,
                "user_agent": ... or self._oauth_user_agent,
                **_extra_kwargs,
            },
        )

    with_options = copy

    # Class methods: from_env, from_storage, authorize_interactive
    @classmethod
    def from_env(cls, **kwargs: Any) -> AnthropicOAuth:
        tokens = load_tokens_from_env()
        return cls(oauth_tokens=tokens, **kwargs)

    @classmethod
    def from_storage(cls, storage_path: str | None = None, **kwargs: Any) -> AnthropicOAuth:
        storage = TokenStorage(storage_path)
        tokens = storage.load()
        return cls(oauth_tokens=tokens, token_storage=storage, **kwargs)

    @staticmethod
    def authorize_interactive(config: OAuthConfig | None = None) -> OAuthTokens:
        url, oauth_state = build_authorization_url(config)
        open_browser(url)
        raw = input("Enter the code#state from the browser: ")
        code, state = parse_auth_code(raw)
        return exchange_code_for_tokens(code, state, oauth_state, config)

# AsyncAnthropicOAuth(AsyncAnthropic) follows same pattern with:
# - async _prepare_options()
# - async _ensure_access_token() using asyncio.Lock and async_refresh_access_token()
```

### Integration Points
```yaml
EXPORTS:
  - add to: src/anthropic/__init__.py
  - pattern: "from .lib.oauth import AnthropicOAuth as AnthropicOAuth, AsyncAnthropicOAuth as AsyncAnthropicOAuth"
  - location: after line 104 (Foundry import)

MODULE_INIT:
  - create: src/anthropic/lib/oauth/__init__.py
  - exports: AnthropicOAuth, AsyncAnthropicOAuth, OAuthConfig, OAuthTokens, AccountInfo, OrganizationInfo,
             OAuthState, OAuthFlowError, TokenStorage, TokenStorageError, load_tokens_from_env,
             build_authorization_url, exchange_code_for_tokens, refresh_access_token, parse_auth_code,
             open_browser, async_exchange_code_for_tokens, async_refresh_access_token, DEFAULT_OAUTH_BETAS

NO_NEW_DEPENDENCIES:
  - httpx: already required
  - hashlib, secrets, base64, webbrowser, json, threading, asyncio, time, os, pathlib, dataclasses: all stdlib
```

## Validation Loop

### Level 1: Syntax & Style
```bash
# Run these FIRST - fix any errors before proceeding
uv run ruff check src/anthropic/lib/oauth/ tests/lib/test_oauth.py --fix
uv run ruff format src/anthropic/lib/oauth/ tests/lib/test_oauth.py

# Expected: No errors. If errors, READ the error and fix.
```

### Level 2: Type Checking
```bash
# Run pyright on the new module
uv run pyright src/anthropic/lib/oauth/

# Expected: No errors. Common issues:
# - Missing type annotations on function params
# - Union types need to use | syntax with from __future__ import annotations
# - Ensure all imports from parent package use correct relative paths
```

### Level 3: Unit Tests
```python
# CREATE tests/lib/test_oauth.py following test_azure.py patterns

# Key test classes:

class TestOAuthTypes:
    def test_is_expired_true(self) -> None:
        tokens = OAuthTokens(access_token="x", refresh_token="y", expires_at=0.0)
        assert tokens.is_expired is True

    def test_is_expired_false(self) -> None:
        tokens = OAuthTokens(access_token="x", refresh_token="y", expires_at=time.time() + 3600)
        assert tokens.is_expired is False

    def test_from_token_response(self) -> None:
        data = {"access_token": "at", "refresh_token": "rt", "expires_in": 3600, "token_type": "bearer"}
        tokens = OAuthTokens.from_token_response(data)
        assert tokens.access_token == "at"
        assert tokens.refresh_token == "rt"
        assert not tokens.is_expired

class TestOAuthAuth:
    def test_generate_pkce(self) -> None:
        verifier, challenge = generate_pkce()
        assert len(verifier) > 0
        assert len(challenge) > 0
        assert verifier != challenge

    def test_build_authorization_url(self) -> None:
        url, state = build_authorization_url()
        assert "client_id=" in url
        assert "code_challenge=" in url
        assert state.code_verifier
        assert state.state

    def test_parse_auth_code_valid(self) -> None:
        code, state = parse_auth_code("mycode#mystate")
        assert code == "mycode"
        assert state == "mystate"

    def test_parse_auth_code_invalid(self) -> None:
        with pytest.raises(OAuthFlowError):
            parse_auth_code("no-hash-here")

    def test_exchange_code_for_tokens(self) -> None:
        # Use respx to mock the POST to token URL
        oauth_state = OAuthState(code_verifier="verifier", state="test-state")
        with respx.mock:
            respx.post(DEFAULT_TOKEN_URL).respond(json={
                "access_token": "new-at", "refresh_token": "new-rt",
                "expires_in": 3600, "token_type": "bearer"
            })
            tokens = exchange_code_for_tokens("code", "test-state", oauth_state)
            assert tokens.access_token == "new-at"

    def test_exchange_state_mismatch(self) -> None:
        oauth_state = OAuthState(code_verifier="v", state="correct")
        with pytest.raises(OAuthFlowError, match="State mismatch"):
            exchange_code_for_tokens("code", "wrong", oauth_state)

    def test_refresh_access_token(self) -> None:
        with respx.mock:
            respx.post(DEFAULT_TOKEN_URL).respond(json={
                "access_token": "refreshed", "refresh_token": "new-rt",
                "expires_in": 3600, "token_type": "bearer"
            })
            tokens = refresh_access_token("old-rt")
            assert tokens.access_token == "refreshed"

class TestTokenStorage:
    def test_save_load_roundtrip(self, tmp_path) -> None:
        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        storage.save(tokens)
        loaded = storage.load()
        assert loaded is not None
        assert loaded.access_token == "at"

    def test_load_missing_returns_none(self, tmp_path) -> None:
        storage = TokenStorage(str(tmp_path / "missing.json"))
        assert storage.load() is None

    def test_clear(self, tmp_path) -> None:
        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=0.0)
        storage.save(tokens)
        storage.clear()
        assert not storage.exists()

class TestLoadTokensFromEnv:
    def test_loads_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", "env-at")
        monkeypatch.setenv("ANTHROPIC_REFRESH_TOKEN", "env-rt")
        monkeypatch.setenv("ANTHROPIC_TOKEN_EXPIRES_AT", str(time.time() + 3600))
        tokens = load_tokens_from_env()
        assert tokens is not None
        assert tokens.access_token == "env-at"

    def test_returns_none_when_no_env(self, monkeypatch) -> None:
        monkeypatch.delenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_ACCESS_TOKEN", raising=False)
        tokens = load_tokens_from_env()
        assert tokens is None

class TestAnthropicOAuth:
    def test_initialization_with_tokens(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        assert client._oauth_tokens is tokens

    def test_auth_headers_empty(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        assert client.auth_headers == {}

    def test_default_headers_include_betas(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        headers = client.default_headers
        assert "anthropic-beta" in headers
        assert "oauth-2025-04-20" in str(headers["anthropic-beta"])

    def test_default_headers_user_agent(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        assert client.default_headers["User-Agent"] == DEFAULT_USER_AGENT

    def test_ensure_access_token_valid(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        assert client._ensure_access_token() == "at"

    def test_ensure_access_token_refreshes_expired(self) -> None:
        tokens = OAuthTokens(access_token="old", refresh_token="rt", expires_at=0.0)
        client = AnthropicOAuth(oauth_tokens=tokens)
        with respx.mock:
            respx.post(DEFAULT_TOKEN_URL).respond(json={
                "access_token": "new", "refresh_token": "new-rt",
                "expires_in": 3600, "token_type": "bearer"
            })
            result = client._ensure_access_token()
            assert result == "new"

    def test_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", "env-at")
        monkeypatch.setenv("ANTHROPIC_REFRESH_TOKEN", "env-rt")
        monkeypatch.setenv("ANTHROPIC_TOKEN_EXPIRES_AT", str(time.time() + 3600))
        client = AnthropicOAuth.from_env()
        assert client._oauth_tokens is not None
        assert client._oauth_tokens.access_token == "env-at"

    def test_copy_preserves_oauth_state(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        copied = client.copy()
        assert copied._oauth_tokens is not None
        assert copied._oauth_tokens.access_token == "at"

class TestAsyncAnthropicOAuth:
    async def test_initialization(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        assert client._oauth_tokens is tokens

    async def test_ensure_access_token_valid(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        result = await client._ensure_access_token()
        assert result == "at"
```

```bash
# Run and iterate until passing:
UV_PYTHON=">=3.9.0" uv run --isolated --all-extras pytest tests/lib/test_oauth.py -v
# If failing: Read error, understand root cause, fix code, re-run
```

### Level 4: Import Smoke Test
```bash
# Verify top-level import works
uv run python -c "from anthropic import AnthropicOAuth, AsyncAnthropicOAuth; print('OK')"
uv run python -c "from anthropic.lib.oauth import OAuthConfig, OAuthTokens, TokenStorage; print('OK')"
```

## Final Validation Checklist
- [ ] All tests pass: `UV_PYTHON=">=3.9.0" uv run --isolated --all-extras pytest tests/lib/test_oauth.py -v`
- [ ] No linting errors: `uv run ruff check src/anthropic/lib/oauth/ tests/lib/test_oauth.py`
- [ ] No type errors: `uv run pyright src/anthropic/lib/oauth/`
- [ ] Import check: `uv run python -c "from anthropic import AnthropicOAuth, AsyncAnthropicOAuth; print('OK')"`
- [ ] Error cases handled gracefully
- [ ] Token refresh works with expired tokens
- [ ] Thread-safe token refresh via locking
- [ ] File permissions set to 0600 for token storage

---

## Anti-Patterns to Avoid
- Do NOT create Pydantic models for internal types - use plain dataclasses
- Do NOT use `@pytest.mark.asyncio` - conftest.py auto-applies it
- Do NOT inherit from BaseFoundryClient - direct inheritance from Anthropic/AsyncAnthropic
- Do NOT skip the `auth_token="oauth"` placeholder - parent __init__ needs it to not auto-read env vars
- Do NOT use `model.model_copy()` directly - use `model_copy()` from `_compat`
- Do NOT catch broad exceptions - be specific (httpx.HTTPStatusError, etc.)
- Do NOT hardcode the token URL in multiple places - use DEFAULT_TOKEN_URL constant
- Do NOT forget `from __future__ import annotations` in every new file
- Do NOT import from `asyncio` at module level in sync-only code - use conditional imports or import in methods

---

## Confidence Score: 9/10

High confidence because:
- Clear patterns to follow from Foundry (primary) and Vertex (secondary)
- All dependencies are already available (httpx, respx, stdlib)
- Test patterns well-established in test_azure.py
- No external API calls needed for tests (all mocked)
- Simple dataclass-based types, no complex serialization

Minor risk:
- asyncio.Lock usage in AsyncAnthropicOAuth needs careful handling (must be created per-instance, not at class level)
- Pyright strictness may flag some patterns that need type: ignore comments
