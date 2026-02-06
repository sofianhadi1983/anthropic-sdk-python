from __future__ import annotations

import asyncio
import threading
from typing import Any, Mapping
from typing_extensions import Self, override

import httpx

from ._auth import (
    OAuthFlowError,
    open_browser,
    parse_auth_code,
    refresh_access_token,
    build_authorization_url,
    exchange_code_for_tokens,
    async_refresh_access_token,
)
from ._types import DEFAULT_USER_AGENT, DEFAULT_OAUTH_BETAS, DEFAULT_SYSTEM_PROMPT, OAuthConfig, OAuthTokens
from ..._types import NOT_GIVEN, Omit, Timeout, NotGiven
from ..._utils import is_dict, is_given
from ..._client import Anthropic, AsyncAnthropic
from ..._compat import model_copy
from ..._models import FinalRequestOptions
from ..._base_client import DEFAULT_MAX_RETRIES
from ._token_storage import TokenStorage, load_tokens_from_env


def _inject_system_prompt(options: FinalRequestOptions) -> None:
    """Inject mandatory Claude Code system prompt into Messages API requests.

    OAuth tokens with ``user:sessions:claude_code`` scope require this.
    """
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
        json_data["system"] = [
            claude_code_block,
            {"type": "text", "text": existing_system},
        ]
    elif isinstance(existing_system, list):
        json_data["system"] = [claude_code_block, *existing_system]


class AnthropicOAuth(Anthropic):
    _oauth_tokens: OAuthTokens | None
    _oauth_config: OAuthConfig
    _token_storage: TokenStorage | None
    _oauth_betas: list[str]
    _oauth_user_agent: str

    def __init__(
        self,
        *,
        oauth_tokens: OAuthTokens | None = None,
        oauth_config: OAuthConfig | None = None,
        token_storage: TokenStorage | None = None,
        betas: list[str] | None = None,
        user_agent: str | None = None,
        api_key: str | None = None,  # noqa: ARG002
        auth_token: str | None = None,  # noqa: ARG002
        base_url: str | httpx.URL | None = None,
        timeout: float | Timeout | None | NotGiven = NOT_GIVEN,
        max_retries: int = DEFAULT_MAX_RETRIES,
        default_headers: Mapping[str, str] | None = None,
        default_query: Mapping[str, object] | None = None,
        http_client: httpx.Client | None = None,
        _strict_response_validation: bool = False,
    ) -> None:
        super().__init__(
            auth_token="oauth",
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            default_headers=default_headers,
            default_query=default_query,
            http_client=http_client,
            _strict_response_validation=_strict_response_validation,
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
        return {}

    @override
    def _validate_headers(self, headers: Any, custom_headers: Any) -> None:  # type: ignore[override]
        return

    @property
    @override
    def default_headers(self) -> dict[str, str | Omit]:
        headers = {**super().default_headers}
        headers["anthropic-beta"] = ",".join(self._oauth_betas)
        headers["User-Agent"] = self._oauth_user_agent
        return headers

    @override
    def _prepare_options(self, options: FinalRequestOptions) -> FinalRequestOptions:
        headers: dict[str, str | Omit] = {**options.headers} if is_given(options.headers) else {}

        options = model_copy(options)
        options.headers = headers
        _inject_system_prompt(options)

        access_token = self._ensure_access_token()
        headers["Authorization"] = f"Bearer {access_token}"

        if "?" in options.url:
            options.url = f"{options.url}&beta=true"
        else:
            options.url = f"{options.url}?beta=true"

        return options

    def _ensure_access_token(self) -> str:
        tokens = self._oauth_tokens
        if tokens is not None and not tokens.is_expired:
            return tokens.access_token

        with self._token_lock:
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

    @property
    def oauth_tokens(self) -> OAuthTokens | None:
        return self._oauth_tokens

    @property
    def oauth_config(self) -> OAuthConfig:
        return self._oauth_config

    @override
    def copy(
        self,
        *,
        oauth_tokens: OAuthTokens | None = None,
        oauth_config: OAuthConfig | None = None,
        token_storage: TokenStorage | None = None,
        betas: list[str] | None = None,
        user_agent: str | None = None,
        api_key: str | None = None,
        auth_token: str | None = None,
        base_url: str | httpx.URL | None = None,
        timeout: float | Timeout | None | NotGiven = NOT_GIVEN,
        http_client: httpx.Client | None = None,
        max_retries: int | NotGiven = NOT_GIVEN,
        default_headers: Mapping[str, str] | None = None,
        set_default_headers: Mapping[str, str] | None = None,
        default_query: Mapping[str, object] | None = None,
        set_default_query: Mapping[str, object] | None = None,
        _extra_kwargs: Mapping[str, Any] = {},
    ) -> Self:
        return super().copy(
            api_key=api_key,
            auth_token=auth_token,
            base_url=base_url,
            timeout=timeout,
            http_client=http_client,
            max_retries=max_retries,
            default_headers=default_headers,
            set_default_headers=set_default_headers,
            default_query=default_query,
            set_default_query=set_default_query,
            _extra_kwargs={
                "oauth_tokens": oauth_tokens or self._oauth_tokens,
                "oauth_config": oauth_config or self._oauth_config,
                "token_storage": token_storage or self._token_storage,
                "betas": betas or self._oauth_betas,
                "user_agent": user_agent or self._oauth_user_agent,
                **_extra_kwargs,
            },
        )

    with_options = copy

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


class AsyncAnthropicOAuth(AsyncAnthropic):
    _oauth_tokens: OAuthTokens | None
    _oauth_config: OAuthConfig
    _token_storage: TokenStorage | None
    _oauth_betas: list[str]
    _oauth_user_agent: str

    def __init__(
        self,
        *,
        oauth_tokens: OAuthTokens | None = None,
        oauth_config: OAuthConfig | None = None,
        token_storage: TokenStorage | None = None,
        betas: list[str] | None = None,
        user_agent: str | None = None,
        api_key: str | None = None,  # noqa: ARG002
        auth_token: str | None = None,  # noqa: ARG002
        base_url: str | httpx.URL | None = None,
        timeout: float | Timeout | None | NotGiven = NOT_GIVEN,
        max_retries: int = DEFAULT_MAX_RETRIES,
        default_headers: Mapping[str, str] | None = None,
        default_query: Mapping[str, object] | None = None,
        http_client: httpx.AsyncClient | None = None,
        _strict_response_validation: bool = False,
    ) -> None:
        super().__init__(
            auth_token="oauth",
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            default_headers=default_headers,
            default_query=default_query,
            http_client=http_client,
            _strict_response_validation=_strict_response_validation,
        )
        self._oauth_tokens = oauth_tokens
        self._oauth_config = oauth_config or OAuthConfig()
        self._token_storage = token_storage
        self._oauth_betas = betas if betas is not None else list(DEFAULT_OAUTH_BETAS)
        self._oauth_user_agent = user_agent or DEFAULT_USER_AGENT
        self._token_lock: asyncio.Lock | None = None

    def _get_token_lock(self) -> asyncio.Lock:
        if self._token_lock is None:
            self._token_lock = asyncio.Lock()
        return self._token_lock

    @property
    @override
    def auth_headers(self) -> dict[str, str]:
        return {}

    @override
    def _validate_headers(self, headers: Any, custom_headers: Any) -> None:  # type: ignore[override]
        return

    @property
    @override
    def default_headers(self) -> dict[str, str | Omit]:
        headers = {**super().default_headers}
        headers["anthropic-beta"] = ",".join(self._oauth_betas)
        headers["User-Agent"] = self._oauth_user_agent
        return headers

    @override
    async def _prepare_options(self, options: FinalRequestOptions) -> FinalRequestOptions:
        headers: dict[str, str | Omit] = {**options.headers} if is_given(options.headers) else {}

        options = model_copy(options)
        options.headers = headers
        _inject_system_prompt(options)

        access_token = await self._ensure_access_token()
        headers["Authorization"] = f"Bearer {access_token}"

        if "?" in options.url:
            options.url = f"{options.url}&beta=true"
        else:
            options.url = f"{options.url}?beta=true"

        return options

    async def _ensure_access_token(self) -> str:
        tokens = self._oauth_tokens
        if tokens is not None and not tokens.is_expired:
            return tokens.access_token

        async with self._get_token_lock():
            tokens = self._oauth_tokens
            if tokens is not None and not tokens.is_expired:
                return tokens.access_token

            if tokens is None or not tokens.refresh_token:
                raise OAuthFlowError("No valid OAuth tokens available. Run authorize_interactive() first.")

            new_tokens = await async_refresh_access_token(tokens.refresh_token, self._oauth_config)
            self._oauth_tokens = new_tokens
            if self._token_storage is not None:
                self._token_storage.save(new_tokens)
            return new_tokens.access_token

    @property
    def oauth_tokens(self) -> OAuthTokens | None:
        return self._oauth_tokens

    @property
    def oauth_config(self) -> OAuthConfig:
        return self._oauth_config

    @override
    def copy(
        self,
        *,
        oauth_tokens: OAuthTokens | None = None,
        oauth_config: OAuthConfig | None = None,
        token_storage: TokenStorage | None = None,
        betas: list[str] | None = None,
        user_agent: str | None = None,
        api_key: str | None = None,
        auth_token: str | None = None,
        base_url: str | httpx.URL | None = None,
        timeout: float | Timeout | None | NotGiven = NOT_GIVEN,
        http_client: httpx.AsyncClient | None = None,
        max_retries: int | NotGiven = NOT_GIVEN,
        default_headers: Mapping[str, str] | None = None,
        set_default_headers: Mapping[str, str] | None = None,
        default_query: Mapping[str, object] | None = None,
        set_default_query: Mapping[str, object] | None = None,
        _extra_kwargs: Mapping[str, Any] = {},
    ) -> Self:
        return super().copy(
            api_key=api_key,
            auth_token=auth_token,
            base_url=base_url,
            timeout=timeout,
            http_client=http_client,
            max_retries=max_retries,
            default_headers=default_headers,
            set_default_headers=set_default_headers,
            default_query=default_query,
            set_default_query=set_default_query,
            _extra_kwargs={
                "oauth_tokens": oauth_tokens or self._oauth_tokens,
                "oauth_config": oauth_config or self._oauth_config,
                "token_storage": token_storage or self._token_storage,
                "betas": betas or self._oauth_betas,
                "user_agent": user_agent or self._oauth_user_agent,
                **_extra_kwargs,
            },
        )

    with_options = copy

    @classmethod
    def from_env(cls, **kwargs: Any) -> AsyncAnthropicOAuth:
        tokens = load_tokens_from_env()
        return cls(oauth_tokens=tokens, **kwargs)

    @classmethod
    def from_storage(cls, storage_path: str | None = None, **kwargs: Any) -> AsyncAnthropicOAuth:
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
