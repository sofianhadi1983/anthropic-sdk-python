from __future__ import annotations

import time
import base64
import hashlib
from pathlib import Path

import respx
import pytest

from anthropic._models import FinalRequestOptions
from anthropic.lib.oauth import (
    OAuthState,
    OAuthConfig,
    OAuthTokens,
    TokenStorage,
    AnthropicOAuth,
    OAuthFlowError,
    AsyncAnthropicOAuth,
    generate_pkce,
    parse_auth_code,
    load_tokens_from_env,
    refresh_access_token,
    build_authorization_url,
    exchange_code_for_tokens,
)
from anthropic.lib.oauth._types import DEFAULT_TOKEN_URL, DEFAULT_USER_AGENT, DEFAULT_SYSTEM_PROMPT
from anthropic.lib.oauth._client import _inject_system_prompt


class TestOAuthTypes:
    def test_is_expired_true(self) -> None:
        tokens = OAuthTokens(access_token="x", refresh_token="y", expires_at=0.0)
        assert tokens.is_expired is True

    def test_is_expired_false(self) -> None:
        tokens = OAuthTokens(access_token="x", refresh_token="y", expires_at=time.time() + 3600)
        assert tokens.is_expired is False

    def test_is_expired_within_buffer(self) -> None:
        tokens = OAuthTokens(access_token="x", refresh_token="y", expires_at=time.time() + 100)
        assert tokens.is_expired is True

    def test_from_token_response_basic(self) -> None:
        data: dict[str, object] = {
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
            "token_type": "bearer",
        }
        tokens = OAuthTokens.from_token_response(data)
        assert tokens.access_token == "at"
        assert tokens.refresh_token == "rt"
        assert tokens.token_type == "bearer"
        assert not tokens.is_expired

    def test_from_token_response_with_org_and_account(self) -> None:
        data: dict[str, object] = {
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
            "token_type": "bearer",
            "scope": "user:profile",
            "organization": {"uuid": "org-123", "name": "My Org"},
            "account": {"uuid": "acct-456", "email_address": "test@example.com"},
        }
        tokens = OAuthTokens.from_token_response(data)
        assert tokens.organization is not None
        assert tokens.organization.uuid == "org-123"
        assert tokens.organization.name == "My Org"
        assert tokens.account is not None
        assert tokens.account.uuid == "acct-456"
        assert tokens.account.email_address == "test@example.com"
        assert tokens.scope == "user:profile"


class TestOAuthAuth:
    def test_generate_pkce(self) -> None:
        verifier, challenge = generate_pkce()
        assert len(verifier) > 0
        assert len(challenge) > 0
        assert verifier != challenge
        expected_challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        assert challenge == expected_challenge

    def test_generate_pkce_unique(self) -> None:
        v1, c1 = generate_pkce()
        v2, c2 = generate_pkce()
        assert v1 != v2
        assert c1 != c2

    def test_build_authorization_url(self) -> None:
        url, state = build_authorization_url()
        assert "client_id=" in url
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url
        assert "response_type=code" in url
        assert "redirect_uri=" in url
        assert "scope=" in url
        assert "state=" in url
        assert state.code_verifier
        assert state.state

    def test_build_authorization_url_custom_config(self) -> None:
        config = OAuthConfig(client_id="custom-id", scopes="custom:scope")
        url, state = build_authorization_url(config)
        assert "client_id=custom-id" in url
        assert "scope=custom" in url
        assert state.code_verifier
        assert state.state

    def test_parse_auth_code_valid(self) -> None:
        code, state = parse_auth_code("mycode#mystate")
        assert code == "mycode"
        assert state == "mystate"

    def test_parse_auth_code_with_hash_in_code(self) -> None:
        code, state = parse_auth_code("my#code#mystate")
        assert code == "my"
        assert state == "code#mystate"

    def test_parse_auth_code_no_hash(self) -> None:
        with pytest.raises(OAuthFlowError, match="Invalid auth code format"):
            parse_auth_code("no-hash-here")

    def test_parse_auth_code_empty_code(self) -> None:
        with pytest.raises(OAuthFlowError, match="Both code and state are required"):
            parse_auth_code("#mystate")

    def test_parse_auth_code_empty_state(self) -> None:
        with pytest.raises(OAuthFlowError, match="Both code and state are required"):
            parse_auth_code("mycode#")

    def test_exchange_code_for_tokens(self) -> None:
        oauth_state = OAuthState(code_verifier="verifier", state="test-state")
        with respx.mock:
            respx.post(DEFAULT_TOKEN_URL).respond(
                json={
                    "access_token": "new-at",
                    "refresh_token": "new-rt",
                    "expires_in": 3600,
                    "token_type": "bearer",
                }
            )
            tokens = exchange_code_for_tokens("code", "test-state", oauth_state)
            assert tokens.access_token == "new-at"
            assert tokens.refresh_token == "new-rt"

    def test_exchange_state_mismatch(self) -> None:
        oauth_state = OAuthState(code_verifier="v", state="correct")
        with pytest.raises(OAuthFlowError, match="State mismatch"):
            exchange_code_for_tokens("code", "wrong", oauth_state)

    def test_refresh_access_token(self) -> None:
        with respx.mock:
            respx.post(DEFAULT_TOKEN_URL).respond(
                json={
                    "access_token": "refreshed",
                    "refresh_token": "new-rt",
                    "expires_in": 3600,
                    "token_type": "bearer",
                }
            )
            tokens = refresh_access_token("old-rt")
            assert tokens.access_token == "refreshed"
            assert tokens.refresh_token == "new-rt"


class TestTokenStorage:
    def test_save_load_roundtrip(self, tmp_path: Path) -> None:
        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        storage.save(tokens)
        loaded = storage.load()
        assert loaded is not None
        assert loaded.access_token == "at"
        assert loaded.refresh_token == "rt"

    def test_save_load_with_org_and_account(self, tmp_path: Path) -> None:
        from anthropic.lib.oauth import AccountInfo, OrganizationInfo

        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(
            access_token="at",
            refresh_token="rt",
            expires_at=time.time() + 3600,
            organization=OrganizationInfo(uuid="org-1", name="Test Org"),
            account=AccountInfo(uuid="acct-1", email_address="test@test.com"),
        )
        storage.save(tokens)
        loaded = storage.load()
        assert loaded is not None
        assert loaded.organization is not None
        assert loaded.organization.uuid == "org-1"
        assert loaded.account is not None
        assert loaded.account.email_address == "test@test.com"

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        storage = TokenStorage(str(tmp_path / "missing.json"))
        assert storage.load() is None

    def test_clear(self, tmp_path: Path) -> None:
        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=0.0)
        storage.save(tokens)
        assert storage.exists()
        storage.clear()
        assert not storage.exists()

    def test_exists(self, tmp_path: Path) -> None:
        storage = TokenStorage(str(tmp_path / "tokens.json"))
        assert not storage.exists()
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=0.0)
        storage.save(tokens)
        assert storage.exists()

    def test_file_permissions(self, tmp_path: Path) -> None:
        import os
        import stat

        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=0.0)
        storage.save(tokens)
        mode = os.stat(tmp_path / "tokens.json").st_mode
        assert stat.S_IMODE(mode) == 0o600


class TestLoadTokensFromEnv:
    def test_loads_from_oauth_access_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", "env-at")
        monkeypatch.setenv("ANTHROPIC_REFRESH_TOKEN", "env-rt")
        monkeypatch.setenv("ANTHROPIC_TOKEN_EXPIRES_AT", str(time.time() + 3600))
        tokens = load_tokens_from_env()
        assert tokens is not None
        assert tokens.access_token == "env-at"
        assert tokens.refresh_token == "env-rt"

    def test_loads_from_access_token_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", raising=False)
        monkeypatch.setenv("ANTHROPIC_ACCESS_TOKEN", "fallback-at")
        tokens = load_tokens_from_env()
        assert tokens is not None
        assert tokens.access_token == "fallback-at"

    def test_returns_none_when_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_ACCESS_TOKEN", raising=False)
        tokens = load_tokens_from_env()
        assert tokens is None

    def test_defaults_expires_at_to_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", "at")
        monkeypatch.delenv("ANTHROPIC_TOKEN_EXPIRES_AT", raising=False)
        tokens = load_tokens_from_env()
        assert tokens is not None
        assert tokens.expires_at == 0.0


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
        beta_value = str(headers["anthropic-beta"])
        assert "oauth-2025-04-20" in beta_value

    def test_default_headers_user_agent(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        assert client.default_headers["User-Agent"] == DEFAULT_USER_AGENT

    def test_custom_user_agent(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens, user_agent="custom-agent/1.0")
        assert client.default_headers["User-Agent"] == "custom-agent/1.0"

    def test_ensure_access_token_valid(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        assert client._ensure_access_token() == "at"

    def test_ensure_access_token_refreshes_expired(self) -> None:
        tokens = OAuthTokens(access_token="old", refresh_token="rt", expires_at=0.0)
        client = AnthropicOAuth(oauth_tokens=tokens)
        with respx.mock:
            respx.post(DEFAULT_TOKEN_URL).respond(
                json={
                    "access_token": "new",
                    "refresh_token": "new-rt",
                    "expires_in": 3600,
                    "token_type": "bearer",
                }
            )
            result = client._ensure_access_token()
            assert result == "new"
            assert client._oauth_tokens is not None
            assert client._oauth_tokens.access_token == "new"

    def test_ensure_access_token_no_tokens_raises(self) -> None:
        client = AnthropicOAuth()
        with pytest.raises(OAuthFlowError, match="No valid OAuth tokens"):
            client._ensure_access_token()

    def test_ensure_access_token_persists_to_storage(self, tmp_path: Path) -> None:
        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(access_token="old", refresh_token="rt", expires_at=0.0)
        client = AnthropicOAuth(oauth_tokens=tokens, token_storage=storage)
        with respx.mock:
            respx.post(DEFAULT_TOKEN_URL).respond(
                json={
                    "access_token": "refreshed",
                    "refresh_token": "new-rt",
                    "expires_in": 3600,
                    "token_type": "bearer",
                }
            )
            client._ensure_access_token()
        loaded = storage.load()
        assert loaded is not None
        assert loaded.access_token == "refreshed"

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", "env-at")
        monkeypatch.setenv("ANTHROPIC_REFRESH_TOKEN", "env-rt")
        monkeypatch.setenv("ANTHROPIC_TOKEN_EXPIRES_AT", str(time.time() + 3600))
        client = AnthropicOAuth.from_env()
        assert client._oauth_tokens is not None
        assert client._oauth_tokens.access_token == "env-at"

    def test_from_storage(self, tmp_path: Path) -> None:
        storage = TokenStorage(str(tmp_path / "tokens.json"))
        tokens = OAuthTokens(access_token="stored-at", refresh_token="rt", expires_at=time.time() + 3600)
        storage.save(tokens)
        client = AnthropicOAuth.from_storage(storage_path=str(tmp_path / "tokens.json"))
        assert client._oauth_tokens is not None
        assert client._oauth_tokens.access_token == "stored-at"
        assert client._token_storage is not None

    def test_copy_preserves_oauth_state(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens, user_agent="my-agent/1.0")
        copied = client.copy()
        assert copied._oauth_tokens is not None
        assert copied._oauth_tokens.access_token == "at"
        assert copied._oauth_user_agent == "my-agent/1.0"

    def test_oauth_tokens_property(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        assert client.oauth_tokens is tokens

    def test_oauth_config_property(self) -> None:
        config = OAuthConfig(client_id="custom")
        client = AnthropicOAuth(oauth_config=config)
        assert client.oauth_config.client_id == "custom"

    def test_base_url_default(self) -> None:
        client = AnthropicOAuth()
        assert "api.anthropic.com" in str(client.base_url)


class TestSystemPromptInjection:
    def test_inject_when_system_absent(self) -> None:
        options = FinalRequestOptions(
            method="post",
            url="/v1/messages",
            json_data={"messages": [{"role": "user", "content": "hello"}], "model": "claude-sonnet-4-20250514"},
        )
        _inject_system_prompt(options)
        assert isinstance(options.json_data, dict)
        system = options.json_data["system"]
        assert isinstance(system, list)
        assert len(system) == 1
        assert system[0]["type"] == "text"
        assert system[0]["text"] == DEFAULT_SYSTEM_PROMPT

    def test_inject_when_system_is_string(self) -> None:
        options = FinalRequestOptions(
            method="post",
            url="/v1/messages",
            json_data={
                "messages": [{"role": "user", "content": "hello"}],
                "model": "claude-sonnet-4-20250514",
                "system": "You are a helpful assistant.",
            },
        )
        _inject_system_prompt(options)
        assert isinstance(options.json_data, dict)
        system = options.json_data["system"]
        assert isinstance(system, list)
        assert len(system) == 2
        assert system[0]["text"] == DEFAULT_SYSTEM_PROMPT
        assert system[1]["text"] == "You are a helpful assistant."

    def test_inject_when_system_is_list(self) -> None:
        existing_blocks = [
            {"type": "text", "text": "Block 1"},
            {"type": "text", "text": "Block 2"},
        ]
        options = FinalRequestOptions(
            method="post",
            url="/v1/messages",
            json_data={
                "messages": [{"role": "user", "content": "hello"}],
                "model": "claude-sonnet-4-20250514",
                "system": existing_blocks,
            },
        )
        _inject_system_prompt(options)
        assert isinstance(options.json_data, dict)
        system = options.json_data["system"]
        assert isinstance(system, list)
        assert len(system) == 3
        assert system[0]["text"] == DEFAULT_SYSTEM_PROMPT
        assert system[1]["text"] == "Block 1"
        assert system[2]["text"] == "Block 2"

    def test_no_inject_when_json_data_is_none(self) -> None:
        options = FinalRequestOptions(method="get", url="/v1/models")
        _inject_system_prompt(options)
        assert options.json_data is None

    def test_no_inject_when_no_messages_key(self) -> None:
        options = FinalRequestOptions(
            method="post",
            url="/v1/messages/batches",
            json_data={"requests": []},
        )
        _inject_system_prompt(options)
        assert isinstance(options.json_data, dict)
        assert "system" not in options.json_data

    def test_does_not_mutate_original_json_data(self) -> None:
        original_json: dict[str, object] = {
            "messages": [{"role": "user", "content": "hello"}],
            "model": "claude-sonnet-4-20250514",
        }
        options = FinalRequestOptions(method="post", url="/v1/messages", json_data=original_json)
        _inject_system_prompt(options)
        assert "system" not in original_json
        assert isinstance(options.json_data, dict)
        assert "system" in options.json_data

    def test_inject_includes_cache_control(self) -> None:
        options = FinalRequestOptions(
            method="post",
            url="/v1/messages",
            json_data={"messages": [{"role": "user", "content": "hello"}], "model": "claude-sonnet-4-20250514"},
        )
        _inject_system_prompt(options)
        assert isinstance(options.json_data, dict)
        system = options.json_data["system"]
        assert isinstance(system, list)
        assert system[0]["cache_control"] == {"type": "ephemeral"}

    def test_inject_via_sync_prepare_options(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AnthropicOAuth(oauth_tokens=tokens)
        options = FinalRequestOptions(
            method="post",
            url="/v1/messages",
            json_data={
                "messages": [{"role": "user", "content": "hello"}],
                "model": "claude-sonnet-4-20250514",
            },
        )
        result = client._prepare_options(options)
        assert isinstance(result.json_data, dict)
        system = result.json_data["system"]
        assert isinstance(system, list)
        assert system[0]["text"] == DEFAULT_SYSTEM_PROMPT

    async def test_inject_via_async_prepare_options(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        options = FinalRequestOptions(
            method="post",
            url="/v1/messages",
            json_data={
                "messages": [{"role": "user", "content": "hello"}],
                "model": "claude-sonnet-4-20250514",
            },
        )
        result = await client._prepare_options(options)
        assert isinstance(result.json_data, dict)
        system = result.json_data["system"]
        assert isinstance(system, list)
        assert system[0]["text"] == DEFAULT_SYSTEM_PROMPT


class TestAsyncAnthropicOAuth:
    async def test_initialization(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        assert client._oauth_tokens is tokens

    async def test_auth_headers_empty(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        assert client.auth_headers == {}

    async def test_default_headers_include_betas(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        headers = client.default_headers
        assert "anthropic-beta" in headers
        beta_value = str(headers["anthropic-beta"])
        assert "oauth-2025-04-20" in beta_value

    async def test_ensure_access_token_valid(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        result = await client._ensure_access_token()
        assert result == "at"

    async def test_ensure_access_token_no_tokens_raises(self) -> None:
        client = AsyncAnthropicOAuth()
        with pytest.raises(OAuthFlowError, match="No valid OAuth tokens"):
            await client._ensure_access_token()

    async def test_copy_preserves_oauth_state(self) -> None:
        tokens = OAuthTokens(access_token="at", refresh_token="rt", expires_at=time.time() + 3600)
        client = AsyncAnthropicOAuth(oauth_tokens=tokens)
        copied = client.copy()
        assert copied._oauth_tokens is not None
        assert copied._oauth_tokens.access_token == "at"

    async def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_OAUTH_ACCESS_TOKEN", "env-at")
        monkeypatch.setenv("ANTHROPIC_REFRESH_TOKEN", "env-rt")
        monkeypatch.setenv("ANTHROPIC_TOKEN_EXPIRES_AT", str(time.time() + 3600))
        client = AsyncAnthropicOAuth.from_env()
        assert client._oauth_tokens is not None
        assert client._oauth_tokens.access_token == "env-at"
