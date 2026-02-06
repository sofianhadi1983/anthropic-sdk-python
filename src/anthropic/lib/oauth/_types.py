from __future__ import annotations

import time
import dataclasses
from typing import Any, Dict, cast

DEFAULT_OAUTH_BETAS: list[str] = [
    "oauth-2025-04-20",
    "interleaved-thinking-2025-05-14",
    "claude-code-20250219",
    "fine-grained-tool-streaming-2025-05-14",
]
DEFAULT_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
DEFAULT_REDIRECT_URI = "https://platform.claude.com/oauth/code/callback"
DEFAULT_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
DEFAULT_AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
DEFAULT_SCOPES = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers"
DEFAULT_USER_AGENT = "claude-cli/2.1.2 (external, cli)"
DEFAULT_SYSTEM_PROMPT = "You are Claude Code, Anthropic's official CLI for Claude."
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
        expires_in = data.get("expires_in", 3600)
        expires_at = time.time() + int(str(expires_in))

        org_data = data.get("organization")
        org: OrganizationInfo | None = None
        if isinstance(org_data, dict):
            org_dict = cast(Dict[str, Any], org_data)
            org = OrganizationInfo(uuid=str(org_dict["uuid"]), name=str(org_dict["name"]))

        acct_data = data.get("account")
        acct: AccountInfo | None = None
        if isinstance(acct_data, dict):
            acct_dict = cast(Dict[str, Any], acct_data)
            acct = AccountInfo(uuid=str(acct_dict["uuid"]), email_address=str(acct_dict["email_address"]))

        return cls(
            access_token=str(data["access_token"]),
            refresh_token=str(data.get("refresh_token", "")),
            expires_at=expires_at,
            token_type=str(data.get("token_type", "bearer")),
            scope=str(data.get("scope", "")),
            organization=org,
            account=acct,
        )
