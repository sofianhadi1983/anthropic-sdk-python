from __future__ import annotations

import os
import json
import threading
from typing import Any, Dict, cast
from pathlib import Path

from ._types import AccountInfo, OAuthTokens, OrganizationInfo
from ..._exceptions import AnthropicError


class TokenStorageError(AnthropicError):
    pass


_DEFAULT_TOKEN_PATH = os.path.join(os.path.expanduser("~"), ".anthropic", "oauth_tokens.json")


class TokenStorage:
    """JSON file-based OAuth token persistence."""

    def __init__(self, path: str | None = None) -> None:
        self._path = Path(path or _DEFAULT_TOKEN_PATH)
        self._lock = threading.Lock()

    def save(self, tokens: OAuthTokens) -> None:
        """Save tokens to the JSON file with 0600 permissions."""
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                data: dict[str, object] = {
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token,
                    "expires_at": tokens.expires_at,
                    "token_type": tokens.token_type,
                    "scope": tokens.scope,
                }
                if tokens.organization is not None:
                    data["organization"] = {
                        "uuid": tokens.organization.uuid,
                        "name": tokens.organization.name,
                    }
                if tokens.account is not None:
                    data["account"] = {
                        "uuid": tokens.account.uuid,
                        "email_address": tokens.account.email_address,
                    }
                self._path.write_text(json.dumps(data, indent=2))
                os.chmod(self._path, 0o600)
            except OSError as e:
                raise TokenStorageError(f"Failed to save tokens: {e}") from e

    def load(self) -> OAuthTokens | None:
        """Load tokens from the JSON file. Returns None if the file doesn't exist."""
        with self._lock:
            if not self._path.exists():
                return None
            try:
                data = json.loads(self._path.read_text())
                org: OrganizationInfo | None = None
                org_data = data.get("organization")
                if isinstance(org_data, dict):
                    org_dict = cast(Dict[str, Any], org_data)
                    org = OrganizationInfo(uuid=str(org_dict["uuid"]), name=str(org_dict["name"]))

                acct: AccountInfo | None = None
                acct_data = data.get("account")
                if isinstance(acct_data, dict):
                    acct_dict = cast(Dict[str, Any], acct_data)
                    acct = AccountInfo(uuid=str(acct_dict["uuid"]), email_address=str(acct_dict["email_address"]))

                return OAuthTokens(
                    access_token=str(data["access_token"]),
                    refresh_token=str(data["refresh_token"]),
                    expires_at=float(data["expires_at"]),
                    token_type=str(data.get("token_type", "bearer")),
                    scope=str(data.get("scope", "")),
                    organization=org,
                    account=acct,
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
                raise TokenStorageError(f"Failed to load tokens: {e}") from e

    def clear(self) -> None:
        """Delete the token file."""
        with self._lock:
            try:
                if self._path.exists():
                    self._path.unlink()
            except OSError as e:
                raise TokenStorageError(f"Failed to clear tokens: {e}") from e

    def exists(self) -> bool:
        """Check if the token file exists."""
        return self._path.exists()


def load_tokens_from_env() -> OAuthTokens | None:
    """Load OAuth tokens from environment variables.

    Checks ANTHROPIC_OAUTH_ACCESS_TOKEN first, then ANTHROPIC_ACCESS_TOKEN.
    Also reads ANTHROPIC_REFRESH_TOKEN and ANTHROPIC_TOKEN_EXPIRES_AT.
    """
    access_token = os.environ.get("ANTHROPIC_OAUTH_ACCESS_TOKEN") or os.environ.get("ANTHROPIC_ACCESS_TOKEN")
    if not access_token:
        return None

    refresh_token = os.environ.get("ANTHROPIC_REFRESH_TOKEN", "")
    expires_at_str = os.environ.get("ANTHROPIC_TOKEN_EXPIRES_AT")
    expires_at = float(expires_at_str) if expires_at_str else 0.0

    return OAuthTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
    )
