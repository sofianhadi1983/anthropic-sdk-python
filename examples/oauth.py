# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "anthropic",
# ]
#
# [tool.uv.sources]
# anthropic = { path = "../", editable = true }
# ///

"""OAuth authentication example for the Anthropic Python SDK.

This script demonstrates the full OAuth flow:
1. Generate an authorization URL with PKCE
2. Open the browser for user authorization
3. Exchange the authorization code for tokens
4. Save tokens to disk
5. Make an API call using OAuth tokens
6. Subsequent runs load saved tokens automatically

Usage:
    # First run — starts the interactive OAuth flow
    uv run examples/oauth.py

    # Subsequent runs — loads saved tokens from ~/.anthropic/oauth_tokens.json
    uv run examples/oauth.py
"""

from anthropic.lib.oauth import TokenStorage, AnthropicOAuth

storage = TokenStorage()

if storage.exists():
    # Load saved tokens — auto-refreshes if expired
    print("Loading saved OAuth tokens...")
    client = AnthropicOAuth.from_storage()
else:
    # First-time: run the interactive browser-based OAuth flow
    print("No saved tokens found. Starting OAuth authorization flow...\n")
    tokens = AnthropicOAuth.authorize_interactive()

    print(f"\nAuthorized successfully!")
    if tokens.account:
        print(f"  Account: {tokens.account.email_address}")
    if tokens.organization:
        print(f"  Organization: {tokens.organization.name}")

    # Save tokens for next time
    storage.save(tokens)
    print(f"  Tokens saved to {storage._path}\n")

    client = AnthropicOAuth(oauth_tokens=tokens, token_storage=storage)

# Make an API call
response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=256,
    messages=[
        {"role": "user", "content": "Hello! What can you help me with today?"},
    ],
)

print(response.content[0].text)
