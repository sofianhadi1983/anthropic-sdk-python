# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "anthropic",
# ]
#
# [tool.uv.sources]
# anthropic = { path = "../", editable = true }
# ///

"""Manual OAuth flow — step-by-step control over each phase.

Useful when you need to:
- Embed the flow in a custom UI
- Use a custom redirect URI or scopes
- Handle the authorization callback programmatically
"""

from anthropic.lib.oauth import (
    TokenStorage,
    AnthropicOAuth,
    open_browser,
    parse_auth_code,
    build_authorization_url,
    exchange_code_for_tokens,
)

# Step 1: Build the authorization URL
url, oauth_state = build_authorization_url()

print("Authorization URL:\n")
print(url)
print()

# Step 2: Open the browser
open_browser(url)

# Step 3: User authorizes and gets redirected — paste "code#state" back
raw = input("Paste the code#state from the browser: ")
code, state = parse_auth_code(raw)

# Step 4: Exchange authorization code for tokens
tokens = exchange_code_for_tokens(code, state, oauth_state)

print(f"\nAccess token: {tokens.access_token[:20]}...")
print(f"Refresh token: {tokens.refresh_token[:20]}...")
print(f"Expires at: {tokens.expires_at}")
if tokens.account:
    print(f"Account: {tokens.account.email_address}")
if tokens.organization:
    print(f"Organization: {tokens.organization.name}")

# Step 5: Save tokens
storage = TokenStorage()
storage.save(tokens)
print(f"\nTokens saved to {storage._path}")

# Step 6: Create client and make an API call
client = AnthropicOAuth(oauth_tokens=tokens, token_storage=storage)

response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=256,
    messages=[
        {"role": "user", "content": "Hello! Confirm this OAuth flow is working."},
    ],
)

print(f"\nResponse: {response.content[0].text}")
