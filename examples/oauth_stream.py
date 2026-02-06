# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "anthropic",
# ]
#
# [tool.uv.sources]
# anthropic = { path = "../", editable = true }
# ///

"""OAuth authentication example with streaming responses.

Same OAuth flow as oauth.py, but streams the API response token-by-token.

Usage:
    uv run examples/oauth_stream.py
"""

from anthropic.lib.oauth import TokenStorage, AnthropicOAuth

storage = TokenStorage()

if storage.exists():
    print("Loading saved OAuth tokens...")
    client = AnthropicOAuth.from_storage()
else:
    print("No saved tokens found. Starting OAuth authorization flow...\n")
    tokens = AnthropicOAuth.authorize_interactive()

    print(f"\nAuthorized successfully!")
    if tokens.account:
        print(f"  Account: {tokens.account.email_address}")
    if tokens.organization:
        print(f"  Organization: {tokens.organization.name}")

    storage.save(tokens)
    print(f"  Tokens saved to {storage._path}\n")

    client = AnthropicOAuth(oauth_tokens=tokens, token_storage=storage)

# Make a streaming API call
with client.messages.stream(
    model="claude-sonnet-4-5-20250929",
    max_tokens=256,
    messages=[
        {"role": "user", "content": "Hello! What can you help me with today?"},
    ],
) as stream:
    for event in stream:
        if event.type == "text":
            print(event.text, end="", flush=True)
    print()
