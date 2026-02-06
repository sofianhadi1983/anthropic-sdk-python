# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "anthropic",
# ]
#
# [tool.uv.sources]
# anthropic = { path = "../", editable = true }
# ///

"""Async OAuth authentication example with streaming responses."""

import asyncio

from anthropic.lib.oauth import TokenStorage, AsyncAnthropicOAuth


async def main() -> None:
    storage = TokenStorage()

    if storage.exists():
        print("Loading saved OAuth tokens...")
        client = AsyncAnthropicOAuth.from_storage()
    else:
        print("No saved tokens found. Starting OAuth authorization flow...\n")
        tokens = AsyncAnthropicOAuth.authorize_interactive()

        storage.save(tokens)
        print("Tokens saved.\n")

        client = AsyncAnthropicOAuth(oauth_tokens=tokens, token_storage=storage)

    # Make a streaming API call
    async with client.messages.stream(
        model="claude-sonnet-4-5-20250929",
        max_tokens=256,
        messages=[
            {"role": "user", "content": "Hello from async! What can you help me with?"},
        ],
    ) as stream:
        async for event in stream:
            if event.type == "text":
                print(event.text, end="", flush=True)
        print()


asyncio.run(main())
