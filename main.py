import os
import json
import hashlib
import base64
import re
from typing import Optional
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = FastAPI()

# Environment variables
ENCRYPT_KEY = os.getenv("LARK_ENCRYPT_KEY", "")
VERIFICATION_TOKEN = os.getenv("LARK_VERIFICATION_TOKEN", "")

# X/Twitter API (optional - for richer previews)
X_BEARER_TOKEN = os.getenv("X_BEARER_TOKEN", "")


def decrypt_aes(encrypt_key: str, encrypted_data: str) -> dict:
    """
    Decrypt Lark's AES-256-CBC encrypted data.

    Encryption principle from Lark docs:
    1. SHA256 hash of encrypt_key to get the key
    2. PKCS7 padding
    3. First 16 bytes of decoded data is the IV
    4. Rest is the encrypted content
    """
    if not encrypt_key:
        raise ValueError("Encrypt key is not configured")

    # SHA256 hash of encrypt_key to get the actual key
    key = hashlib.sha256(encrypt_key.encode()).digest()

    # Base64 decode the encrypted data
    encrypted_bytes = base64.b64decode(encrypted_data)

    # First 16 bytes is IV, rest is encrypted content
    iv = encrypted_bytes[:16]
    encrypted_content = encrypted_bytes[16:]

    # Decrypt using AES-256-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_len = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_len]

    return json.loads(decrypted.decode("utf-8"))


def parse_request_body(body: dict) -> dict:
    """Parse request body, decrypting if necessary."""
    if "encrypt" in body:
        return decrypt_aes(ENCRYPT_KEY, body["encrypt"])
    return body


def extract_tweet_id(url: str) -> str | None:
    """Extract tweet ID from x.com or twitter.com URL."""
    # Match patterns like:
    # https://x.com/user/status/1234567890
    # https://twitter.com/user/status/1234567890
    pattern = r"(?:x\.com|twitter\.com)/\w+/status/(\d+)"
    match = re.search(pattern, url)
    return match.group(1) if match else None


async def fetch_tweet_oembed(url: str) -> dict | None:
    """Fetch tweet data using Twitter's oEmbed API (no auth required)."""
    oembed_url = "https://publish.twitter.com/oembed"
    params = {"url": url, "omit_script": "true"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(oembed_url, params=params, timeout=2.5)
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        print(f"Error fetching oEmbed: {e}")
    return None


async def fetch_tweet_api(tweet_id: str) -> dict | None:
    """Fetch tweet data using X API v2 (requires bearer token)."""
    if not X_BEARER_TOKEN:
        return None

    url = f"https://api.twitter.com/2/tweets/{tweet_id}"
    params = {
        "expansions": "author_id,attachments.media_keys",
        "tweet.fields": "created_at,public_metrics,text",
        "user.fields": "name,username,profile_image_url",
        "media.fields": "preview_image_url,url"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {X_BEARER_TOKEN}"},
                timeout=2.5
            )
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        print(f"Error fetching from X API: {e}")
    return None


def build_preview_response(url: str, tweet_data: dict | None, oembed_data: dict | None) -> dict:
    """Build the link preview response for Lark."""
    # Default fallback
    title = "X Post"
    author = ""
    text = ""

    if tweet_data and "data" in tweet_data:
        data = tweet_data["data"]
        text = data.get("text", "")[:100]

        # Get author info from includes
        includes = tweet_data.get("includes", {})
        users = includes.get("users", [])
        if users:
            author = f"@{users[0].get('username', '')}"
            title = f"{users[0].get('name', 'X Post')}"
    elif oembed_data:
        author = oembed_data.get("author_name", "")
        title = f"Post by {author}" if author else "X Post"
        # Extract text from HTML (basic extraction)
        html = oembed_data.get("html", "")
        # Try to get text content
        text_match = re.search(r'<p[^>]*>(.*?)</p>', html, re.DOTALL)
        if text_match:
            text = re.sub(r'<[^>]+>', '', text_match.group(1))[:100]

    # Build inline preview (required)
    inline_title = f"{title}"
    if author:
        inline_title = f"{author}: {text[:50]}..." if text else f"Post by {author}"

    response = {
        "inline": {
            "i18n_title": {
                "en_us": inline_title,
                "zh_cn": inline_title
            }
            # Note: image_key requires uploading image to Lark first
            # "image_key": "img_xxx"
        }
    }

    # Build card preview (optional but recommended)
    card_elements = []

    # Add tweet text
    if text:
        card_elements.append({
            "tag": "markdown",
            "content": text
        })

    # Add author info
    if author:
        card_elements.append({
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": f"From {author} on X"
                }
            ]
        })

    # Add action button
    card_elements.append({
        "tag": "action",
        "actions": [
            {
                "tag": "button",
                "text": {
                    "tag": "plain_text",
                    "content": "View on X"
                },
                "type": "primary",
                "multi_url": {
                    "url": url,
                    "pc_url": url,
                    "ios_url": url,
                    "android_url": url
                }
            }
        ]
    })

    response["card"] = {
        "type": "raw",
        "data": {
            "config": {
                "wide_screen_mode": True
            },
            "header": {
                "title": {
                    "tag": "plain_text",
                    "content": title
                },
                "template": "blue"
            },
            "elements": card_elements
        }
    }

    return response


@app.post("/webhook")
async def webhook(request: Request):
    """Main webhook endpoint for Lark callbacks."""
    try:
        raw_body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Parse and potentially decrypt the request
    try:
        body = parse_request_body(raw_body)
    except Exception as e:
        print(f"Decryption error: {e}")
        raise HTTPException(status_code=400, detail="Decryption failed")

    # Handle URL verification challenge
    if body.get("type") == "url_verification":
        challenge = body.get("challenge", "")
        # Optionally verify the token
        token = body.get("token", "")
        if VERIFICATION_TOKEN and token != VERIFICATION_TOKEN:
            print(f"Token mismatch: expected {VERIFICATION_TOKEN}, got {token}")
            # Still return challenge but log the mismatch
        return JSONResponse(content={"challenge": challenge})

    # Handle event callbacks
    header = body.get("header", {})
    event_type = header.get("event_type", "")

    if event_type == "url.preview.get":
        return await handle_url_preview(body)

    # Unknown event type
    return JSONResponse(content={"msg": "ok"})


async def handle_url_preview(body: dict) -> JSONResponse:
    """Handle the url.preview.get callback."""
    event = body.get("event", {})
    context = event.get("context", {})
    url = context.get("url", "")
    preview_token = context.get("preview_token", "")

    print(f"Processing URL preview for: {url}")

    if not url:
        return JSONResponse(content={"msg": "no url"})

    # Extract tweet ID
    tweet_id = extract_tweet_id(url)

    # Fetch tweet data (try both methods)
    tweet_data = None
    oembed_data = None

    if tweet_id:
        # Try X API first (richer data), fall back to oEmbed
        tweet_data = await fetch_tweet_api(tweet_id)

    # Always try oEmbed as fallback/supplement
    oembed_data = await fetch_tweet_oembed(url)

    # Build and return preview response
    response = build_preview_response(url, tweet_data, oembed_data)

    return JSONResponse(content=response)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Lark X Link Preview",
        "status": "running",
        "endpoints": {
            "webhook": "/webhook",
            "health": "/health"
        }
    }
