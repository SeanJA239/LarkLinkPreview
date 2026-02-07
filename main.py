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


def decrypt_aes(encrypt_key: str, encrypted_data: str) -> dict:
    """
    Decrypt Lark's AES-256-CBC encrypted data.
    """
    if not encrypt_key:
        raise ValueError("Encrypt key is not configured")

    key = hashlib.sha256(encrypt_key.encode()).digest()
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_bytes[:16]
    encrypted_content = encrypted_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()

    padding_len = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_len]

    return json.loads(decrypted.decode("utf-8"))


def parse_request_body(body: dict) -> dict:
    """Parse request body, decrypting if necessary."""
    if "encrypt" in body:
        return decrypt_aes(ENCRYPT_KEY, body["encrypt"])
    return body


def extract_tweet_info(url: str) -> tuple:
    """Extract username and tweet ID from x.com or twitter.com URL."""
    # Match patterns like:
    # https://x.com/elonmusk/status/1234567890
    # https://twitter.com/elonmusk/status/1234567890
    pattern = r"(?:x\.com|twitter\.com)/(\w+)/status/(\d+)"
    match = re.search(pattern, url)
    if match:
        return match.group(1), match.group(2)
    return None, None


async def fetch_tweet_fxtwitter(username: str, tweet_id: str) -> Optional[dict]:
    """Fetch tweet data using fxtwitter.com API (no auth required, reliable)."""
    api_url = f"https://api.fxtwitter.com/{username}/status/{tweet_id}"

    print(f"Fetching from fxtwitter: {api_url}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(api_url, timeout=2.5)
            print(f"fxtwitter response status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"fxtwitter response: {json.dumps(data, indent=2)[:500]}")
                return data
            else:
                print(f"fxtwitter error response: {response.text[:200]}")
    except Exception as e:
        print(f"Error fetching from fxtwitter: {e}")
    return None


def build_preview_response(url: str, fx_data: Optional[dict]) -> dict:
    """Build the link preview response for Lark."""
    # Default fallback
    title = "X Post"
    author = ""
    author_name = ""
    text = ""
    likes = 0
    retweets = 0

    if fx_data and fx_data.get("code") == 200 and "tweet" in fx_data:
        tweet = fx_data["tweet"]
        text = tweet.get("text", "")[:200]
        author = f"@{tweet.get('author', {}).get('screen_name', '')}"
        author_name = tweet.get("author", {}).get("name", "X Post")
        title = author_name
        likes = tweet.get("likes", 0)
        retweets = tweet.get("retweets", 0)

        print(f"Parsed tweet - Author: {author}, Title: {title}, Text: {text[:50]}...")

    # Build inline preview (required)
    if author and text:
        inline_title = f"{author}: {text[:60]}..."
    elif author:
        inline_title = f"Post by {author}"
    else:
        inline_title = "X Post"

    response = {
        "inline": {
            "i18n_title": {
                "en_us": inline_title,
                "zh_cn": inline_title
            }
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

    # Add engagement metrics
    if likes or retweets:
        card_elements.append({
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": f"❤️ {likes:,}  🔁 {retweets:,}  •  {author} on X"
                }
            ]
        })
    elif author:
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
                    "content": title if title != "X Post" else "X Post"
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
    print("=== Webhook request received ===")

    try:
        raw_body = await request.json()
        print(f"Raw body: {json.dumps(raw_body)[:200]}")
    except Exception as e:
        print(f"JSON parse error: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Parse and potentially decrypt the request
    try:
        body = parse_request_body(raw_body)
        print(f"Parsed body type: {body.get('type', body.get('header', {}).get('event_type', 'unknown'))}")
    except Exception as e:
        print(f"Decryption error: {e}")
        raise HTTPException(status_code=400, detail="Decryption failed")

    # Handle URL verification challenge
    if body.get("type") == "url_verification":
        challenge = body.get("challenge", "")
        print(f"Challenge request, returning: {challenge}")
        return JSONResponse(content={"challenge": challenge})

    # Handle event callbacks
    header = body.get("header", {})
    event_type = header.get("event_type", "")
    print(f"Event type: {event_type}")

    if event_type == "url.preview.get":
        return await handle_url_preview(body)

    # Unknown event type
    print(f"Unknown event type: {event_type}")
    return JSONResponse(content={"msg": "ok"})


async def handle_url_preview(body: dict) -> JSONResponse:
    """Handle the url.preview.get callback."""
    event = body.get("event", {})
    context = event.get("context", {})
    url = context.get("url", "")

    print(f"=== Processing URL preview for: {url} ===")

    if not url:
        print("No URL in request")
        return JSONResponse(content={"msg": "no url"})

    # Extract username and tweet ID
    username, tweet_id = extract_tweet_info(url)
    print(f"Extracted - username: {username}, tweet_id: {tweet_id}")

    # Fetch tweet data from fxtwitter
    fx_data = None
    if username and tweet_id:
        fx_data = await fetch_tweet_fxtwitter(username, tweet_id)

    # Build and return preview response
    response = build_preview_response(url, fx_data)
    print(f"Returning response: {json.dumps(response)[:300]}")

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
        "version": "2.0",
        "api": "fxtwitter.com",
        "status": "running",
        "endpoints": {
            "webhook": "/webhook",
            "health": "/health"
        }
    }
