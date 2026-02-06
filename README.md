# Lark X Link Preview Service

A webhook server that provides rich link previews for X.com (Twitter) links in Lark/Feishu.

## Features

- Handles Lark's URL verification challenge
- Decrypts AES-256-CBC encrypted payloads (when Encrypt Key is configured)
- Fetches tweet data via Twitter's oEmbed API (no auth required)
- Optionally uses X API v2 for richer previews (requires bearer token)
- Returns both inline text preview and card preview

## Deploy to Railway

### 1. Create Railway Project

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project in this directory
cd lark-link-preview
railway init
```

### 2. Set Environment Variables

In Railway dashboard or via CLI:

```bash
# Optional but recommended
railway variables set LARK_ENCRYPT_KEY=your_encrypt_key
railway variables set LARK_VERIFICATION_TOKEN=your_verification_token

# Optional: for richer previews
railway variables set X_BEARER_TOKEN=your_x_bearer_token
```

### 3. Deploy

```bash
railway up
```

Or connect your GitHub repo in Railway dashboard for automatic deployments.

### 4. Get Your Public URL

After deployment, Railway provides a public URL like:
`https://your-service.up.railway.app`

## Configure Lark Developer Console

### Step 1: Add Link Preview Capability

1. Go to [Lark Developer Console](https://open.larksuite.com/app)
2. Select your app
3. Go to **Add Capabilities** > **Link Preview**
4. Add URL rules: `x.com` and `twitter.com`

### Step 2: Configure Callback URL

1. Go to **Event & Callback** > **Callback Configuration**
2. Set Request URL to: `https://your-service.up.railway.app/webhook`
3. Lark will send a challenge request - your server will respond automatically

### Step 3: (Optional) Configure Encryption

1. Go to **Event & Callback** > **Encryption Strategy**
2. Set or note down the **Encrypt Key** and **Verification Token**
3. Add these to your Railway environment variables

### Step 4: Publish App Version

Create and publish a new app version for changes to take effect.

## Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Copy and edit environment variables
cp .env.example .env

# Run server
uvicorn main:app --reload --port 8000
```

For local testing with Lark, use ngrok or similar:

```bash
ngrok http 8000
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service info |
| `/health` | GET | Health check |
| `/webhook` | POST | Lark callback endpoint |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LARK_ENCRYPT_KEY` | No | AES encryption key from Lark console |
| `LARK_VERIFICATION_TOKEN` | No | Verification token from Lark console |
| `X_BEARER_TOKEN` | No | X API v2 bearer token for richer previews |

## How It Works

1. User sends/views an x.com link in Lark chat
2. Lark detects the URL matches your registered pattern
3. Lark sends `url.preview.get` callback to your webhook
4. Server fetches tweet data from Twitter/X
5. Server returns preview data (inline text + card)
6. Lark displays the rich preview to the user

## Preview Response Format

The server returns:

- **Inline preview** (required): Text link with title
- **Card preview** (optional): Rich card with tweet content, author, and "View on X" button
