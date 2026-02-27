# Web Tool — "Is My Data in AI?" Canary Token Generator

## Overview

The web tool provides a browser-based interface for generating and checking
canary tokens. Users embed these tokens in documents, emails, or private
content. If the token string later appears in AI-generated output, it
indicates the source material was used for model training or retrieval.

## How Canary Tokens Work

1. **Generate** — The server creates a unique string in the format
   `AUMOS-CANARY-{uuid}-{timestamp}` and stores its record in Cloudflare KV.
2. **Embed** — The user copies the string and places it inside documents
   they want to monitor (contracts, drafts, emails, knowledge bases).
3. **Detect** — If the exact string appears verbatim in AI output, the user
   knows their content was ingested by an AI system.
4. **Report** — Users or automated scanners call the report endpoint to
   record that the token was observed in AI output.
5. **Check** — Anyone with the token ID can verify whether it has been
   reported as seen.

## Deployment (Cloudflare Workers)

### Prerequisites

- Node.js 18+ and npm
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) v3+
- A Cloudflare account with Workers enabled

### Steps

```bash
# 1. Install wrangler globally (if not already installed)
npm install -g wrangler

# 2. Navigate to the web-tool directory
cd web-tool

# 3. Create the KV namespace
wrangler kv:namespace create "CANARY_TOKENS"
# Copy the output id into wrangler.toml

# 4. Deploy
wrangler deploy
```

After deployment, wrangler prints the public URL for the worker.

### Local Development

```bash
wrangler dev
```

This starts a local server at `http://localhost:8787` with a local KV store.

## API Reference

### POST /generate

Creates a new canary token and returns the embeddable string.

**Request:** No body required.

**Response (201):**

```json
{
  "tokenId": "a1b2c3d4-...",
  "canaryString": "AUMOS-CANARY-a1b2c3d4-...-2026-01-15T10:30:00.000Z",
  "createdAt": "2026-01-15T10:30:00.000Z",
  "instructions": "Embed this canary string in your documents..."
}
```

### GET /check/:tokenId

Check whether a token has been reported as seen in AI output.

**Response (200):**

```json
{
  "tokenId": "a1b2c3d4-...",
  "found": true,
  "reported": false,
  "reportCount": 0,
  "firstReportedAt": null
}
```

### POST /report/:tokenId

Report that a canary token was observed in AI-generated output.

**Response (200):**

```json
{
  "tokenId": "a1b2c3d4-...",
  "acknowledged": true,
  "reportCount": 1
}
```

## Privacy

- **No personal data stored.** Only random UUIDs and timestamps are kept.
- Token records expire automatically after one year of inactivity.
- The server does not log IP addresses or user agents beyond standard
  Cloudflare Worker request logging.
- CORS is enabled so the API can be called from any origin.

## Token Format

```
AUMOS-CANARY-{uuid}-{iso-timestamp}
```

The format is intentionally verbose and unlikely to appear naturally in text.
The UUID provides uniqueness; the timestamp provides temporal context for
when the token was planted.
