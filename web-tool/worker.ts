// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 MuVeraAI Corporation

/**
 * @module worker
 * Cloudflare Worker for the "Is My Data in AI?" canary token web tool.
 *
 * Generates unique canary strings that users embed in documents.
 * If the string appears in AI-generated output, it indicates the
 * document was used for training or retrieval.
 */

interface Env {
  readonly CANARY_TOKENS: KVNamespace;
}

/** Shape of a stored canary token record in KV. */
interface StoredToken {
  readonly tokenId: string;
  readonly createdAt: string;
  readonly reportedAt: string | null;
  readonly reportCount: number;
}

/** Response body returned by the generate endpoint. */
interface GenerateResponse {
  readonly tokenId: string;
  readonly canaryString: string;
  readonly createdAt: string;
  readonly instructions: string;
}

/** Response body returned by the check endpoint. */
interface CheckResponse {
  readonly tokenId: string;
  readonly found: boolean;
  readonly reported: boolean;
  readonly reportCount: number;
  readonly firstReportedAt: string | null;
}

/** Response body returned by the report endpoint. */
interface ReportResponse {
  readonly tokenId: string;
  readonly acknowledged: boolean;
  readonly reportCount: number;
}

/**
 * Build a canary string from a UUID and ISO timestamp.
 * Format: AUMOS-CANARY-{uuid}-{timestamp}
 */
function buildCanaryString(uuid: string, timestamp: string): string {
  return `AUMOS-CANARY-${uuid}-${timestamp}`;
}

/**
 * Generate a v4-like UUID using the Web Crypto API available in Workers.
 */
function generateUUID(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  // Set version (4) and variant (RFC 4122)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

/** Standard CORS headers for browser access. */
function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

/** Build a JSON response with CORS headers. */
function jsonResponse(body: unknown, status: number = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(),
    },
  });
}

/** Build an error JSON response. */
function errorResponse(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

/**
 * POST /generate
 * Generates a unique canary token string and stores it in KV.
 */
async function handleGenerateToken(
  _request: Request,
  env: Env
): Promise<Response> {
  const tokenId = generateUUID();
  const createdAt = new Date().toISOString();
  const canaryString = buildCanaryString(tokenId, createdAt);

  const record: StoredToken = {
    tokenId,
    createdAt,
    reportedAt: null,
    reportCount: 0,
  };

  await env.CANARY_TOKENS.put(tokenId, JSON.stringify(record), {
    // Tokens expire after 1 year if unused
    expirationTtl: 365 * 24 * 60 * 60,
  });

  const responseBody: GenerateResponse = {
    tokenId,
    canaryString,
    createdAt,
    instructions:
      "Embed this canary string in your documents. " +
      "If you see it reproduced in AI-generated output, " +
      "your document was likely used for training or retrieval.",
  };

  return jsonResponse(responseBody, 201);
}

/**
 * GET /check/:tokenId
 * Checks whether a canary token has been reported as seen in AI output.
 */
async function handleCheckToken(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const segments = url.pathname.split("/").filter(Boolean);

  // Expect: /check/{tokenId}
  if (segments.length < 2 || segments[0] !== "check") {
    return errorResponse("Missing token ID. Use GET /check/:tokenId", 400);
  }

  const tokenId = segments[1];
  const raw = await env.CANARY_TOKENS.get(tokenId);

  if (raw === null) {
    const responseBody: CheckResponse = {
      tokenId,
      found: false,
      reported: false,
      reportCount: 0,
      firstReportedAt: null,
    };
    return jsonResponse(responseBody);
  }

  const record = JSON.parse(raw) as StoredToken;
  const responseBody: CheckResponse = {
    tokenId: record.tokenId,
    found: true,
    reported: record.reportedAt !== null,
    reportCount: record.reportCount,
    firstReportedAt: record.reportedAt,
  };

  return jsonResponse(responseBody);
}

/**
 * POST /report/:tokenId
 * Report that a canary token was observed in AI output.
 */
async function handleReportToken(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);
  const segments = url.pathname.split("/").filter(Boolean);

  if (segments.length < 2 || segments[0] !== "report") {
    return errorResponse("Missing token ID. Use POST /report/:tokenId", 400);
  }

  const tokenId = segments[1];
  const raw = await env.CANARY_TOKENS.get(tokenId);

  if (raw === null) {
    return errorResponse(`Token '${tokenId}' not found.`, 404);
  }

  const record = JSON.parse(raw) as StoredToken;
  const updatedRecord: StoredToken = {
    ...record,
    reportedAt: record.reportedAt ?? new Date().toISOString(),
    reportCount: record.reportCount + 1,
  };

  await env.CANARY_TOKENS.put(tokenId, JSON.stringify(updatedRecord));

  const responseBody: ReportResponse = {
    tokenId,
    acknowledged: true,
    reportCount: updatedRecord.reportCount,
  };

  return jsonResponse(responseBody);
}

/**
 * GET /
 * Serves the static index.html UI.
 */
async function handleServeUI(_request: Request): Promise<Response> {
  // In production this would serve from __STATIC_CONTENT or an asset binding.
  // For simplicity, we redirect to the co-located index.html via the static
  // asset handler that wrangler provides automatically for files in the
  // web-tool directory when configured with [site].
  return new Response(INDEX_HTML, {
    status: 200,
    headers: {
      "Content-Type": "text/html;charset=UTF-8",
      ...corsHeaders(),
    },
  });
}

// Inline the HTML so the worker is fully self-contained.
// See web-tool/index.html for the readable source.
const INDEX_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Is My Data in AI?</title></head>
<body><p>See index.html for the full UI.</p></body>
</html>`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // POST /generate
    if (path === "/generate" && request.method === "POST") {
      return handleGenerateToken(request, env);
    }

    // GET /check/:tokenId
    if (path.startsWith("/check/") && request.method === "GET") {
      return handleCheckToken(request, env);
    }

    // POST /report/:tokenId
    if (path.startsWith("/report/") && request.method === "POST") {
      return handleReportToken(request, env);
    }

    // GET / — serve UI
    if (path === "/" && request.method === "GET") {
      return handleServeUI(request);
    }

    return errorResponse("Not found", 404);
  },
};
