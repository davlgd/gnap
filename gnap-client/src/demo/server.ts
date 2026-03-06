/**
 * Mock GNAP Authorization Server for demo and testing.
 *
 * Implements the core grant flow:
 * - POST /gnap          -> Grant endpoint (Section 2/3)
 * - GET  /interact/:id  -> User interaction page (Section 4)
 * - POST /continue/:id  -> Continuation endpoint (Section 5)
 * - POST /token/:id     -> Token management (Section 6)
 * - DELETE /token/:id   -> Token revocation (Section 6)
 *
 * Uses Bun.serve() with URL pattern routing.
 */

import type { GrantRequest, GrantResponse } from "../types/grant.ts";
import type { AccessToken } from "../types/token.ts";

interface PendingGrant {
  id: string;
  request: GrantRequest;
  interactionNonce: string;
  interactRef: string;
  continueToken: string;
  approved: boolean;
  finalized: boolean;
  tokens: AccessToken[];
}

const grants = new Map<string, PendingGrant>();

function generateId(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 20).toUpperCase();
}

function jsonResponse(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: { "content-type": "application/json" },
  });
}

function getBaseUrl(req: Request): string {
  const url = new URL(req.url);
  return `${url.protocol}//${url.host}`;
}

function extractParam(pathname: string, prefix: string): string | null {
  if (!pathname.startsWith(prefix)) return null;
  return pathname.slice(prefix.length);
}

function buildTokens(
  grantReq: GrantRequest,
  baseUrl: string,
  grantId: string,
): AccessToken[] {
  const tokenField = grantReq.access_token;
  if (!tokenField) return [];

  const requests = Array.isArray(tokenField) ? tokenField : [tokenField];
  return requests.map((req, i) => {
    const tokenId = generateId();
    return {
      value: tokenId,
      ...(req.label ? { label: req.label } : {}),
      manage: {
        uri: `${baseUrl}/token/${grantId}-${i}`,
        access_token: { value: generateId() },
      },
      access: req.access,
      expires_in: 3600,
      ...(req.flags?.includes("bearer") ? { flags: ["bearer"] } : {}),
    };
  });
}

const port = parseInt(process.env["GNAP_PORT"] ?? "3000", 10);

const server = Bun.serve({
  port,
  async fetch(req) {
    const url = new URL(req.url);
    const { pathname } = url;
    const method = req.method;

    // POST /gnap -- Grant endpoint (Section 2/3)
    if (method === "POST" && pathname === "/gnap") {
      const body = await req.text();
      const grantReq = JSON.parse(body) as GrantRequest;
      const base = getBaseUrl(req);

      const grantId = generateId();
      const continueToken = generateId();
      const interactionNonce = generateId();
      const interactRef = generateId();

      const hasInteract =
        grantReq.interact?.start.includes("redirect") ||
        grantReq.interact?.start.includes("user_code");

      const grant: PendingGrant = {
        id: grantId,
        request: grantReq,
        interactionNonce,
        interactRef,
        continueToken,
        approved: !hasInteract,
        finalized: false,
        tokens: [],
      };

      if (grant.approved) {
        grant.tokens = buildTokens(grantReq, base, grantId);
      }

      grants.set(grantId, grant);

      const response: GrantResponse = {
        continue: {
          access_token: { value: continueToken },
          uri: `${base}/continue/${grantId}`,
          ...(hasInteract ? { wait: 5 } : {}),
        },
      };

      if (hasInteract) {
        response.interact = {};
        if (grantReq.interact?.start.includes("redirect")) {
          response.interact.redirect = `${base}/interact/${grantId}`;
        }
        if (grantReq.interact?.start.includes("user_code")) {
          response.interact.user_code = `${grantId.slice(0, 4)}-${grantId.slice(4, 8)}`;
        }
        response.interact.finish = interactionNonce;
      }

      if (grant.approved && grant.tokens.length > 0) {
        response.access_token =
          grant.tokens.length === 1 ? grant.tokens[0]! : grant.tokens;
      }

      return jsonResponse(response);
    }

    // GET /interact/:id -- User interaction page (Section 4)
    const interactId = extractParam(pathname, "/interact/");
    if (method === "GET" && interactId) {
      const grant = grants.get(interactId);
      if (!grant) return jsonResponse({ error: "unknown_interaction" }, 404);

      const base = getBaseUrl(req);
      grant.approved = true;
      grant.tokens = buildTokens(grant.request, base, grant.id);

      const finishUri = grant.request.interact?.finish?.uri;
      if (finishUri) {
        const callbackUrl = new URL(finishUri);
        callbackUrl.searchParams.set("hash", grant.interactionNonce);
        callbackUrl.searchParams.set("interact_ref", grant.interactRef);

        return new Response(null, {
          status: 302,
          headers: { location: callbackUrl.toString() },
        });
      }

      return new Response(
        `<html><body>
          <h1>Grant Approved</h1>
          <p>Grant ID: ${interactId}</p>
          <p>Interact Ref: ${grant.interactRef}</p>
          <p>You can close this page.</p>
        </body></html>`,
        { headers: { "content-type": "text/html" } },
      );
    }

    // POST /continue/:id -- Continuation endpoint (Section 5)
    // DELETE /continue/:id -- Grant revocation (Section 5.4)
    const continueId = extractParam(pathname, "/continue/");
    if (continueId) {
      const grant = grants.get(continueId);
      if (!grant) return jsonResponse({ error: "invalid_continuation" }, 404);

      if (method === "DELETE") {
        grants.delete(continueId);
        return new Response(null, { status: 204 });
      }

      if (method === "POST") {
        const auth = req.headers.get("authorization");
        if (auth !== `GNAP ${grant.continueToken}`) {
          return jsonResponse({ error: "invalid_client" }, 401);
        }

        const body = await req.text();
        const continueReq = body
          ? (JSON.parse(body) as { interact_ref?: string })
          : {};

        if (!grant.approved) {
          return jsonResponse({
            continue: {
              access_token: { value: grant.continueToken },
              uri: `${getBaseUrl(req)}/continue/${continueId}`,
              wait: 5,
            },
          } satisfies GrantResponse);
        }

        const base = getBaseUrl(req);
        if (grant.tokens.length === 0) {
          grant.tokens = buildTokens(grant.request, base, grant.id);
        }

        const newContinueToken = generateId();
        grant.continueToken = newContinueToken;

        const response: GrantResponse = {
          continue: {
            access_token: { value: newContinueToken },
            uri: `${base}/continue/${continueId}`,
          },
          access_token:
            grant.tokens.length === 1 ? grant.tokens[0]! : grant.tokens,
        };

        grant.finalized = true;
        return jsonResponse(response);
      }
    }

    // POST /token/:id -- Token rotation (Section 6.1)
    // DELETE /token/:id -- Token revocation (Section 6.2)
    const tokenId = extractParam(pathname, "/token/");
    if (tokenId) {
      const base = getBaseUrl(req);

      if (method === "POST") {
        for (const grant of grants.values()) {
          const token = grant.tokens.find(
            (t) => t.manage?.uri === `${base}/token/${tokenId}`,
          );
          if (token) {
            const newToken: AccessToken = {
              ...token,
              value: generateId(),
              manage: {
                uri: token.manage!.uri,
                access_token: { value: generateId() },
              },
            };
            const idx = grant.tokens.indexOf(token);
            grant.tokens[idx] = newToken;
            return jsonResponse({ access_token: newToken });
          }
        }
        return jsonResponse({ error: "invalid_request" }, 404);
      }

      if (method === "DELETE") {
        for (const grant of grants.values()) {
          const idx = grant.tokens.findIndex(
            (t) => t.manage?.uri === `${base}/token/${tokenId}`,
          );
          if (idx !== -1) {
            grant.tokens.splice(idx, 1);
            return new Response(null, { status: 204 });
          }
        }
        return jsonResponse({ error: "invalid_request" }, 404);
      }
    }

    // GET /.well-known/gnap-as-rs -- Discovery endpoint
    if (method === "GET" && pathname === "/.well-known/gnap-as-rs") {
      const base = getBaseUrl(req);
      return jsonResponse({
        grant_request_endpoint: `${base}/gnap`,
        key_proofs_supported: ["httpsig"],
        introspection_endpoint: `${base}/introspect`,
      });
    }

    return jsonResponse({ error: "not_found" }, 404);
  },
});

console.log(`GNAP Mock AS running on http://localhost:${port}`);
console.log(`  Grant endpoint: http://localhost:${port}/gnap`);
console.log(`  Discovery:      http://localhost:${port}/.well-known/gnap-as-rs`);

export { server };
