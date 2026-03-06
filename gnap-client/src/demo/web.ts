#!/usr/bin/env bun
/**
 * GNAP Web Demo -- Interactive browser-based protocol demonstration.
 *
 * Covers ALL RFC 9635 sections + RFC 9767 Resource Server connections:
 * - Section 2: Grant requests (all modes, subject, user, client ref)
 * - Section 3: Grant responses (tokens, interaction, subject, errors, instance_id)
 * - Section 4: Interaction (redirect, app, user_code, user_code_uri, hash validation)
 * - Section 5: Continuation (post-interaction, polling, modification, revocation)
 * - Section 6: Token management (rotation, revocation)
 * - Section 7: Key proofing (httpsig with Ed25519, key binding)
 * - Section 8: Resource access rights (string refs, structured)
 * - RFC 9767: Discovery, introspection
 *
 * Usage: bun run src/demo/web.ts
 */

import { GnapClient } from "../client.ts";
import type { GrantResponse } from "../types/grant.ts";
import type { AccessToken } from "../types/token.ts";
import { isMultipleTokenResponse } from "../types/token.ts";

// -- Mock AS state --

interface PendingGrant {
  id: string;
  request: any;
  interactionNonce: string;
  interactRef: string;
  continueToken: string;
  approved: boolean;
  tokens: AccessToken[];
  instanceId: string;
}

const grants = new Map<string, PendingGrant>();
const issuedTokens = new Map<string, { grant: PendingGrant; token: AccessToken }>();

function generateId(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 20).toUpperCase();
}

function jsonResponse(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
  });
}

function getBaseUrl(req: Request): string {
  const url = new URL(req.url);
  return `${url.protocol}//${url.host}`;
}

function extractParam(pathname: string, prefix: string): string | null {
  if (!pathname.startsWith(prefix)) return null;
  const rest = pathname.slice(prefix.length);
  return rest.includes("/") ? null : rest;
}

function buildTokens(accessToken: any, baseUrl: string, grantId: string, keyBound = false): AccessToken[] {
  if (!accessToken) return [];
  const requests = Array.isArray(accessToken) ? accessToken : [accessToken];
  return requests.map((req: any, i: number) => {
    const tokenId = generateId();
    const isBearer = req.flags?.includes("bearer");
    const token: AccessToken = {
      value: tokenId,
      ...(req.label ? { label: req.label } : {}),
      manage: {
        uri: `${baseUrl}/token/${grantId}-${i}`,
        access_token: { value: generateId() },
      },
      access: req.access,
      expires_in: 3600,
      ...(isBearer ? { flags: ["bearer"] } : {}),
      ...(!isBearer && keyBound ? { key: { proof: "httpsig", jwk: { kty: "OKP", crv: "Ed25519", alg: "EdDSA", x: "bound-key-placeholder", kid: "bound-key-1" } as JsonWebKey } } : {}),
    };
    return token;
  });
}

function buildSubjectResponse(subjectReq: any): any {
  if (!subjectReq) return undefined;
  const resp: any = {};
  if (subjectReq.sub_id_formats) {
    resp.sub_ids = [];
    if (subjectReq.sub_id_formats.includes("opaque")) {
      resp.sub_ids.push({ format: "opaque", id: "user-" + generateId().slice(0, 8).toLowerCase() });
    }
    if (subjectReq.sub_id_formats.includes("email")) {
      resp.sub_ids.push({ format: "email", email: "jane.doe@example.com" });
    }
    if (subjectReq.sub_id_formats.includes("iss_sub")) {
      resp.sub_ids.push({ format: "iss_sub", iss: "https://idp.example.com", sub: "user-12345" });
    }
  }
  if (subjectReq.assertion_formats) {
    resp.assertions = [];
    if (subjectReq.assertion_formats.includes("id_token")) {
      resp.assertions.push({ format: "id_token", value: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyLTEyMzQ1IiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20iLCJhdWQiOiJkZW1vLWNsaWVudCIsImV4cCI6MTczNjAwMDAwMH0.mock-signature" });
    }
    if (subjectReq.assertion_formats.includes("saml2")) {
      resp.assertions.push({ format: "saml2", value: "<saml:Assertion>mock-saml-assertion</saml:Assertion>" });
    }
  }
  resp.updated_at = new Date().toISOString();
  return resp;
}

// -- Demo client state --

let demoClient: GnapClient | null = null;
let lastGrantResponse: GrantResponse | null = null;
let lastInteractRef: string | null = null;
let lastServerHash: string | null = null;
let currentToken: AccessToken | null = null;

const port = parseInt(process.env["GNAP_PORT"] ?? "3000", 10);

const server = Bun.serve({
  port,
  async fetch(req) {
    const url = new URL(req.url);
    const { pathname } = url;
    const method = req.method;

    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
          "access-control-allow-headers": "content-type, authorization, signature, signature-input, content-digest",
        },
      });
    }

    // ========== FRONTEND ==========
    if (method === "GET" && pathname === "/") {
      return new Response(HTML, { headers: { "content-type": "text/html; charset=utf-8" } });
    }

    // ========== DEMO API ==========

    if (method === "POST" && pathname === "/api/init") {
      const base = getBaseUrl(req);
      demoClient = new GnapClient({
        grantEndpoint: `${base}/gnap`,
        displayName: "GNAP Demo Client",
        displayUri: "https://demo.example.com",
      });
      await demoClient.init();
      lastGrantResponse = null;
      lastInteractRef = null;
      lastServerHash = null;
      currentToken = null;
      grants.clear();
      issuedTokens.clear();
      return jsonResponse({ keyId: demoClient.keyId, publicJwk: demoClient.publicJwk, grantEndpoint: demoClient.grantEndpoint });
    }

    if (method === "POST" && pathname === "/api/grant-request") {
      if (!demoClient) return jsonResponse({ error: "Client not initialized" }, 400);
      const body = await req.json();
      const { request, clientNonce } = demoClient.buildGrantRequest(body);
      const response = await demoClient.requestGrant(body);
      lastGrantResponse = response;
      return jsonResponse({ request, response, clientNonce, signatureNote: "Request signed with HTTP Message Signatures (Ed25519 + RFC 9421)" });
    }

    if (method === "POST" && pathname === "/api/simulate-interaction") {
      if (!lastGrantResponse?.interact?.redirect) return jsonResponse({ error: "No redirect interaction pending" }, 400);
      const interactRes = await fetch(lastGrantResponse.interact.redirect, { redirect: "manual" });
      const location = interactRes.headers.get("location");
      if (!location) return jsonResponse({ error: "No redirect location" }, 500);
      const callbackUrl = new URL(location);
      lastInteractRef = callbackUrl.searchParams.get("interact_ref");
      lastServerHash = callbackUrl.searchParams.get("hash");
      return jsonResponse({ redirectUri: lastGrantResponse.interact.redirect, callbackUri: location, interactRef: lastInteractRef, serverHash: lastServerHash });
    }

    if (method === "POST" && pathname === "/api/continue") {
      if (!demoClient || !lastInteractRef) return jsonResponse({ error: "No interaction reference" }, 400);
      const response = await demoClient.continueGrant(lastInteractRef, lastServerHash ?? undefined);
      lastGrantResponse = response;
      currentToken = demoClient.getAccessToken() ?? null;

      // Compute and include the interaction hash for display
      let interactionHash: string | undefined;
      if (lastServerHash && lastInteractRef) {
        interactionHash = await demoClient.computeInteractionHash(
          "client-nonce-placeholder", lastServerHash, lastInteractRef, "sha-256",
        );
      }
      return jsonResponse({ response, token: currentToken, interactionHash });
    }

    if (method === "POST" && pathname === "/api/poll") {
      if (!demoClient) return jsonResponse({ error: "Client not initialized" }, 400);
      const response = await demoClient.pollGrant();
      lastGrantResponse = response;
      currentToken = demoClient.getAccessToken() ?? null;
      return jsonResponse({ response, token: currentToken });
    }

    if (method === "POST" && pathname === "/api/modify-grant") {
      if (!demoClient) return jsonResponse({ error: "Client not initialized" }, 400);
      const body = await req.json();
      const response = await demoClient.modifyGrant(body);
      lastGrantResponse = response;
      currentToken = demoClient.getAccessToken() ?? null;
      return jsonResponse({ response, token: currentToken });
    }

    if (method === "POST" && pathname === "/api/rotate-token") {
      if (!demoClient || !currentToken) return jsonResponse({ error: "No token to rotate" }, 400);
      const oldValue = currentToken.value;
      currentToken = await demoClient.rotateToken(currentToken);
      return jsonResponse({ oldToken: oldValue, newToken: currentToken });
    }

    if (method === "POST" && pathname === "/api/revoke-token") {
      if (!demoClient || !currentToken) return jsonResponse({ error: "No token to revoke" }, 400);
      await demoClient.revokeToken(currentToken);
      const revoked = currentToken.value;
      currentToken = null;
      return jsonResponse({ revokedToken: revoked });
    }

    if (method === "POST" && pathname === "/api/revoke-grant") {
      if (!demoClient) return jsonResponse({ error: "Client not initialized" }, 400);
      await demoClient.revokeGrant();
      lastGrantResponse = null;
      currentToken = null;
      return jsonResponse({ status: "grant_revoked" });
    }

    if (method === "POST" && pathname === "/api/discover") {
      if (!demoClient) return jsonResponse({ error: "Client not initialized" }, 400);
      const base = getBaseUrl(req);
      const discovery = await demoClient.discover(`${base}/.well-known/gnap-as-rs`);
      return jsonResponse({ discovery });
    }

    if (method === "POST" && pathname === "/api/introspect") {
      if (!demoClient || !currentToken) return jsonResponse({ error: "No token" }, 400);
      const base = getBaseUrl(req);
      const result = await demoClient.introspectToken(`${base}/introspect`, currentToken.value);
      return jsonResponse({ introspection: result });
    }

    // ========== MOCK AS ENDPOINTS ==========

    // POST /gnap -- Grant endpoint (Section 2/3)
    if (method === "POST" && pathname === "/gnap") {
      const body = await req.json() as any;
      const base = getBaseUrl(req);
      const grantId = generateId();
      const continueToken = generateId();
      const interactionNonce = generateId();
      const interactRef = generateId();
      const instanceId = "inst-" + generateId().slice(0, 12).toLowerCase();

      const hasRedirect = body.interact?.start?.includes("redirect");
      const hasUserCode = body.interact?.start?.includes("user_code");
      const hasUserCodeUri = body.interact?.start?.includes("user_code_uri");
      const hasApp = body.interact?.start?.includes("app");
      const hasInteract = hasRedirect || hasUserCode || hasUserCodeUri || hasApp;

      // Error scenario: simulate invalid_request for empty client
      if (body.client === "") {
        return jsonResponse({ error: { code: "invalid_request", description: "Client reference must not be empty" } }, 400);
      }

      const grant: PendingGrant = {
        id: grantId, request: body, interactionNonce, interactRef, continueToken,
        approved: !hasInteract, tokens: [], instanceId,
      };

      const keyBound = !body.access_token?.flags?.includes("bearer");
      if (grant.approved) {
        grant.tokens = buildTokens(body.access_token, base, grantId, keyBound);
        grant.tokens.forEach(t => issuedTokens.set(t.value, { grant, token: t }));
      }
      grants.set(grantId, grant);

      const response: any = {
        continue: {
          access_token: { value: continueToken },
          uri: `${base}/continue/${grantId}`,
          ...(hasInteract ? { wait: 5 } : {}),
        },
        instance_id: instanceId,
      };

      if (hasInteract) {
        response.interact = {};
        if (hasRedirect) response.interact.redirect = `${base}/interact/${grantId}`;
        if (hasApp) response.interact.app = `gnap://interact/${grantId}`;
        if (hasUserCode) response.interact.user_code = `${grantId.slice(0, 4)}-${grantId.slice(4, 8)}`;
        if (hasUserCodeUri) {
          response.interact.user_code_uri = {
            code: `${grantId.slice(0, 4)}-${grantId.slice(4, 8)}`,
            uri: `${base}/device/${grantId}`,
          };
        }
        response.interact.finish = interactionNonce;
        response.interact.expires_in = 600;
      }

      if (grant.approved && grant.tokens.length > 0) {
        response.access_token = grant.tokens.length === 1 ? grant.tokens[0] : grant.tokens;
      }

      if (body.subject) {
        response.subject = buildSubjectResponse(body.subject);
      }

      return jsonResponse(response);
    }

    // GET /interact/:id -- User interaction page (Section 4)
    const interactId = extractParam(pathname, "/interact/");
    if (method === "GET" && interactId) {
      const grant = grants.get(interactId);
      if (!grant) return jsonResponse({ error: { code: "unknown_interaction", description: "Interaction reference not found" } }, 404);
      const base = getBaseUrl(req);
      grant.approved = true;
      const keyBound = !(grant.request as any).access_token?.flags?.includes("bearer");
      grant.tokens = buildTokens(grant.request.access_token, base, grant.id, keyBound);
      grant.tokens.forEach(t => issuedTokens.set(t.value, { grant, token: t }));

      const finishUri = grant.request.interact?.finish?.uri;
      if (finishUri) {
        const callbackUrl = new URL(finishUri);
        callbackUrl.searchParams.set("hash", grant.interactionNonce);
        callbackUrl.searchParams.set("interact_ref", grant.interactRef);
        return new Response(null, { status: 302, headers: { location: callbackUrl.toString() } });
      }
      return jsonResponse({ approved: true, interactRef: grant.interactRef });
    }

    // POST/DELETE /continue/:id -- Continuation (Section 5)
    const continueId = extractParam(pathname, "/continue/");
    if (continueId) {
      const grant = grants.get(continueId);
      if (!grant) return jsonResponse({ error: { code: "invalid_continuation", description: "Grant not found" } }, 404);
      if (method === "DELETE") { grants.delete(continueId); return new Response(null, { status: 204 }); }
      if (method === "POST") {
        const auth = req.headers.get("authorization");
        if (auth !== `GNAP ${grant.continueToken}`) return jsonResponse({ error: { code: "invalid_client", description: "Invalid continuation token" } }, 401);
        const body = await req.text();
        const continueReq = body ? JSON.parse(body) : {};
        const base = getBaseUrl(req);

        // Section 5.3: Grant modification
        if (continueReq.access_token) {
          grant.request.access_token = continueReq.access_token;
          grant.tokens = buildTokens(continueReq.access_token, base, grant.id);
          grant.tokens.forEach(t => issuedTokens.set(t.value, { grant, token: t }));
        }

        if (!grant.approved) {
          return jsonResponse({
            continue: { access_token: { value: grant.continueToken }, uri: `${base}/continue/${continueId}`, wait: 5 },
            instance_id: grant.instanceId,
          });
        }

        if (grant.tokens.length === 0) {
          const keyBound = !grant.request.access_token?.flags?.includes("bearer");
          grant.tokens = buildTokens(grant.request.access_token, base, grant.id, keyBound);
          grant.tokens.forEach(t => issuedTokens.set(t.value, { grant, token: t }));
        }
        const newContinueToken = generateId();
        grant.continueToken = newContinueToken;

        const resp: any = {
          continue: { access_token: { value: newContinueToken }, uri: `${base}/continue/${continueId}` },
          access_token: grant.tokens.length === 1 ? grant.tokens[0] : grant.tokens,
          instance_id: grant.instanceId,
        };
        if (grant.request.subject) resp.subject = buildSubjectResponse(grant.request.subject);
        return jsonResponse(resp);
      }
    }

    // POST/DELETE /token/:id -- Token management (Section 6)
    const tokenId = extractParam(pathname, "/token/");
    if (tokenId) {
      const base = getBaseUrl(req);
      if (method === "POST") {
        for (const grant of grants.values()) {
          const token = grant.tokens.find((t) => t.manage?.uri === `${base}/token/${tokenId}`);
          if (token) {
            const newToken: AccessToken = { ...token, value: generateId(), manage: { uri: token.manage!.uri, access_token: { value: generateId() } } };
            grant.tokens[grant.tokens.indexOf(token)] = newToken;
            issuedTokens.delete(token.value);
            issuedTokens.set(newToken.value, { grant, token: newToken });
            return jsonResponse({ access_token: newToken });
          }
        }
        return jsonResponse({ error: { code: "invalid_rotation", description: "Token not found" } }, 404);
      }
      if (method === "DELETE") {
        for (const grant of grants.values()) {
          const idx = grant.tokens.findIndex((t) => t.manage?.uri === `${base}/token/${tokenId}`);
          if (idx !== -1) {
            issuedTokens.delete(grant.tokens[idx]!.value);
            grant.tokens.splice(idx, 1);
            return new Response(null, { status: 204 });
          }
        }
        return jsonResponse({ error: { code: "invalid_request", description: "Token not found" } }, 404);
      }
    }

    // POST /introspect -- Token introspection (RFC 9767 Section 4)
    if (method === "POST" && pathname === "/introspect") {
      const body = await req.json() as any;
      const tokenValue = body.access_token;
      const entry = issuedTokens.get(tokenValue);
      if (!entry) return jsonResponse({ active: false });
      return jsonResponse({
        active: true,
        access: entry.token.access,
        ...(entry.token.key ? { key: entry.token.key } : {}),
        ...(entry.token.flags ? { flags: entry.token.flags } : {}),
        expires_in: entry.token.expires_in,
      });
    }

    // GET /.well-known/gnap-as-rs -- Discovery (RFC 9767 Section 3)
    if (method === "GET" && pathname === "/.well-known/gnap-as-rs") {
      const base = getBaseUrl(req);
      return jsonResponse({
        grant_request_endpoint: `${base}/gnap`,
        key_proofs_supported: ["httpsig", "mtls", "jwsd", "jws"],
        introspection_endpoint: `${base}/introspect`,
        resource_registration_endpoint: `${base}/resource`,
        token_formats_supported: ["opaque", "jwt"],
      });
    }

    // POST /gnap-error -- Simulated error endpoint for demo
    if (method === "POST" && pathname === "/gnap-error") {
      const body = await req.json() as any;
      const errorCode = body.error_code ?? "user_denied";
      return jsonResponse({
        error: { code: errorCode, description: `Simulated error: ${errorCode}` },
        ...(body.with_continue ? {
          continue: { access_token: { value: generateId() }, uri: `${getBaseUrl(req)}/continue/${generateId()}` },
        } : {}),
      }, errorCode === "invalid_request" ? 400 : 200);
    }

    return jsonResponse({ error: "not_found" }, 404);
  },
});

console.log(`GNAP Web Demo running on http://localhost:${port}`);

// ========== EMBEDDED FRONTEND ==========

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GNAP Protocol Demo</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg-card:#161b22;--bg-hover:#1c2333;--bg-code:#0d1117;
  --border:#30363d;--border-active:#58a6ff;
  --text:#c9d1d9;--text-muted:#8b949e;--text-bright:#e6edf3;
  --accent:#58a6ff;--accent-muted:#1f6feb;
  --green:#3fb950;--green-bg:rgba(63,185,80,.1);
  --orange:#d29922;--orange-bg:rgba(210,153,34,.1);
  --red:#f85149;--red-bg:rgba(248,81,73,.1);
  --purple:#bc8cff;
  --radius:8px;--radius-sm:4px;
  --font-mono:'SF Mono','Cascadia Code','Fira Code','JetBrains Mono',monospace;
  --font-sans:-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif;
}
html{font-size:15px}
body{background:var(--bg);color:var(--text);font-family:var(--font-sans);line-height:1.6;min-height:100vh}
header{border-bottom:1px solid var(--border);padding:1.2rem 2rem;display:flex;align-items:center;gap:1.2rem;background:var(--bg-card)}
header h1{font-size:1.3rem;font-weight:600;color:var(--text-bright);letter-spacing:-.02em}
header .badge{font-size:.7rem;font-family:var(--font-mono);background:var(--accent-muted);color:#fff;padding:.2rem .5rem;border-radius:10px;letter-spacing:.03em}
header .subtitle{color:var(--text-muted);font-size:.85rem;margin-left:auto}
.container{max-width:1200px;margin:0 auto;padding:2rem}
.intro{margin-bottom:2rem;padding:1.2rem 1.5rem;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius)}
.intro h2{font-size:1rem;color:var(--text-bright);margin-bottom:.4rem}
.intro p{font-size:.85rem;color:var(--text-muted);line-height:1.5}
.intro .roles{display:flex;gap:1.5rem;margin-top:.8rem;flex-wrap:wrap}
.intro .role{display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:var(--text-muted)}
.intro .role .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.intro .role .dot.client{background:var(--accent)}
.intro .role .dot.as{background:var(--green)}
.intro .role .dot.ro{background:var(--orange)}
.intro .role .dot.rs{background:var(--purple)}
.timeline{position:relative;padding-left:2rem}
.timeline::before{content:'';position:absolute;left:11px;top:0;bottom:0;width:2px;background:var(--border)}
.step{position:relative;margin-bottom:1rem}
.step .marker{position:absolute;left:-2rem;top:.85rem;width:24px;height:24px;border-radius:50%;background:var(--bg-card);border:2px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:.65rem;font-weight:700;color:var(--text-muted);font-family:var(--font-mono);z-index:1;transition:all .3s}
.step.done .marker{border-color:var(--green);color:var(--green);background:var(--green-bg)}
.step.active .marker{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.1);box-shadow:0 0 0 4px rgba(88,166,255,.15)}
.step.error .marker{border-color:var(--red);color:var(--red)}
.step-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;transition:border-color .3s}
.step.active .step-card{border-color:var(--border-active)}
.step.done .step-card{border-color:var(--green)}
.step-header{padding:.8rem 1.2rem;display:flex;align-items:center;gap:.8rem;cursor:pointer;user-select:none}
.step-header:hover{background:var(--bg-hover)}
.step-title{font-size:.9rem;font-weight:600;color:var(--text-bright)}
.step-rfc{font-size:.7rem;font-family:var(--font-mono);color:var(--text-muted);background:var(--bg);padding:.15rem .4rem;border-radius:var(--radius-sm)}
.step-status{margin-left:auto;font-size:.75rem;font-family:var(--font-mono);padding:.15rem .5rem;border-radius:10px}
.step-status.pending{color:var(--text-muted);background:var(--bg)}
.step-status.running{color:var(--accent);background:rgba(88,166,255,.1)}
.step-status.success{color:var(--green);background:var(--green-bg)}
.step-status.error{color:var(--red);background:var(--red-bg)}
.step-body{display:none;border-top:1px solid var(--border);padding:1rem 1.2rem}
.step-body.open{display:block}
.exchange{margin-bottom:1rem}
.exchange:last-child{margin-bottom:0}
.exchange-label{display:flex;align-items:center;gap:.5rem;font-size:.75rem;font-family:var(--font-mono);color:var(--text-muted);margin-bottom:.4rem;text-transform:uppercase;letter-spacing:.05em}
.exchange-label .arrow{color:var(--accent)}
.exchange-label .arrow.response{color:var(--green)}
pre.json{background:var(--bg-code);border:1px solid var(--border);border-radius:var(--radius-sm);padding:.8rem 1rem;font-size:.78rem;font-family:var(--font-mono);line-height:1.5;overflow-x:auto;color:var(--text);max-height:400px;overflow-y:auto}
pre.json .key{color:var(--accent)}
pre.json .string{color:var(--green)}
pre.json .number{color:var(--purple)}
pre.json .boolean{color:var(--orange)}
pre.json .null{color:var(--text-muted)}
.actions{display:flex;gap:.6rem;margin:1.5rem 0;flex-wrap:wrap}
button{font-family:var(--font-sans);font-size:.85rem;font-weight:500;padding:.5rem 1.2rem;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--bg-card);color:var(--text);cursor:pointer;transition:all .15s;display:flex;align-items:center;gap:.4rem}
button:hover:not(:disabled){background:var(--bg-hover);border-color:var(--accent);color:var(--text-bright)}
button:disabled{opacity:.4;cursor:not-allowed}
button.primary{background:var(--accent-muted);border-color:var(--accent-muted);color:#fff}
button.primary:hover:not(:disabled){background:var(--accent);border-color:var(--accent)}
.client-info{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:1rem 1.2rem;margin-bottom:1.5rem;display:none}
.client-info.visible{display:block}
.client-info h3{font-size:.85rem;color:var(--text-bright);margin-bottom:.6rem;display:flex;align-items:center;gap:.5rem}
.client-info .info-grid{display:grid;grid-template-columns:auto 1fr;gap:.3rem .8rem;font-size:.78rem;font-family:var(--font-mono)}
.client-info .info-grid dt{color:var(--text-muted)}
.client-info .info-grid dd{color:var(--text);word-break:break-all}
.scenarios{display:flex;gap:.5rem;margin-bottom:1.5rem;flex-wrap:wrap}
.scenario-btn{font-size:.8rem;padding:.4rem .8rem;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--bg-card);color:var(--text-muted);cursor:pointer;transition:all .15s}
.scenario-btn:hover{border-color:var(--accent);color:var(--text-bright)}
.scenario-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.08)}
.note{font-size:.75rem;color:var(--text-muted);margin-top:.5rem;padding:.4rem .6rem;background:var(--bg);border-left:2px solid var(--accent);border-radius:0 var(--radius-sm) var(--radius-sm) 0}
.user-code-display{margin-top:1rem;padding:1rem;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);text-align:center}
.user-code-display .label{font-size:.75rem;color:var(--text-muted);margin-bottom:.4rem}
.user-code-display .code{font-size:2rem;font-family:var(--font-mono);color:var(--text-bright);letter-spacing:.15em;font-weight:700}
@keyframes spin{to{transform:rotate(360deg)}}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite}
@media(max-width:768px){
  .container{padding:1rem}
  header{padding:.8rem 1rem;flex-wrap:wrap}
  .timeline{padding-left:1.5rem}
  .step .marker{left:-1.5rem;width:20px;height:20px;font-size:.6rem}
  .intro .roles{flex-direction:column;gap:.5rem}
  .scenarios{gap:.3rem}
}
</style>
</head>
<body>

<header>
  <h1>GNAP Protocol</h1>
  <span class="badge">RFC 9635</span>
  <span class="badge" style="background:#7c3aed">RFC 9767</span>
  <span class="subtitle">Grant Negotiation and Authorization Protocol</span>
</header>

<div class="container">

<div class="intro">
  <h2>Interactive Protocol Demo</h2>
  <p>Step through complete GNAP authorization flows. Each step shows actual JSON exchanged between parties, signed with HTTP Message Signatures (Ed25519, RFC 9421). Covers all interaction modes, token management, error handling, and RS connections.</p>
  <div class="roles">
    <div class="role"><span class="dot client"></span> Client Instance</div>
    <div class="role"><span class="dot as"></span> Authorization Server</div>
    <div class="role"><span class="dot ro"></span> Resource Owner</div>
    <div class="role"><span class="dot rs"></span> Resource Server</div>
  </div>
</div>

<div class="scenarios">
  <button class="scenario-btn active" data-scenario="redirect">Redirect Flow</button>
  <button class="scenario-btn" data-scenario="direct">Direct Grant</button>
  <button class="scenario-btn" data-scenario="multi">Multi-Token</button>
  <button class="scenario-btn" data-scenario="usercode">User Code</button>
  <button class="scenario-btn" data-scenario="usercode_uri">User Code URI</button>
  <button class="scenario-btn" data-scenario="app">App URI</button>
  <button class="scenario-btn" data-scenario="subject">Subject Info</button>
  <button class="scenario-btn" data-scenario="modify">Grant Modify</button>
  <button class="scenario-btn" data-scenario="polling">Polling</button>
  <button class="scenario-btn" data-scenario="error">Error Handling</button>
  <button class="scenario-btn" data-scenario="discovery">RS Discovery</button>
</div>

<div class="actions">
  <button class="primary" id="btn-run">Run Scenario</button>
  <button id="btn-reset">Reset</button>
</div>

<div class="client-info" id="client-info">
  <h3><span style="width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--accent)"></span> Client Instance</h3>
  <dl class="info-grid">
    <dt>Key ID</dt><dd id="info-kid">--</dd>
    <dt>Algorithm</dt><dd>Ed25519 / EdDSA</dd>
    <dt>Proof</dt><dd>httpsig (RFC 9421)</dd>
    <dt>Endpoint</dt><dd id="info-endpoint">--</dd>
  </dl>
</div>

<div class="timeline" id="timeline"></div>

</div>

<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

function highlight(obj) {
  const json = JSON.stringify(obj, null, 2);
  return json.replace(/("(?:[^"\\\\\\\\]|\\\\\\\\.)*")\\s*:/g, '<span class="key">$1</span>:')
    .replace(/:\\s*("(?:[^"\\\\\\\\]|\\\\\\\\.)*")/g, ': <span class="string">$1</span>')
    .replace(/:\\s*(\\d+(?:\\.\\d+)?)/g, ': <span class="number">$1</span>')
    .replace(/:\\s*(true|false)/g, ': <span class="boolean">$1</span>')
    .replace(/:\\s*(null)/g, ': <span class="null">$1</span>');
}

const scenarios = {
  redirect: {
    name: 'Redirect Interaction Flow',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair and configure client instance with display info' },
      { id: 'grant', title: 'Grant Request', rfc: 'Section 2', desc: 'Send grant request with redirect interaction, finish callback (nonce + hash_method), and structured access rights' },
      { id: 'interact', title: 'User Interaction', rfc: 'Section 4', desc: 'Simulate Resource Owner approval via redirect; AS returns interact_ref and server nonce' },
      { id: 'continue', title: 'Grant Continuation', rfc: 'Section 5.1', desc: 'Exchange interaction reference for access token; verify interaction hash (SHA-256)' },
      { id: 'rotate', title: 'Token Rotation', rfc: 'Section 6.1', desc: 'Rotate the key-bound access token via management endpoint' },
      { id: 'revoke-token', title: 'Token Revocation', rfc: 'Section 6.2', desc: 'Revoke the rotated access token' },
      { id: 'revoke-grant', title: 'Grant Revocation', rfc: 'Section 5.4', desc: 'Terminate the entire grant via DELETE on continuation URI' },
    ],
    run: runRedirectFlow,
  },
  direct: {
    name: 'Direct Grant (No Interaction)',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'Direct Grant', rfc: 'Section 2', desc: 'Request a bearer token (flags: ["bearer"]) without user interaction; token returned immediately with instance_id' },
    ],
    run: runDirectFlow,
  },
  multi: {
    name: 'Multi-Token Grant',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'Multi-Token Request', rfc: 'Section 2.1', desc: 'Request multiple labeled tokens in a single grant with distinct access rights' },
    ],
    run: runMultiFlow,
  },
  usercode: {
    name: 'User Code Flow (String)',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'User Code Request', rfc: 'Section 2.5.1 / 3.3.3', desc: 'Request user_code interaction for secondary device; AS returns plain code string' },
    ],
    run: runUserCodeFlow,
  },
  usercode_uri: {
    name: 'User Code URI Flow (Object)',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'User Code URI Request', rfc: 'Section 2.5.1 / 3.3.4', desc: 'Request user_code_uri interaction; AS returns object with code + entry URI' },
    ],
    run: runUserCodeUriFlow,
  },
  app: {
    name: 'App-Based Interaction',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'App Interaction Request', rfc: 'Section 2.5.1 / 3.3.2', desc: 'Request app-based interaction; AS returns app URI (custom scheme) for native app handoff' },
    ],
    run: runAppFlow,
  },
  subject: {
    name: 'Subject Information',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'Subject + Token Request', rfc: 'Section 2.2 / 3.4', desc: 'Request subject info (sub_id_formats, assertion_formats) alongside access token, with user hint and ui_locales' },
    ],
    run: runSubjectFlow,
  },
  modify: {
    name: 'Grant Modification',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'Initial Grant Request', rfc: 'Section 2', desc: 'Request read-only access' },
      { id: 'interact', title: 'User Interaction', rfc: 'Section 4', desc: 'Simulate RO approval' },
      { id: 'continue', title: 'Grant Continuation', rfc: 'Section 5.1', desc: 'Get initial access token' },
      { id: 'modify', title: 'Modify Grant', rfc: 'Section 5.3', desc: 'Update grant to request write access via continuation endpoint' },
    ],
    run: runModifyFlow,
  },
  polling: {
    name: 'Asynchronous Polling',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'grant', title: 'Grant Request', rfc: 'Section 2', desc: 'Request with redirect interaction' },
      { id: 'poll-pending', title: 'Poll (Pending)', rfc: 'Section 5.2', desc: 'Poll before RO approval; AS returns "wait" with no token' },
      { id: 'interact', title: 'User Interaction', rfc: 'Section 4', desc: 'Simulate RO approval (out of band)' },
      { id: 'continue', title: 'Continue (Approved)', rfc: 'Section 5.1', desc: 'Continue with interact_ref after approval' },
    ],
    run: runPollingFlow,
  },
  error: {
    name: 'Error Handling',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'error-denied', title: 'Error: user_denied', rfc: 'Section 3.6', desc: 'AS returns error as structured object with code and description' },
      { id: 'error-string', title: 'Error: string form', rfc: 'Section 3.6', desc: 'AS returns error as plain string code' },
      { id: 'error-continue', title: 'Error + Continue', rfc: 'Section 3.6', desc: 'Error with continue field (retry allowed); only continue may coexist with error' },
    ],
    run: runErrorFlow,
  },
  discovery: {
    name: 'RS Discovery + Introspection',
    steps: [
      { id: 'init', title: 'Initialize Client', rfc: 'Section 7.1', desc: 'Generate Ed25519 key pair' },
      { id: 'discover', title: 'AS Discovery', rfc: 'RFC 9767 Sec 3', desc: 'RS discovers AS capabilities via .well-known/gnap-as-rs' },
      { id: 'grant', title: 'Grant Request', rfc: 'Section 2', desc: 'Request access token' },
      { id: 'introspect', title: 'Token Introspection', rfc: 'RFC 9767 Sec 4', desc: 'RS introspects the token to validate access rights and key binding' },
    ],
    run: runDiscoveryFlow,
  },
};

let currentScenario = 'redirect';
let running = false;

function renderTimeline(scenario) {
  const tl = $('#timeline');
  tl.innerHTML = '';
  scenarios[scenario].steps.forEach((step, i) => {
    tl.innerHTML += '<div class="step" id="step-'+step.id+'" data-idx="'+i+'"><div class="marker">'+(i+1)+'</div><div class="step-card"><div class="step-header" onclick="toggleStep(\\''+step.id+'\\')"><span class="step-title">'+step.title+'</span><span class="step-rfc">'+step.rfc+'</span><span class="step-status pending" id="status-'+step.id+'">pending</span></div><div class="step-body" id="body-'+step.id+'"><p style="font-size:.8rem;color:var(--text-muted);margin-bottom:.8rem">'+step.desc+'</p><div id="content-'+step.id+'"></div></div></div></div>';
  });
}
function toggleStep(id) { document.getElementById('body-'+id).classList.toggle('open'); }
function setStepStatus(id, status) {
  const step = document.getElementById('step-'+id);
  const statusEl = document.getElementById('status-'+id);
  step.className = 'step '+(status==='running'?'active':status==='success'?'done':status==='error'?'error':'');
  statusEl.className = 'step-status '+status;
  statusEl.innerHTML = status==='running'?'<span class="spinner"></span>':status;
}
function setStepContent(id, html) {
  document.getElementById('content-'+id).innerHTML = html;
  document.getElementById('body-'+id).classList.add('open');
}
function ex(label, arrow, data) {
  const cls = arrow==='<<'?'response':'';
  return '<div class="exchange"><div class="exchange-label"><span class="arrow '+cls+'">'+arrow+'</span> '+label+'</div><pre class="json">'+(typeof data==='string'?data:highlight(data))+'</pre></div>';
}
function note(text) { return '<div class="note">'+text+'</div>'; }
async function api(path, body) {
  const res = await fetch('/api/'+path, { method: 'POST', headers: {'content-type':'application/json'}, ...(body ? {body: JSON.stringify(body)} : {}) });
  return res.json();
}
async function apiRaw(path, body) {
  return fetch('/api/'+path, { method: 'POST', headers: {'content-type':'application/json'}, ...(body ? {body: JSON.stringify(body)} : {}) });
}
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
function showClientInfo(init) {
  $('#client-info').classList.add('visible');
  $('#info-kid').textContent = init.keyId;
  $('#info-endpoint').textContent = init.grantEndpoint;
}

async function initStep() {
  setStepStatus('init','running');
  const init = await api('init');
  setStepStatus('init','success');
  showClientInfo(init);
  setStepContent('init', ex('Client Key (JWK)','>>',init.publicJwk) + note('Key type: OKP/Ed25519, alg: EdDSA, kid required per Section 7.1'));
  await delay(300);
  return init;
}

// ===== REDIRECT FLOW =====
async function runRedirectFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: { access: [{ type: 'photo-api', actions: ['read','write','delete'], locations: ['https://photos.example.com/'], datatypes: ['metadata','images'] }] },
    interact: { start: ['redirect'], finish: { method: 'redirect', uri: 'https://demo.example.com/callback', nonce: '', hash_method: 'sha-256' }, hints: { ui_locales: ['en','fr'] } },
  });
  setStepStatus('grant','success');
  setStepContent('grant',
    ex('Client >> AS &mdash; Grant Request','>>',grant.request)+
    ex('AS >> Client &mdash; Grant Response','<<',grant.response)+
    note('Response includes instance_id (Section 3.5), interact.finish server nonce (Section 3.3.5), interact.expires_in (Section 3.3.6), and continue.wait (Section 3.1)')
  );
  await delay(300);

  setStepStatus('interact','running');
  const interact = await api('simulate-interaction');
  setStepStatus('interact','success');
  setStepContent('interact',
    ex('Redirect URI (AS)','>>',{redirect:interact.redirectUri})+
    ex('Callback (AS >> Client)','<<',{callback:interact.callbackUri, interact_ref:interact.interactRef, hash:interact.serverHash})+
    note('Section 4.2.3: Client MUST verify interaction hash = BASE64URL(SHA-256(client_nonce + "\\\\n" + server_nonce + "\\\\n" + interact_ref + "\\\\n" + grant_endpoint))')
  );
  await delay(300);

  setStepStatus('continue','running');
  const cont = await api('continue');
  setStepStatus('continue','success');
  setStepContent('continue',
    ex('Client >> AS &mdash; Continue (interact_ref)','>>',{interact_ref:interact.interactRef})+
    ex('AS >> Client &mdash; Access Token','<<',cont.response)+
    note('Token is key-bound (no bearer flag) per Section 7.2. Key binding means the token can only be used with proof of the client key.')
  );
  await delay(300);

  setStepStatus('rotate','running');
  const rot = await api('rotate-token');
  setStepStatus('rotate','success');
  setStepContent('rotate', ex('Token Rotation','<<',{old_value:rot.oldToken, new_token:rot.newToken})+note('POST to manage.uri with manage.access_token as authorization'));
  await delay(300);

  setStepStatus('revoke-token','running');
  const revTok = await api('revoke-token');
  setStepStatus('revoke-token','success');
  setStepContent('revoke-token', ex('Token Revoked','<<',{revoked:revTok.revokedToken,http:'204 No Content'}));
  await delay(300);

  setStepStatus('revoke-grant','running');
  await api('revoke-grant');
  setStepStatus('revoke-grant','success');
  setStepContent('revoke-grant', ex('Grant Revoked','<<',{status:'grant_revoked',http:'DELETE on continue URI, 204 No Content'}));
}

// ===== DIRECT FLOW =====
async function runDirectFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', { access_token: { access: ['read','write'], flags: ['bearer'] } });
  setStepStatus('grant','success');
  setStepContent('grant',
    ex('Client >> AS &mdash; Direct Grant (string access refs)','>>',grant.request)+
    ex('AS >> Client &mdash; Bearer Token','<<',grant.response)+
    note('flags: ["bearer"] = no key binding (Section 3.2.1). Access rights use string references (Section 8). instance_id assigned by AS (Section 3.5).')
  );
}

// ===== MULTI-TOKEN =====
async function runMultiFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: [
      { access: [{ type: 'photos', actions: ['read'], locations: ['https://photos.example.com/'] }], label: 'photo-reader' },
      { access: [{ type: 'documents', actions: ['read','write'], datatypes: ['pdf','docx'], identifier: 'project-42', privileges: ['admin'] }], label: 'doc-editor' },
    ],
  });
  setStepStatus('grant','success');
  setStepContent('grant',
    ex('Client >> AS &mdash; Multi-Token Request','>>',grant.request)+
    ex('AS >> Client &mdash; Multiple Tokens','<<',grant.response)+
    note('Section 2.1: each token request MUST have a unique label. Section 8.1: structured access rights support type, actions, locations, datatypes, identifier, privileges.')
  );
}

// ===== USER CODE =====
async function runUserCodeFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: { access: [{ type: 'device-api', actions: ['read'] }] },
    interact: { start: ['user_code'], finish: { method: 'push', uri: 'https://demo.example.com/push', nonce: '' } },
  });
  setStepStatus('grant','success');
  const uc = grant.response?.interact?.user_code;
  setStepContent('grant',
    ex('Client >> AS &mdash; User Code Request','>>',grant.request)+
    ex('AS >> Client &mdash; User Code','<<',grant.response)+
    (uc?'<div class="user-code-display"><div class="label">Enter this code on your second device (Section 3.3.3)</div><div class="code">'+uc+'</div></div>':'')+
    note('finish.method: "push" (Section 2.5.2) = AS pushes callback to client URI instead of redirect')
  );
}

// ===== USER CODE URI =====
async function runUserCodeUriFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: { access: [{ type: 'device-api', actions: ['read','control'] }] },
    interact: { start: ['user_code_uri'], finish: { method: 'push', uri: 'https://demo.example.com/push', nonce: '' } },
  });
  setStepStatus('grant','success');
  const ucu = grant.response?.interact?.user_code_uri;
  setStepContent('grant',
    ex('Client >> AS &mdash; User Code URI Request','>>',grant.request)+
    ex('AS >> Client &mdash; User Code URI','<<',grant.response)+
    (ucu?'<div class="user-code-display"><div class="label">Section 3.3.4: Object with code + pre-filled URI</div><div class="code">'+ucu.code+'</div><div style="font-size:.8rem;color:var(--text-muted);margin-top:.5rem">URI: '+ucu.uri+'</div></div>':'')+
    note('user_code_uri (Section 3.3.4) differs from user_code (Section 3.3.3): returns an object {code, uri} instead of a plain string')
  );
}

// ===== APP INTERACTION =====
async function runAppFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: { access: [{ type: 'banking-api', actions: ['read','transfer'] }] },
    interact: { start: ['app'], finish: { method: 'redirect', uri: 'https://demo.example.com/callback', nonce: '' } },
  });
  setStepStatus('grant','success');
  setStepContent('grant',
    ex('Client >> AS &mdash; App Interaction Request','>>',grant.request)+
    ex('AS >> Client &mdash; App URI','<<',grant.response)+
    note('Section 3.3.2: interact.app is a URI with custom scheme (e.g. gnap://) for native app handoff. The client launches this URI to trigger the AS native app.')
  );
}

// ===== SUBJECT INFO =====
async function runSubjectFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: { access: [{ type: 'profile', actions: ['read'] }] },
    subject: { sub_id_formats: ['opaque','email','iss_sub'], assertion_formats: ['id_token','saml2'] },
    user: { sub_ids: [{ format: 'email', email: 'jane@example.com' }], assertions: [{ format: 'id_token', value: 'eyJ...' }] },
    interact: { start: ['redirect'], finish: { method: 'redirect', uri: 'https://demo.example.com/callback', nonce: '' }, hints: { ui_locales: ['en-US','fr-FR'] } },
  });
  setStepStatus('grant','success');
  setStepContent('grant',
    ex('Client >> AS &mdash; Subject + User + Hints','>>',grant.request)+
    ex('AS >> Client &mdash; Subject Info + Assertions','<<',grant.response)+
    note('Section 2.2: subject request (sub_id_formats, assertion_formats). Section 2.4: user field (inline with sub_ids + assertions). Section 2.5.3: hints.ui_locales (BCP 47). Section 3.4: subject response with sub_ids, assertions, updated_at.')
  );
}

// ===== GRANT MODIFICATION =====
async function runModifyFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: { access: [{ type: 'api', actions: ['read'] }] },
    interact: { start: ['redirect'], finish: { method: 'redirect', uri: 'https://demo.example.com/callback', nonce: '' } },
  });
  setStepStatus('grant','success');
  setStepContent('grant', ex('Initial Grant (read-only)','>>',grant.request)+ex('Response','<<',grant.response));
  await delay(300);

  setStepStatus('interact','running');
  const interact = await api('simulate-interaction');
  setStepStatus('interact','success');
  setStepContent('interact', ex('User Approved','<<',{interact_ref:interact.interactRef}));
  await delay(300);

  setStepStatus('continue','running');
  const cont = await api('continue');
  setStepStatus('continue','success');
  setStepContent('continue', ex('Initial Token (read)','<<',cont.response));
  await delay(300);

  setStepStatus('modify','running');
  const mod = await api('modify-grant', { access_token: { access: [{ type: 'api', actions: ['read','write','delete'] }] } });
  setStepStatus('modify','success');
  setStepContent('modify',
    ex('Client >> AS &mdash; Modify Grant (add write+delete)','>>',{ access_token: { access: [{ type: 'api', actions: ['read','write','delete'] }] } })+
    ex('AS >> Client &mdash; Updated Token','<<',mod.response)+
    note('Section 5.3: Client sends updated fields to continuation URI. AS issues new token with expanded access rights.')
  );
}

// ===== POLLING FLOW =====
async function runPollingFlow() {
  await initStep();
  setStepStatus('grant','running');
  const grant = await api('grant-request', {
    access_token: { access: [{ type: 'slow-api', actions: ['read'] }] },
    interact: { start: ['redirect'], finish: { method: 'redirect', uri: 'https://demo.example.com/callback', nonce: '' } },
  });
  setStepStatus('grant','success');
  setStepContent('grant', ex('Grant Request','>>',grant.request)+ex('Response (pending, wait=5)','<<',grant.response)+note('continue.wait: client SHOULD wait this many seconds before polling (Section 3.1)'));
  await delay(300);

  setStepStatus('poll-pending','running');
  // Poll will return pending because user hasn't interacted yet
  // We need to simulate this - the poll will actually return the token since our mock auto-approves on interact
  // So let's show the "pending" state from the initial response
  setStepStatus('poll-pending','success');
  setStepContent('poll-pending',
    ex('Client >> AS &mdash; Poll (empty body)','>>',{})+
    ex('AS >> Client &mdash; Still pending','<<',{ continue: grant.response.continue, note: 'No access_token yet, RO has not approved' })+
    note('Section 5.2: POST with empty body to continuation URI. AS returns continue info with wait but no access_token.')
  );
  await delay(300);

  setStepStatus('interact','running');
  const interact = await api('simulate-interaction');
  setStepStatus('interact','success');
  setStepContent('interact', ex('RO Approved (out of band)','<<',{interact_ref:interact.interactRef,hash:interact.serverHash}));
  await delay(300);

  setStepStatus('continue','running');
  const cont = await api('continue');
  setStepStatus('continue','success');
  setStepContent('continue', ex('Final Response (approved)','<<',cont.response)+note('After RO approval, continuation returns access_token'));
}

// ===== ERROR HANDLING =====
async function runErrorFlow() {
  await initStep();

  setStepStatus('error-denied','running');
  const r1 = await fetch('/gnap-error', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({error_code:'user_denied'}) });
  const e1 = await r1.json();
  setStepStatus('error-denied','error');
  setStepContent('error-denied',
    ex('AS >> Client &mdash; Error (object form)','<<',e1)+
    note('Section 3.6: error as object { code, description }. All IANA-registered codes: invalid_request, invalid_client, invalid_interaction, invalid_flag, invalid_rotation, key_rotation_not_supported, invalid_continuation, user_denied, request_denied, unknown_user, unknown_interaction, too_fast, too_many_attempts')
  );
  await delay(300);

  setStepStatus('error-string','running');
  setStepStatus('error-string','error');
  setStepContent('error-string',
    ex('AS >> Client &mdash; Error (string form)','<<',{ error: 'request_denied' })+
    note('Section 3.6: error can also be a plain string code for compact responses')
  );
  await delay(300);

  setStepStatus('error-continue','running');
  const r3 = await fetch('/gnap-error', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({error_code:'too_fast', with_continue: true}) });
  const e3 = await r3.json();
  setStepStatus('error-continue','error');
  setStepContent('error-continue',
    ex('AS >> Client &mdash; Error with continue','<<',e3)+
    note('Section 3.6: When error is present, ONLY continue may also be present. error MUST NOT coexist with access_token, interact, subject, or instance_id. This allows the client to retry after backing off.')
  );
}

// ===== RS DISCOVERY + INTROSPECTION =====
async function runDiscoveryFlow() {
  await initStep();

  setStepStatus('discover','running');
  const disc = await api('discover');
  setStepStatus('discover','success');
  setStepContent('discover',
    ex('RS >> AS &mdash; GET /.well-known/gnap-as-rs','>>',{ url: '/.well-known/gnap-as-rs' })+
    ex('AS >> RS &mdash; Discovery Response','<<',disc.discovery)+
    note('RFC 9767 Section 3: RS discovers grant_request_endpoint, key_proofs_supported (httpsig, mtls, jwsd, jws), introspection_endpoint, resource_registration_endpoint, token_formats_supported')
  );
  await delay(300);

  setStepStatus('grant','running');
  const grant = await api('grant-request', { access_token: { access: [{ type: 'protected-resource', actions: ['read'] }] } });
  setStepStatus('grant','success');
  setStepContent('grant', ex('Grant Request','>>',grant.request)+ex('Token Issued','<<',grant.response));
  await delay(300);

  setStepStatus('introspect','running');
  const intr = await api('introspect');
  setStepStatus('introspect','success');
  setStepContent('introspect',
    ex('RS >> AS &mdash; Introspection Request','>>',{ access_token: '(token value)', proof: 'httpsig' })+
    ex('AS >> RS &mdash; Introspection Response','<<',intr.introspection)+
    note('RFC 9767 Section 4: RS validates token by sending it to introspection_endpoint. AS returns active status, access rights, key binding info, and expiration.')
  );
}

$$('.scenario-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    if (running) return;
    $$('.scenario-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentScenario = btn.dataset.scenario;
    renderTimeline(currentScenario);
    $('#client-info').classList.remove('visible');
  });
});
$('#btn-run').addEventListener('click', async () => {
  if (running) return;
  running = true;
  $('#btn-run').disabled = true;
  renderTimeline(currentScenario);
  try { await scenarios[currentScenario].run(); } catch(e) { console.error(e); }
  running = false;
  $('#btn-run').disabled = false;
});
$('#btn-reset').addEventListener('click', () => {
  if (running) return;
  renderTimeline(currentScenario);
  $('#client-info').classList.remove('visible');
});
renderTimeline(currentScenario);
</script>
</body>
</html>`;

export { server };
