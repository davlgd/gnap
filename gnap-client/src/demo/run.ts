#!/usr/bin/env bun
/**
 * GNAP Client Demo -- Interactive demonstration of the protocol flow.
 *
 * Starts a mock AS server, then runs the client through:
 * 1. Grant request with redirect interaction
 * 2. Simulated user interaction (auto-approve)
 * 3. Continuation with interact_ref
 * 4. Token usage demonstration
 * 5. Token rotation
 * 6. Token revocation
 * 7. Grant revocation
 *
 * Usage: bun run src/demo/run.ts
 */

import { GnapClient } from "../client.ts";
import type { AccessToken } from "../types/token.ts";

const PORT = 3456;
const GRANT_ENDPOINT = `http://localhost:${PORT}/gnap`;

process.env["GNAP_PORT"] = String(PORT);

// Start mock AS
const { server } = await import("./server.ts");

async function sleep(ms: number) {
  return Bun.sleep(ms);
}

function step(n: number, title: string) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`  Step ${n}: ${title}`);
  console.log("=".repeat(60));
}

async function main() {
  console.log("\n--- GNAP Protocol Demo (RFC 9635) ---\n");

  // Initialize client
  const client = new GnapClient({
    grantEndpoint: GRANT_ENDPOINT,
    displayName: "GNAP Demo Client",
    displayUri: "https://demo.example.com",
  });
  await client.init();

  console.log("Client initialized with key:", client.keyId);
  console.log("Public JWK:", JSON.stringify(client.publicJwk, null, 2));

  // Step 1: Grant Request with redirect interaction
  step(1, "Grant Request (redirect interaction)");

  const grantResponse = await client.requestGrant({
    access_token: {
      access: [
        {
          type: "photo-api",
          actions: ["read", "write", "delete"],
          locations: ["https://photos.example.com/"],
          datatypes: ["metadata", "images"],
        },
      ],
    },
    interact: {
      start: ["redirect"],
      finish: {
        method: "redirect",
        uri: "https://demo.example.com/callback",
        nonce: "",
      },
    },
  });

  console.log("\nGrant Response:");
  console.log(JSON.stringify(grantResponse, null, 2));

  // Step 2: Simulate user interaction
  step(2, "User Interaction (simulated)");

  if (grantResponse.interact?.redirect) {
    console.log(`Redirect user to: ${grantResponse.interact.redirect}`);
    console.log("Simulating user approval...");

    // Auto-approve by hitting the interact endpoint
    const interactRes = await fetch(grantResponse.interact.redirect, {
      redirect: "manual",
    });

    const location = interactRes.headers.get("location");
    console.log(`AS redirected to: ${location}`);

    if (location) {
      const callbackUrl = new URL(location);
      const interactRef = callbackUrl.searchParams.get("interact_ref")!;
      const serverHash = callbackUrl.searchParams.get("hash")!;

      console.log(`Interact ref: ${interactRef}`);
      console.log(`Server hash: ${serverHash}`);

      // Step 3: Continue grant
      step(3, "Grant Continuation (post-interaction)");

      const finalResponse = await client.continueGrant(interactRef, serverHash);

      console.log("\nFinal Grant Response:");
      console.log(JSON.stringify(finalResponse, null, 2));

      // Step 4: Use the token
      const token = client.getAccessToken();
      if (token) {
        step(4, "Access Token Obtained");
        console.log(`Token value: ${token.value}`);
        console.log(`Expires in: ${token.expires_in}s`);
        console.log(`Access rights: ${JSON.stringify(token.access)}`);
        if (token.manage) {
          console.log(`Management URI: ${token.manage.uri}`);
        }

        // Step 5: Token rotation
        step(5, "Token Rotation");
        const newToken = await client.rotateToken(token);
        console.log(`Old token: ${token.value}`);
        console.log(`New token: ${newToken.value}`);

        // Step 6: Token revocation
        step(6, "Token Revocation");
        await client.revokeToken(newToken);
        console.log("Token revoked successfully");
      }

      // Step 7: Grant revocation
      step(7, "Grant Revocation");
      await client.revokeGrant();
      console.log("Grant revoked successfully");
    }
  }

  // Bonus: Direct grant (no interaction)
  step(8, "Direct Grant (no interaction)");

  const directResponse = await client.requestGrant({
    access_token: {
      access: ["read"],
      flags: ["bearer"],
    },
  });

  console.log("\nDirect Grant Response:");
  console.log(JSON.stringify(directResponse, null, 2));

  const directToken = client.getAccessToken();
  if (directToken) {
    console.log(`\nBearer token obtained: ${directToken.value}`);
    console.log(`Flags: ${JSON.stringify(directToken.flags)}`);
  }

  // Bonus: Multi-token request
  step(9, "Multi-Token Grant Request");

  const multiResponse = await client.requestGrant({
    access_token: [
      {
        access: [{ type: "photos", actions: ["read"] }],
        label: "photo-reader",
      },
      {
        access: [{ type: "documents", actions: ["read", "write"] }],
        label: "doc-editor",
      },
    ],
  });

  console.log("\nMulti-Token Response:");
  console.log(JSON.stringify(multiResponse, null, 2));

  // Bonus: User code flow
  step(10, "User Code Flow");

  const userCodeResponse = await client.requestGrant({
    access_token: {
      access: [{ type: "device-api", actions: ["read"] }],
    },
    interact: {
      start: ["user_code"],
      finish: {
        method: "push",
        uri: "https://demo.example.com/push-callback",
        nonce: "",
      },
    },
  });

  console.log("\nUser Code Response:");
  console.log(JSON.stringify(userCodeResponse, null, 2));
  if (userCodeResponse.interact?.user_code) {
    console.log(
      `\nUser code to enter on second device: ${userCodeResponse.interact.user_code}`,
    );
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log("  Demo complete!");
  console.log("=".repeat(60));

  server.stop();
  process.exit(0);
}

main().catch((err) => {
  console.error("Demo failed:", err);
  server.stop();
  process.exit(1);
});
