interface Env {
  STRIPE_WEBHOOK_SECRET: string;
  STRIPE_SECRET_KEY: string;
  RESEND_API_KEY: string;
  ED25519_JWK: string;
  FROM_EMAIL?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method !== "POST" || url.pathname !== "/webhook") {
        return new Response("Not found", { status: 404 });
      }

      const sigHeader = request.headers.get("stripe-signature");
      if (!sigHeader) {
        return new Response("Missing Stripe-Signature", { status: 400 });
      }

      const rawBody = await request.text();
      const valid = await verifyStripeSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
      if (!valid) {
        return new Response("Invalid signature", { status: 401 });
      }

      const event = JSON.parse(rawBody) as {
        id: string;
        type: string;
        data: { object: Record<string, any> };
      };

      if (event.type !== "checkout.session.completed") {
        return new Response("Ignored event", { status: 200 });
      }

      const session = event.data.object;
      const email: string | undefined = session.customer_details?.email ?? session.customer_email;
      if (!email) {
        return new Response("Missing customer email", { status: 400 });
      }

      const org: string = session.customer_details?.name || email;
      const tier = await resolveTier(session, env.STRIPE_SECRET_KEY);

      const expiresUnix = session.mode === "subscription"
        ? Math.floor(Date.now() / 1000) + 366 * 24 * 60 * 60
        : 0;

      const licenseKey = await signLicense({ org, tier, expires_unix: expiresUnix }, env.ED25519_JWK);
      await sendLicenseEmail(email, org, tier, licenseKey, event.id, env);

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } catch (err: any) {
      return new Response(`Worker Error: ${err?.message || String(err)}`, { status: 500 });
    }
  },
};

async function resolveTier(session: Record<string, any>, stripeKey: string): Promise<string> {
  if (session.metadata?.tier) {
    return String(session.metadata.tier);
  }
  // Product metadata isn't copied onto Checkout Sessions automatically; fetch expanded line items
  const resp = await fetch(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(session.id)}/line_items?expand[]=data.price.product`,
    {
      headers: { Authorization: `Bearer ${stripeKey}` },
      signal: AbortSignal.timeout(10_000),
    }
  );
  if (!resp.ok) {
    throw new Error(`Stripe line_items fetch failed: ${resp.status}`);
  }
  const data = (await resp.json()) as { data?: Array<{ price?: { product?: { metadata?: { tier?: string } } } }> };
  return data.data?.[0]?.price?.product?.metadata?.tier ?? "pro";
}

async function signLicense(
  claims: { org: string; tier: string; expires_unix: number },
  jwkJson: string
): Promise<string> {
  const jwk = JSON.parse(jwkJson) as JsonWebKey;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
  const payloadBytes = new TextEncoder().encode(JSON.stringify(claims));
  const sigBuf = await crypto.subtle.sign("Ed25519", key, payloadBytes);
  return `${toBase64Url(payloadBytes)}.${toBase64Url(new Uint8Array(sigBuf))}`;
}

async function sendLicenseEmail(
  to: string,
  org: string,
  tier: string,
  licenseKey: string,
  eventId: string,
  env: Env
): Promise<void> {
  const from = env.FROM_EMAIL ?? "Guardrails <licenses@oceansniagara.com>";
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
      "Idempotency-Key": eventId,
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject: `Your Guardrails (${tier}) License Key`,
      text: [
        `Hi ${org},`,
        "",
        `Thanks for purchasing Guardrails (${tier}). Here is your offline Ed25519 license key:`,
        "",
        licenseKey,
        "",
        "Quickstart:",
        "  export GUARDRAILS_LICENSE_KEY=\"" + licenseKey + "\"",
        "  guardrails license-check",
        "  guardrails resilience",
      ].join("\n"),
    }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Resend failed (${resp.status}): ${body}`);
  }
}

async function verifyStripeSignature(rawBody: string, header: string, secret: string): Promise<boolean> {
  const parts = Object.fromEntries(header.split(",").map((kv) => kv.split("=") as [string, string]));
  const ts = Number(parts.t);
  const v1Hex = parts.v1;
  if (!ts || !v1Hex || Math.abs(Math.floor(Date.now() / 1000) - ts) > 300) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${ts}.${rawBody}`))
  );
  const expected = hexToBytes(v1Hex);
  if (!expected || expected.length !== mac.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < mac.length; i++) {
    diff |= mac[i] ^ expected[i];
  }
  return diff === 0;
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}