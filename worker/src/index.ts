interface Env {
  STRIPE_WEBHOOK_SECRET: string;
  STRIPE_SECRET_KEY: string;
  RESEND_API_KEY: string;
  ED25519_JWK: string;
  FROM_EMAIL?: string;
}

const RELEASES_URL = "https://github.com/oceans-niagara/guardrails/releases/latest";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // 1. Post-checkout browser lookup (?session_id=cs_...)
    if (request.method === "GET" && url.pathname === "/claim") {
      const sessionId = url.searchParams.get("session_id");
      if (!sessionId) {
        return jsonResponse({ error: "Missing session_id" }, 400);
      }

      const resp = await fetch(
        `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`,
        { headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` } }
      );
      if (!resp.ok) {
        return jsonResponse({ error: "Invalid or expired checkout session" }, 404);
      }

      const session = (await resp.json()) as Record<string, any>;
      if (session.payment_status !== "paid" && session.status !== "complete") {
        return jsonResponse({ error: "Payment not completed yet" }, 402);
      }

      const email: string | undefined = session.customer_details?.email ?? session.customer_email;
      const org: string = session.customer_details?.name || email || "Customer";
      const tier = await resolveTier(session, env.STRIPE_SECRET_KEY);
      const license = await signLicense({ org, tier, expires_unix: 0 }, env.ED25519_JWK);

      return jsonResponse({ ok: true, tier, holder: org, license, releases_url: RELEASES_URL }, 200);
    }

    // 2. Stripe Webhook (/webhook)
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
    const licenseKey = await signLicense({ org, tier, expires_unix: 0 }, env.ED25519_JWK);

    await sendLicenseEmail(email, org, tier, licenseKey, event.id, env);

    return jsonResponse({ ok: true }, 200);
  },
};

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

async function resolveTier(session: Record<string, any>, stripeKey: string): Promise<string> {
  if (session.metadata?.tier) {
    return String(session.metadata.tier);
  }
  const resp = await fetch(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(session.id)}/line_items?expand[]=data.price.product`,
    {
      headers: { Authorization: `Bearer ${stripeKey}` },
      signal: AbortSignal.timeout(10_000),
    }
  );
  if (!resp.ok) {
    return "pro";
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
  const tierLabel = tier.toUpperCase();

  const html = `
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:0 auto;color:#111;line-height:1.6;">
      <h2 style="margin-bottom:4px;">Guardrails ${tierLabel} License</h2>
      <p style="color:#555;margin-top:0;">Issued to <strong>${escapeHtml(org)}</strong> &bull; Perpetual offline license</p>
      <p>Thanks for purchasing Guardrails ${tierLabel}. Save your offline Ed25519 license key below:</p>
      <div style="background:#f7f7f7;border:1px solid #111;border-radius:5px;padding:12px 14px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;word-break:break-all;margin:16px 0;">
        ${escapeHtml(licenseKey)}
      </div>

      <h3 style="font-size:15px;margin-bottom:6px;">1. Download the Prebuilt Binary (No Rust Required)</h3>
      <p style="margin-top:0;font-size:14px;color:#333;">
        Download the standalone executable for your OS from
        <a href="${RELEASES_URL}" style="color:#111;font-weight:600;">GitHub Releases</a>
        and place it in your project folder (or on your <code>PATH</code>):
      </p>
      <ul style="font-size:13px;color:#333;padding-left:20px;margin-top:4px;">
        <li><strong>Windows (x86_64):</strong> <code>guardrails-windows-x86_64.exe</code></li>
        <li><strong>macOS (Apple Silicon):</strong> <code>guardrails-macos-arm64</code></li>
        <li><strong>macOS (Intel):</strong> <code>guardrails-macos-x86_64</code></li>
        <li><strong>Linux (x86_64):</strong> <code>guardrails-linux-x86_64</code></li>
      </ul>
      <p style="font-size:12px;color:#666;margin-top:4px;">
        Prefer building from source? Run <code>cargo install --git https://github.com/oceans-niagara/guardrails</code>.
      </p>

      <h3 style="font-size:15px;margin-bottom:6px;">2. Verify Offline &amp; Initialize Your Project</h3>
      <pre style="background:#f7f7f7;border:1px solid #e5e5e5;border-radius:5px;padding:12px 14px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;overflow-x:auto;"># Windows (PowerShell — inside your project folder)
$env:GUARDRAILS_LICENSE_KEY="${escapeHtml(licenseKey)}"
.\\guardrails-windows-x86_64.exe license-check
.\\guardrails-windows-x86_64.exe init
.\\guardrails-windows-x86_64.exe check

# macOS / Linux (replace binary name for your OS/arch)
chmod +x ./guardrails-macos-arm64
export GUARDRAILS_LICENSE_KEY="${escapeHtml(licenseKey)}"
./guardrails-macos-arm64 license-check
./guardrails-macos-arm64 init
./guardrails-macos-arm64 check</pre>
      <p style="font-size:12px;color:#666;margin-top:6px;">
        Tip: Rename the binary to <code>guardrails</code> (or <code>guardrails.exe</code>) on your <code>PATH</code> to run <code>guardrails</code> from any folder.
      </p>

      <p style="font-size:13px;color:#666;margin-top:24px;border-top:1px solid #e5e5e5;padding-top:12px;">
        Oceans Niagara, LLC &bull; Need help? Reply to this email or contact <a href="mailto:connect@oceansniagara.com" style="color:#111;">connect@oceansniagara.com</a>
      </p>
    </div>
  `;

  const text = [
    `Guardrails ${tierLabel} License`,
    `Issued to: ${org} (Perpetual offline license)`,
    "",
    "Your offline Ed25519 license key:",
    licenseKey,
    "",
    "1. Download the Prebuilt Binary (No Rust Required):",
    `   ${RELEASES_URL}`,
    "   - Windows (x86_64):        guardrails-windows-x86_64.exe",
    "   - macOS (Apple Silicon):   guardrails-macos-arm64",
    "   - macOS (Intel):           guardrails-macos-x86_64",
    "   - Linux (x86_64):          guardrails-linux-x86_64",
    "   (Or build from source: cargo install --git https://github.com/oceans-niagara/guardrails)",
    "",
    "2. Verify Offline & Initialize Your Project:",
    "",
    "# Windows (PowerShell — from your project folder):",
    `  $env:GUARDRAILS_LICENSE_KEY="${licenseKey}"`,
    "  .\\guardrails-windows-x86_64.exe license-check",
    "  .\\guardrails-windows-x86_64.exe init",
    "  .\\guardrails-windows-x86_64.exe check",
    "",
    "# macOS / Linux (use the binary matching your OS/arch):",
    "  chmod +x ./guardrails-macos-arm64",
    `  export GUARDRAILS_LICENSE_KEY="${licenseKey}"`,
    "  ./guardrails-macos-arm64 license-check",
    "  ./guardrails-macos-arm64 init",
    "  ./guardrails-macos-arm64 check",
    "",
    "Tip: Rename the binary to guardrails (or guardrails.exe) on your PATH to run it from anywhere.",
    "",
    "Questions? Contact connect@oceansniagara.com",
  ].join("\n");

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
      reply_to: "connect@oceansniagara.com",
      subject: `Your Guardrails ${tierLabel} License Key`,
      html,
      text,
    }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Resend failed (${resp.status}): ${body}`);
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
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