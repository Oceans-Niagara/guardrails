use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_compact::{KeyPair, Seed};
use rand::RngCore;
use serde::Serialize;

#[derive(Serialize)]
struct LicenseClaims<'a> {
    org: &'a str,
    tier: &'a str,
    expires_unix: u64,
}

fn main() {
    let mut seed_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
    let kp = KeyPair::from_seed(Seed::new(seed_bytes));

    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(kp.pk.as_ref()),
        "d": URL_SAFE_NO_PAD.encode(seed_bytes),
    });

    let claims = LicenseClaims {
        org: "AcmeCorp",
        tier: "pro",
        expires_unix: 0,
    };
    let payload = serde_json::to_vec(&claims).unwrap();
    let sig = kp.sk.sign(&payload, None);
    let sample = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(sig.as_ref())
    );

    println!("// Paste into src/main.rs:");
    println!("const EMBEDDED_LICENSE_PUBKEY: [u8; 32] = {:?};\n", *kp.pk);
    println!("// Keep SECRET! Paste into `wrangler secret put ED25519_JWK`:");
    println!("{jwk}\n");
    println!("// Sample token for local verification:");
    println!("{sample}");
}