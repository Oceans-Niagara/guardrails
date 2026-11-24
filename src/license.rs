use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_compact::{PublicKey, Signature};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LicenseClaims {
    pub org: String,
    pub tier: String,      // "free" | "pro" | "enterprise"
    pub expires_unix: u64, // 0 = perpetual
}

pub fn verify_license(token: &str, pubkey_bytes: &[u8; 32], now_unix: u64) -> anyhow::Result<LicenseClaims> {
    let (payload_b64, sig_b64) = token
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("Malformed license key"))?;

    let payload = URL_SAFE_NO_PAD.decode(payload_b64)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;

    let pk = PublicKey::from_slice(pubkey_bytes)?;
    let sig = Signature::from_slice(&sig_bytes)?;
    pk.verify(&payload, &sig)
        .map_err(|_| anyhow::anyhow!("Invalid Ed25519 license signature"))?;

    let claims: LicenseClaims = serde_json::from_slice(&payload)?;
    if claims.expires_unix != 0 && now_unix > claims.expires_unix {
        anyhow::bail!("License expired for {}", claims.org);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    fn make_token(kp: &KeyPair, org: &str, tier: &str, expires_unix: u64) -> String {
        let payload = serde_json::json!({
            "org": org,
            "tier": tier,
            "expires_unix": expires_unix
        })
        .to_string()
        .into_bytes();
        let sig = kp.sk.sign(&payload, None);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(sig.as_ref())
        )
    }

    #[test]
    fn verifies_valid_tampered_and_expired_licenses() {
        let kp = KeyPair::from_seed(Seed::new([7u8; 32]));
        let pk: [u8; 32] = *kp.pk;

        let token = make_token(&kp, "Acme", "pro", 2000);
        let claims = verify_license(&token, &pk, 1000).expect("valid token should pass");
        assert_eq!(claims.org, "Acme");
        assert_eq!(claims.tier, "pro");

        // Expired
        assert!(verify_license(&token, &pk, 3000).is_err());

        // Tampered payload
        let mut tampered = token.clone();
        tampered.replace_range(0..1, if tampered.starts_with('A') { "B" } else { "A" });
        assert!(verify_license(&tampered, &pk, 1000).is_err());

        // Perpetual (expires_unix = 0)
        let perpetual = make_token(&kp, "Acme", "enterprise", 0);
        assert!(verify_license(&perpetual, &pk, 9_999_999_999).is_ok());
    }
}