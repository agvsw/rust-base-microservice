use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub preferred_username: String,
    pub email: Option<String>,
    pub exp: usize,
    pub realm_access: RealmAccess,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    kty: String,
}

pub async fn validate_jwt(token: &str) -> Result<Claims, String> {
    let header = decode_header(token).map_err(|e| format!("Header error: {}", e))?;
    let kid = header.kid.ok_or("No `kid` found in token")?;

    let realm = env::var("KEYCLOAK_REALM").map_err(|_| "KEYCLOAK_REALM not set")?;
    let url = format!(
        "{}/realms/{}/protocol/openid-connect/certs",
        env::var("KEYCLOAK_URL").map_err(|_| "KEYCLOAK_URL not set")?,
        realm
    );

    let jwks: Jwks = Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;

    let jwk = jwks
        .keys
        .into_iter()
        .find(|k| k.kid == kid)
        .ok_or("Matching JWK not found")?;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| format!("DecodingKey error: {}", e))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| format!("Token decode error: {}", e))?;

    Ok(token_data.claims)
}
