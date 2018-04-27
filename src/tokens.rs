extern crate jsonwebtoken as jwt;

use self::jwt::{decode, encode, Header, Validation};
use auth::AuthToken;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    uid: u32,
    adm: bool,
}

pub fn build_token(secret: &str, uid: u32, adm: bool) -> String {
    let claims = Claims {
        iss: "wish-api".to_owned(),
        uid,
        adm,
    };

    let token = encode(&Header::default(), &claims, secret.as_bytes()).unwrap();
    token
}

pub fn validate_token(secret: &str, token: &str) -> Result<AuthToken, ()> {
    let validation = Validation {
        iss: Some("wish-api".to_string()),
        ..Default::default()
    };
    let tok = decode::<Claims>(&token, secret.as_bytes(), &validation);

    match tok {
        Ok(t) => Ok(AuthToken {
            uid: t.claims.uid,
            adm: t.claims.adm,
        }),
        Err(_) => Err(()),
    }
}
