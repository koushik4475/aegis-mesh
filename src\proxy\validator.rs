use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Invalid JWT structure: {0}")]
    Malformed(String),
    #[error("Token expired or inactive")]
    Expired,
    #[error("Signature verification failed")]
    SignatureInvalid,
    #[error("Missing authorization bearer prefix")]
    MissingBearer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthClaims {
    pub sub: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iss: String,
    pub aud: String,
    #[serde(flatten)]
    pub custom: HashMap<String, String>,
}

/// Zero-Trust Token Validator verifying signatures, issuer, and RBAC roles
#[derive(Clone)]
pub struct TokenValidator {
    secret: String,
    expected_issuer: String,
    expected_audience: String,
}

impl TokenValidator {
    pub fn new(secret: impl Into<String>, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            expected_issuer: issuer.into(),
            expected_audience: audience.into(),
        }
    }

    /// Issue signed token for mesh testing and peer communication
    pub fn issue_token(&self, sub: &str, roles: Vec<String>, custom: HashMap<String, String>, exp_secs: u64) -> Result<String, TokenError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = AuthClaims {
            sub: sub.to_string(),
            roles,
            exp: (now + exp_secs) as usize,
            iss: self.expected_issuer.clone(),
            aud: self.expected_audience.clone(),
            custom,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| TokenError::Malformed(e.to_string()))
    }

    /// Extract and validate bearer token
    pub fn validate_header(&self, auth_header: &str) -> Result<AuthClaims, TokenError> {
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(TokenError::MissingBearer)?
            .trim();

        self.validate_token(token)
    }

    /// Verify signature and extract valid AuthClaims
    pub fn validate_token(&self, token: &str) -> Result<AuthClaims, TokenError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.expected_issuer]);
        validation.set_audience(&[&self.expected_audience]);

        let token_data = decode::<AuthClaims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::Expired,
            jsonwebtoken::errors::ErrorKind::InvalidSignature => TokenError::SignatureInvalid,
            _ => TokenError::Malformed(e.to_string()),
        })?;

        Ok(token_data.claims)
    }
}
