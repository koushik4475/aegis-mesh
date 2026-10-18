use aegis_mesh::proxy::cert::{CertificateManager, MeshIdentity};
use aegis_mesh::proxy::limiter::TokenBucketLimiter;
use aegis_mesh::proxy::validator::TokenValidator;
use std::collections::HashMap;

#[test]
fn test_mtls_spiffe_generation_and_tls_config() {
    let identity = MeshIdentity::new("auth-service", "prod", "aegis.internal");
    assert_eq!(identity.spiffe_id(), "spiffe://aegis.internal/ns/prod/sa/auth-service");

    let cert_mgr = CertificateManager::generate_ephemeral(identity).expect("Failed generating certs");
    let server_cfg = cert_mgr.build_server_config();
    assert!(server_cfg.is_ok(), "ServerConfig building failed");

    let client_cfg = cert_mgr.build_client_config();
    assert!(client_cfg.is_ok(), "ClientConfig building failed");
}

#[test]
fn test_token_validator_roundtrip() {
    let validator = TokenValidator::new("secret-key-for-mesh-32-bytes-auth!", "issuer.mesh", "service.mesh");
    let mut custom = HashMap::new();
    custom.insert("tenant".to_string(), "t-100".to_string());

    let token = validator
        .issue_token("service-a", vec!["admin".to_string()], custom, 3600)
        .expect("Issue token failed");

    let auth_header = format!("Bearer {}", token);
    let claims = validator.validate_header(&auth_header).expect("Validation failed");

    assert_eq!(claims.sub, "service-a");
    assert_eq!(claims.roles, vec!["admin"]);
    assert_eq!(claims.custom.get("tenant").unwrap(), "t-100");
}

#[test]
fn test_token_bucket_limiter() {
    let limiter = TokenBucketLimiter::new(2, 1);
    assert!(limiter.check_allowed("client-ip-1", Some(2)));
    assert!(limiter.check_allowed("client-ip-1", Some(2)));
    assert!(!limiter.check_allowed("client-ip-1", Some(2))); // Exhausted capacity
}
