use aegis_mesh::policy::engine::{PolicyDecision, PolicyEngine, RequestContext};
use aegis_mesh::policy::model::{Action, PolicyRule, SecurityPolicy};
use std::collections::HashMap;

#[test]
fn test_zero_trust_policy_engine_allow_and_deny() {
    let policy = SecurityPolicy {
        version: "v1".into(),
        service_name: "payment-service".into(),
        default_action: Action::Deny,
        rules: vec![
            PolicyRule {
                name: "allow-health".into(),
                description: None,
                paths: vec!["/healthz".into()],
                methods: vec!["GET".into()],
                required_roles: vec![],
                required_claims: None,
                action: Action::Allow,
                priority: 10,
                rate_limit_rps: None,
            },
            PolicyRule {
                name: "admin-settlement".into(),
                description: None,
                paths: vec!["/api/v1/settle".into()],
                methods: vec!["POST".into()],
                required_roles: vec!["finance-admin".into()],
                required_claims: None,
                action: Action::Allow,
                priority: 20,
                rate_limit_rps: None,
            },
        ],
    };

    let engine = PolicyEngine::new(policy);

    // 1. Health check should be allowed
    let health_ctx = RequestContext {
        client_identity: None,
        roles: vec![],
        claims: HashMap::new(),
        method: "GET".into(),
        path: "/healthz".into(),
        source_ip: "10.0.0.1".into(),
    };
    assert_eq!(
        engine.evaluate(&health_ctx),
        PolicyDecision::Allow {
            rule_name: "allow-health".into()
        }
    );

    // 2. Settle with unauthorized role should be denied by zero trust default
    let unauth_ctx = RequestContext {
        client_identity: Some("user-123".into()),
        roles: vec!["customer".into()],
        claims: HashMap::new(),
        method: "POST".into(),
        path: "/api/v1/settle".into(),
        source_ip: "10.0.0.2".into(),
    };
    match engine.evaluate(&unauth_ctx) {
        PolicyDecision::Deny { .. } => assert!(true),
        other => panic!("Expected Deny, got {:?}", other),
    }

    // 3. Settle with finance-admin role should be allowed
    let auth_ctx = RequestContext {
        client_identity: Some("admin-user".into()),
        roles: vec!["finance-admin".into()],
        claims: HashMap::new(),
        method: "POST".into(),
        path: "/api/v1/settle".into(),
        source_ip: "10.0.0.3".into(),
    };
    assert_eq!(
        engine.evaluate(&auth_ctx),
        PolicyDecision::Allow {
            rule_name: "admin-settlement".into()
        }
    );
}

#[test]
fn test_policy_rate_limit_decision() {
    let policy = SecurityPolicy {
        version: "v1".into(),
        service_name: "analytics".into(),
        default_action: Action::Deny,
        rules: vec![PolicyRule {
            name: "analytics-ratelimit".into(),
            description: None,
            paths: vec!["/analytics/**".into()],
            methods: vec!["POST".into()],
            required_roles: vec!["telemetry".into()],
            required_claims: None,
            action: Action::RateLimit,
            priority: 15,
            rate_limit_rps: Some(250),
        }],
    };

    let engine = PolicyEngine::new(policy);
    let ctx = RequestContext {
        client_identity: Some("device-4".into()),
        roles: vec!["telemetry".into()],
        claims: HashMap::new(),
        method: "POST".into(),
        path: "/analytics/events/batch".into(),
        source_ip: "10.0.0.4".into(),
    };

    assert_eq!(
        engine.evaluate(&ctx),
        PolicyDecision::RateLimit {
            rule_name: "analytics-ratelimit".into(),
            limit_rps: 250
        }
    );
}
