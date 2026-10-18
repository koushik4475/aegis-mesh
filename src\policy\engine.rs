use super::matcher::RouteMatcher;
use super::model::{Action, PolicyRule, SecurityPolicy};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub client_identity: Option<String>,
    pub roles: Vec<String>,
    pub claims: HashMap<String, String>,
    pub method: String,
    pub path: String,
    pub source_ip: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow { rule_name: String },
    Deny { reason: String },
    RateLimit { rule_name: String, limit_rps: u32 },
}

/// Dynamic zero-trust RBAC and route policy evaluation engine
pub struct PolicyEngine {
    policy: Arc<dashmap::RwLock<SecurityPolicy>>,
    matcher: RouteMatcher,
}

impl PolicyEngine {
    pub fn new(policy: SecurityPolicy) -> Self {
        Self {
            policy: Arc::new(dashmap::RwLock::new(policy)),
            matcher: RouteMatcher::new(),
        }
    }

    /// Load or dynamically hot-reload policy rules without downtime
    pub fn update_policy(&self, new_policy: SecurityPolicy) {
        let mut p = self.policy.write();
        info!(
            service = %new_policy.service_name,
            rules_count = new_policy.rules.len(),
            "Hot-reloaded dynamic security policy"
        );
        *p = new_policy;
    }

    /// Evaluates incoming request context against dynamic RBAC and route rules
    pub fn evaluate(&self, ctx: &RequestContext) -> PolicyDecision {
        let policy_guard = self.policy.read();

        // Sort rules by priority descending
        let mut sorted_rules = policy_guard.rules.clone();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in &sorted_rules {
            if self.rule_matches(rule, ctx) {
                debug!(
                    rule_name = %rule.name,
                    action = ?rule.action,
                    path = %ctx.path,
                    "Rule matched request context"
                );

                match rule.action {
                    Action::Allow => {
                        return PolicyDecision::Allow {
                            rule_name: rule.name.clone(),
                        }
                    }
                    Action::Deny => {
                        return PolicyDecision::Deny {
                            reason: format!("Forbidden by rule '{}'", rule.name),
                        }
                    }
                    Action::RateLimit => {
                        return PolicyDecision::RateLimit {
                            rule_name: rule.name.clone(),
                            limit_rps: rule.rate_limit_rps.unwrap_or(100),
                        }
                    }
                }
            }
        }

        // Fallback to default action
        match policy_guard.default_action {
            Action::Allow => PolicyDecision::Allow {
                rule_name: "default_allow".into(),
            },
            Action::Deny => PolicyDecision::Deny {
                reason: "Default zero-trust policy deny".into(),
            },
            Action::RateLimit => PolicyDecision::RateLimit {
                rule_name: "default_ratelimit".into(),
                limit_rps: 50,
            },
        }
    }

    fn rule_matches(&self, rule: &PolicyRule, ctx: &RequestContext) -> bool {
        // 1. Method check
        if !self.matcher.matches_method(&rule.methods, &ctx.method) {
            return false;
        }

        // 2. Path check
        let path_matched = rule.paths.iter().any(|pattern| self.matcher.matches_path(pattern, &ctx.path));
        if !path_matched {
            return false;
        }

        // 3. RBAC role check
        if !rule.required_roles.is_empty() {
            let has_role = rule
                .required_roles
                .iter()
                .any(|req_role| req_role == "*" || ctx.roles.contains(req_role));
            if !has_role {
                return false;
            }
        }

        // 4. Custom token claims check
        if let Some(ref required_claims) = rule.required_claims {
            for (key, val) in required_claims {
                if ctx.claims.get(key) != Some(val) {
                    return false;
                }
            }
        }

        true
    }
}
