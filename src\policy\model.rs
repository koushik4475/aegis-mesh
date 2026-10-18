use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    RateLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub description: Option<String>,
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    pub required_roles: Vec<String>,
    pub required_claims: Option<HashMap<String, String>>,
    pub action: Action,
    pub priority: u32,
    pub rate_limit_rps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub version: String,
    pub service_name: String,
    pub default_action: Action,
    pub rules: Vec<PolicyRule>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            version: "v1".to_string(),
            service_name: "default-mesh-service".to_string(),
            default_action: Action::Deny,
            rules: Vec::new(),
        }
    }
}
