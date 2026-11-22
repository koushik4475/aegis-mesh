use regex::Regex;
use std::collections::HashMap;
use std::sync::RwLock;

/// High-performance compiled regex path matcher
pub struct RouteMatcher {
    // An invalid pattern is cached as None and must never become a permissive match.
    compiled_patterns: RwLock<HashMap<String, Option<Regex>>>,
}

impl RouteMatcher {
    pub fn new() -> Self {
        Self {
            compiled_patterns: RwLock::new(HashMap::new()),
        }
    }

    /// Checks if a request path matches a wildcard pattern (e.g. /api/v1/orders/*, /users/**)
    pub fn matches_path(&self, pattern: &str, path: &str) -> bool {
        if pattern == "*" || pattern == "/**" {
            return true;
        }

        if pattern == path {
            return true;
        }

        let mut lock = self.compiled_patterns.write().unwrap();
        let compiled = lock.entry(pattern.to_string()).or_insert_with(|| {
            let mut regex_str = String::from("^");
            let mut chars = pattern.chars().peekable();
            while let Some(c) = chars.next() {
                match c {
                    '*' => {
                        if chars.peek() == Some(&'*') {
                            chars.next();
                            regex_str.push_str(".*");
                        } else {
                            regex_str.push_str("[^/]*");
                        }
                    }
                    '\\' | '.' | '+' | '?' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' => {
                        regex_str.push('\\');
                        regex_str.push(c);
                    }
                    _ => regex_str.push(c),
                }
            }
            regex_str.push('$');

            // Never turn a malformed policy pattern into a match-all expression.
            Regex::new(&regex_str).ok()
        });

        compiled.as_ref().is_some_and(|regex| regex.is_match(path))
    }

    /// Matches HTTP methods (GET, POST, etc.) with wildcard '*' support
    pub fn matches_method(&self, allowed_methods: &[String], method: &str) -> bool {
        if allowed_methods.is_empty() {
            return true;
        }
        allowed_methods.iter().any(|m| m == "*" || m.eq_ignore_ascii_case(method))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_patterns() {
        let matcher = RouteMatcher::new();
        assert!(matcher.matches_path("/api/v1/users", "/api/v1/users"));
        assert!(matcher.matches_path("/api/v1/*", "/api/v1/orders"));
        assert!(!matcher.matches_path("/api/v1/*", "/api/v1/orders/123"));
        assert!(matcher.matches_path("/api/v1/**", "/api/v1/orders/123/items"));
        assert!(matcher.matches_path("/**", "/any/nested/path"));
        assert!(matcher.matches_method(&["GET".into(), "POST".into()], "get"));
        assert!(!matcher.matches_method(&["GET".into()], "DELETE"));
    }

    #[test]
    fn test_backslash_in_policy_pattern_is_literal_and_cannot_match_everything() {
        let matcher = RouteMatcher::new();
        assert!(matcher.matches_path(r"/api/\\q", r"/api/\\q"));
        assert!(!matcher.matches_path(r"/api/\\q", "/unrelated/path"));
    }
}
