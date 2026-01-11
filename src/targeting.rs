//! Request targeting and matching logic.

use crate::config::{PathMatcher, Targeting};
use rand::Rng;
use regex::Regex;
use std::collections::HashMap;

/// Compiled targeting rules for efficient matching.
pub struct CompiledTargeting {
    paths: Vec<CompiledPathMatcher>,
    methods: Vec<String>,
    headers: HashMap<String, String>,
    percentage: u8,
}

enum CompiledPathMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

impl CompiledTargeting {
    /// Compile targeting rules from configuration.
    pub fn new(targeting: &Targeting) -> Self {
        let paths = targeting
            .paths
            .iter()
            .filter_map(|p| match p {
                PathMatcher::Exact { exact } => Some(CompiledPathMatcher::Exact(exact.clone())),
                PathMatcher::Prefix { prefix } => Some(CompiledPathMatcher::Prefix(prefix.clone())),
                PathMatcher::Regex { regex } => {
                    Regex::new(regex).ok().map(CompiledPathMatcher::Regex)
                }
            })
            .collect();

        let methods = targeting
            .methods
            .iter()
            .map(|m| m.to_uppercase())
            .collect();

        Self {
            paths,
            methods,
            headers: targeting.headers.clone(),
            percentage: targeting.percentage,
        }
    }

    /// Check if a request matches the targeting rules.
    pub fn matches(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> bool {
        // Check method if specified
        if !self.methods.is_empty() && !self.methods.contains(&method.to_uppercase()) {
            return false;
        }

        // Check path if specified
        if !self.paths.is_empty() && !self.matches_path(path) {
            return false;
        }

        // Check headers if specified
        if !self.matches_headers(headers) {
            return false;
        }

        true
    }

    /// Check if the request should be affected based on percentage.
    pub fn should_apply(&self) -> bool {
        if self.percentage >= 100 {
            return true;
        }
        if self.percentage == 0 {
            return false;
        }
        let mut rng = rand::thread_rng();
        rng.gen_range(0..100) < self.percentage
    }

    fn matches_path(&self, path: &str) -> bool {
        self.paths.iter().any(|matcher| match matcher {
            CompiledPathMatcher::Exact(s) => path == s,
            CompiledPathMatcher::Prefix(s) => path.starts_with(s),
            CompiledPathMatcher::Regex(r) => r.is_match(path),
        })
    }

    fn matches_headers(&self, headers: &HashMap<String, String>) -> bool {
        for (name, expected_value) in &self.headers {
            let name_lower = name.to_lowercase();
            let found = headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower);

            match found {
                Some((_, value)) if value == expected_value => continue,
                _ => return false,
            }
        }
        true
    }
}

/// Check if a path matches any of the excluded paths.
pub fn is_excluded_path(path: &str, excluded_paths: &[String]) -> bool {
    excluded_paths.iter().any(|excluded| {
        path == excluded || path.starts_with(&format!("{}/", excluded))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Targeting;

    fn create_targeting(
        paths: Vec<PathMatcher>,
        methods: Vec<&str>,
        headers: HashMap<&str, &str>,
        percentage: u8,
    ) -> Targeting {
        Targeting {
            paths,
            methods: methods.into_iter().map(String::from).collect(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            percentage,
        }
    }

    #[test]
    fn test_exact_path_matching() {
        let targeting = create_targeting(
            vec![PathMatcher::Exact { exact: "/api/users".to_string() }],
            vec![],
            HashMap::new(),
            100,
        );
        let compiled = CompiledTargeting::new(&targeting);

        assert!(compiled.matches("GET", "/api/users", &HashMap::new()));
        assert!(!compiled.matches("GET", "/api/users/123", &HashMap::new()));
        assert!(!compiled.matches("GET", "/api", &HashMap::new()));
    }

    #[test]
    fn test_prefix_path_matching() {
        let targeting = create_targeting(
            vec![PathMatcher::Prefix { prefix: "/api/".to_string() }],
            vec![],
            HashMap::new(),
            100,
        );
        let compiled = CompiledTargeting::new(&targeting);

        assert!(compiled.matches("GET", "/api/users", &HashMap::new()));
        assert!(compiled.matches("GET", "/api/orders/123", &HashMap::new()));
        assert!(!compiled.matches("GET", "/health", &HashMap::new()));
    }

    #[test]
    fn test_regex_path_matching() {
        let targeting = create_targeting(
            vec![PathMatcher::Regex { regex: r"^/api/v\d+/.*".to_string() }],
            vec![],
            HashMap::new(),
            100,
        );
        let compiled = CompiledTargeting::new(&targeting);

        assert!(compiled.matches("GET", "/api/v1/users", &HashMap::new()));
        assert!(compiled.matches("GET", "/api/v2/orders", &HashMap::new()));
        assert!(!compiled.matches("GET", "/api/users", &HashMap::new()));
    }

    #[test]
    fn test_method_matching() {
        let targeting = create_targeting(
            vec![],
            vec!["GET", "POST"],
            HashMap::new(),
            100,
        );
        let compiled = CompiledTargeting::new(&targeting);

        assert!(compiled.matches("GET", "/test", &HashMap::new()));
        assert!(compiled.matches("POST", "/test", &HashMap::new()));
        assert!(compiled.matches("get", "/test", &HashMap::new())); // Case insensitive
        assert!(!compiled.matches("DELETE", "/test", &HashMap::new()));
    }

    #[test]
    fn test_header_matching() {
        let targeting = create_targeting(
            vec![],
            vec![],
            HashMap::from([("x-chaos-enabled", "true")]),
            100,
        );
        let compiled = CompiledTargeting::new(&targeting);

        let mut headers = HashMap::new();
        headers.insert("x-chaos-enabled".to_string(), "true".to_string());
        assert!(compiled.matches("GET", "/test", &headers));

        headers.insert("x-chaos-enabled".to_string(), "false".to_string());
        assert!(!compiled.matches("GET", "/test", &headers));

        let empty_headers = HashMap::new();
        assert!(!compiled.matches("GET", "/test", &empty_headers));
    }

    #[test]
    fn test_header_matching_case_insensitive() {
        let targeting = create_targeting(
            vec![],
            vec![],
            HashMap::from([("X-Chaos-Enabled", "true")]),
            100,
        );
        let compiled = CompiledTargeting::new(&targeting);

        let mut headers = HashMap::new();
        headers.insert("x-chaos-enabled".to_string(), "true".to_string());
        assert!(compiled.matches("GET", "/test", &headers));
    }

    #[test]
    fn test_combined_matching() {
        let targeting = create_targeting(
            vec![PathMatcher::Prefix { prefix: "/api/".to_string() }],
            vec!["POST"],
            HashMap::from([("x-test", "yes")]),
            100,
        );
        let compiled = CompiledTargeting::new(&targeting);

        let mut headers = HashMap::new();
        headers.insert("x-test".to_string(), "yes".to_string());

        // All conditions match
        assert!(compiled.matches("POST", "/api/users", &headers));

        // Wrong method
        assert!(!compiled.matches("GET", "/api/users", &headers));

        // Wrong path
        assert!(!compiled.matches("POST", "/health", &headers));

        // Missing header
        assert!(!compiled.matches("POST", "/api/users", &HashMap::new()));
    }

    #[test]
    fn test_empty_targeting_matches_all() {
        let targeting = create_targeting(vec![], vec![], HashMap::new(), 100);
        let compiled = CompiledTargeting::new(&targeting);

        assert!(compiled.matches("GET", "/anything", &HashMap::new()));
        assert!(compiled.matches("POST", "/whatever", &HashMap::new()));
    }

    #[test]
    fn test_percentage_zero_never_applies() {
        let targeting = create_targeting(vec![], vec![], HashMap::new(), 0);
        let compiled = CompiledTargeting::new(&targeting);

        // Run multiple times to ensure it never applies
        for _ in 0..100 {
            assert!(!compiled.should_apply());
        }
    }

    #[test]
    fn test_percentage_100_always_applies() {
        let targeting = create_targeting(vec![], vec![], HashMap::new(), 100);
        let compiled = CompiledTargeting::new(&targeting);

        // Run multiple times to ensure it always applies
        for _ in 0..100 {
            assert!(compiled.should_apply());
        }
    }

    #[test]
    fn test_excluded_paths() {
        let excluded = vec!["/health".to_string(), "/ready".to_string()];

        assert!(is_excluded_path("/health", &excluded));
        assert!(is_excluded_path("/health/live", &excluded));
        assert!(is_excluded_path("/ready", &excluded));
        assert!(!is_excluded_path("/api/users", &excluded));
        assert!(!is_excluded_path("/healthy", &excluded));
    }
}
