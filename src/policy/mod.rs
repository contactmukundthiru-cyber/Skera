//! Policy engine — `.skera.toml` configuration for compliance rules
//!
//! Allows projects to define allowed/blocked licenses, ignored paths,
//! severity thresholds, and per-dependency overrides. This is what makes
//! Skera CI/CD-ready (competitive with FOSSA/Snyk policy features).

use crate::detection::{Severity, Violation, ViolationType};
use crate::license::LicenseId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Project-level policy configuration (loaded from `.skera.toml`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Licenses that are explicitly allowed
    #[serde(default)]
    pub allowed_licenses: Vec<String>,

    /// Licenses that are explicitly blocked (any match = fail)
    #[serde(default)]
    pub blocked_licenses: Vec<String>,

    /// Violation types to ignore
    #[serde(default)]
    pub ignored_violations: Vec<String>,

    /// Glob patterns for paths to exclude from scanning
    #[serde(default)]
    pub ignore_paths: Vec<String>,

    /// Minimum severity to report (violations below this are filtered)
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Maximum acceptable risk score (scan fails if exceeded)
    #[serde(default = "default_max_risk")]
    pub max_risk_score: u32,

    /// Per-dependency overrides
    #[serde(default)]
    pub overrides: Vec<DependencyOverride>,

    /// Whether to treat this as a commercial project
    #[serde(default = "default_true")]
    pub commercial: bool,

    /// Whether this is a network/SaaS service
    #[serde(default)]
    pub network_service: bool,
}

fn default_min_severity() -> String {
    "low".to_string()
}
fn default_max_risk() -> u32 {
    100
}
fn default_true() -> bool {
    true
}

/// Per-dependency policy override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyOverride {
    /// Dependency name (e.g., "lodash")
    pub name: String,
    /// Allowed license for this specific dependency
    pub allowed_license: Option<String>,
    /// Completely ignore this dependency
    #[serde(default)]
    pub ignore: bool,
    /// Reason for the override (for audit trail)
    pub reason: Option<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allowed_licenses: vec![],
            blocked_licenses: vec![],
            ignored_violations: vec![],
            ignore_paths: vec!["vendor/".into(), "third_party/".into(), "node_modules/".into()],
            min_severity: "low".into(),
            max_risk_score: 100,
            overrides: vec![],
            commercial: true,
            network_service: false,
        }
    }
}

/// The policy engine that evaluates scan results against project policy
pub struct PolicyEngine {
    config: PolicyConfig,
    blocked_set: HashSet<String>,
    allowed_set: HashSet<String>,
    ignored_violations: HashSet<String>,
}

impl PolicyEngine {
    /// Load policy from a `.skera.toml` file
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file: {}", e))?;
        let config: PolicyConfig =
            toml::from_str(&content).map_err(|e| format!("Failed to parse policy: {}", e))?;
        Ok(Self::new(config))
    }

    /// Try to load from project root, fall back to default
    pub fn from_project_root(root: &Path) -> Self {
        let policy_path = root.join(".skera.toml");
        if policy_path.exists() {
            match Self::from_file(&policy_path) {
                Ok(engine) => {
                    tracing::info!("Loaded policy from {}", policy_path.display());
                    return engine;
                }
                Err(e) => {
                    tracing::warn!("Failed to load {}: {} — using defaults", policy_path.display(), e);
                }
            }
        }

        // Also check skera.toml (without dot)
        let alt_path = root.join("skera.toml");
        if alt_path.exists() {
            match Self::from_file(&alt_path) {
                Ok(engine) => {
                    tracing::info!("Loaded policy from {}", alt_path.display());
                    return engine;
                }
                Err(e) => {
                    tracing::warn!("Failed to load {}: {} — using defaults", alt_path.display(), e);
                }
            }
        }

        Self::new(PolicyConfig::default())
    }

    pub fn new(config: PolicyConfig) -> Self {
        let blocked_set: HashSet<String> = config
            .blocked_licenses
            .iter()
            .map(|l| l.to_uppercase())
            .collect();
        let allowed_set: HashSet<String> = config
            .allowed_licenses
            .iter()
            .map(|l| l.to_uppercase())
            .collect();
        let ignored_violations: HashSet<String> = config
            .ignored_violations
            .iter()
            .cloned()
            .collect();

        Self {
            config,
            blocked_set,
            allowed_set,
            ignored_violations,
        }
    }

    /// Check if a license is explicitly blocked
    pub fn is_blocked(&self, license: &LicenseId) -> bool {
        self.blocked_set.contains(&license.as_str().to_uppercase())
    }

    /// Check if a license is explicitly allowed
    pub fn is_allowed(&self, license: &LicenseId) -> bool {
        self.allowed_set.is_empty() || self.allowed_set.contains(&license.as_str().to_uppercase())
    }

    /// Check if a path should be excluded from scanning
    pub fn is_excluded_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().replace('\\', "/");
        self.config
            .ignore_paths
            .iter()
            .any(|pattern| path_str.contains(pattern))
    }

    /// Check if a violation type is ignored by policy
    pub fn is_ignored_violation(&self, vtype: &ViolationType) -> bool {
        let type_name = format!("{:?}", vtype);
        self.ignored_violations.contains(&type_name)
    }

    /// Check if a dependency has an override
    pub fn get_override(&self, dep_name: &str) -> Option<&DependencyOverride> {
        self.config
            .overrides
            .iter()
            .find(|o| o.name == dep_name)
    }

    /// Apply policy to filter and annotate violations
    pub fn apply(&self, violations: &mut Vec<Violation>) {
        let min_sev = parse_severity(&self.config.min_severity);

        violations.retain(|v| {
            // Filter by minimum severity
            if v.severity < min_sev {
                return false;
            }

            // Filter by ignored violation types
            if self.is_ignored_violation(&v.violation_type) {
                return false;
            }

            // Filter by excluded paths
            if v.files.iter().any(|f| self.is_excluded_path(f)) {
                return false;
            }

            true
        });

        // Add blocked-license violations
        // (These are checked by the caller against discovered dependencies)
    }

    /// Generate policy-specific violations for blocked licenses in dependencies
    pub fn check_blocked_licenses(&self, deps: &[(String, LicenseId)]) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (name, license) in deps {
            // Skip overridden deps
            if let Some(ovr) = self.get_override(name) {
                if ovr.ignore {
                    continue;
                }
            }

            if self.is_blocked(license) {
                violations.push(Violation {
                    violation_type: ViolationType::Custom(format!(
                        "Policy: blocked license '{}'",
                        license
                    )),
                    severity: Severity::Critical,
                    confidence: 1.0,
                    description: format!(
                        "Dependency '{}' uses blocked license '{}' (policy: .skera.toml)",
                        name, license
                    ),
                    files: vec![],
                    licenses: vec![license.clone()],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: Some(license.clone()),
                });
            }

            if !self.is_allowed(license) {
                violations.push(Violation {
                    violation_type: ViolationType::Custom(format!(
                        "Policy: unapproved license '{}'",
                        license
                    )),
                    severity: Severity::High,
                    confidence: 1.0,
                    description: format!(
                        "Dependency '{}' uses unapproved license '{}' (not in allowed list)",
                        name, license
                    ),
                    files: vec![],
                    licenses: vec![license.clone()],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: Some(license.clone()),
                });
            }
        }

        violations
    }

    /// Check if risk score exceeds policy threshold
    pub fn exceeds_risk_threshold(&self, score: u32) -> bool {
        score > self.config.max_risk_score
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        assert!(!engine.is_blocked(&LicenseId::new("MIT")));
        assert!(engine.is_allowed(&LicenseId::new("MIT"))); // empty allowed = allow all
    }

    #[test]
    fn test_blocked_license() {
        let config = PolicyConfig {
            blocked_licenses: vec!["AGPL-3.0".into(), "SSPL-1.0".into()],
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.is_blocked(&LicenseId::new("AGPL-3.0")));
        assert!(!engine.is_blocked(&LicenseId::new("MIT")));
    }

    #[test]
    fn test_allowed_license_whitelist() {
        let config = PolicyConfig {
            allowed_licenses: vec!["MIT".into(), "Apache-2.0".into()],
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.is_allowed(&LicenseId::new("MIT")));
        assert!(!engine.is_allowed(&LicenseId::new("GPL-3.0")));
    }

    #[test]
    fn test_excluded_path() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        assert!(engine.is_excluded_path(Path::new("project/vendor/lib/file.js")));
        assert!(engine.is_excluded_path(Path::new("project/node_modules/lodash/index.js")));
        assert!(!engine.is_excluded_path(Path::new("project/src/main.rs")));
    }

    #[test]
    fn test_policy_toml_parse() {
        let toml_str = r#"
            allowed_licenses = ["MIT", "Apache-2.0", "BSD-2-Clause"]
            blocked_licenses = ["AGPL-3.0"]
            ignored_violations = ["MissingSpdxHeader"]
            ignore_paths = ["vendor/", "generated/"]
            min_severity = "medium"
            max_risk_score = 50
            commercial = true

            [[overrides]]
            name = "lodash"
            ignore = true
            reason = "Reviewed and approved internally"
        "#;
        let config: PolicyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.allowed_licenses.len(), 3);
        assert_eq!(config.blocked_licenses, vec!["AGPL-3.0"]);
        assert_eq!(config.max_risk_score, 50);
        assert_eq!(config.overrides.len(), 1);
        assert!(config.overrides[0].ignore);
    }
}
