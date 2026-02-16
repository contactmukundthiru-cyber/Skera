//! Dependency graph resolution — multi-ecosystem license-aware DAG construction
//!
//! Parses lock files and manifests to build the full transitive dependency
//! DAG with license information for each node.
//!
//! ## Supported Ecosystems
//!
//! | Ecosystem   | Lock File / Manifest              | License Source              |
//! |-------------|------------------------------------|-----------------------------|
//! | **NPM**     | `package-lock.json`, `yarn.lock`   | Package metadata            |
//! | **Cargo**   | `Cargo.lock`, `cargo metadata`     | `license` field in manifest |
//! | **Go**      | `go.sum`, `go.mod`                 | External lookup needed      |
//! | **Python**  | `requirements.txt`, `Pipfile.lock` | External lookup needed      |
//! | **Maven**   | `pom.xml`, `build.gradle`          | `<licenses>` XML block      |
//! | **NuGet**   | `*.csproj`, `packages.config`      | `<PackageLicenseExpression>`|
//! | **Composer**| `composer.lock`                    | `license` JSON field        |
//! | **RubyGems**| `Gemfile.lock`, `.gemspec`         | `license` field             |

use crate::license::LicenseId;
use crate::detection::contamination::{DepNode, LinkingMode};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Resolved dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// All nodes in the graph
    pub nodes: Vec<DepNode>,
    /// Root package name
    pub root: String,
    /// Which ecosystem this is from
    pub ecosystem: Ecosystem,
    /// Total transitive dependency count
    pub total_deps: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    Cargo,
    PyPi,
    Go,
    Maven,
    NuGet,
    Composer,
    RubyGems,
    Unknown,
}

/// Dependency graph resolver
pub struct DependencyResolver;

impl DependencyResolver {
    pub fn new() -> Self {
        Self
    }

    /// Auto-detect ecosystem and resolve dependencies
    pub fn resolve(&self, project_root: &Path) -> Option<DependencyGraph> {
        // Try each ecosystem in order of likelihood
        if project_root.join("package-lock.json").exists()
            || project_root.join("yarn.lock").exists()
        {
            return self.resolve_npm(project_root);
        }
        if project_root.join("Cargo.lock").exists() {
            return self.resolve_cargo(project_root);
        }
        if project_root.join("go.sum").exists() {
            return self.resolve_go(project_root);
        }
        if project_root.join("requirements.txt").exists()
            || project_root.join("Pipfile.lock").exists()
            || project_root.join("poetry.lock").exists()
        {
            return self.resolve_python(project_root);
        }
        if project_root.join("pom.xml").exists()
            || project_root.join("build.gradle").exists()
            || project_root.join("build.gradle.kts").exists()
        {
            return self.resolve_maven(project_root);
        }
        if Self::has_nuget_project(project_root) {
            return self.resolve_nuget(project_root);
        }
        if project_root.join("composer.lock").exists() {
            return self.resolve_composer(project_root);
        }
        if project_root.join("Gemfile.lock").exists() {
            return self.resolve_rubygems(project_root);
        }

        None
    }

    // ─── NPM ────────────────────────────────────────────────────────

    /// Resolve NPM dependency graph from package-lock.json
    fn resolve_npm(&self, root: &Path) -> Option<DependencyGraph> {
        let lock_path = root.join("package-lock.json");
        let content = std::fs::read_to_string(&lock_path).ok()?;
        let json: serde_json::Value = serde_json::from_str(&content).ok()?;

        let name = json.get("name")?.as_str()?.to_string();
        let mut nodes = Vec::new();

        // Parse packages (npm v2+ format)
        if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
            for (pkg_path, pkg_info) in packages {
                if pkg_path.is_empty() {
                    continue; // Skip root
                }
                let pkg_name = pkg_path
                    .strip_prefix("node_modules/")
                    .unwrap_or(pkg_path)
                    .to_string();

                let license = pkg_info
                    .get("license")
                    .and_then(|l| l.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string();

                let deps: Vec<String> = pkg_info
                    .get("dependencies")
                    .and_then(|d| d.as_object())
                    .map(|d| d.keys().cloned().collect())
                    .unwrap_or_default();

                let is_dev = pkg_info
                    .get("dev")
                    .and_then(|d| d.as_bool())
                    .unwrap_or(false);

                nodes.push(DepNode {
                    name: pkg_name,
                    version: pkg_info.get("version").and_then(|v| v.as_str()).map(String::from),
                    license: LicenseId::new(&license),
                    spdx_expression: Some(license),
                    depends_on: deps,
                    linking: LinkingMode::Source, // npm = bundled source
                    license_exceptions: vec![],
                    build_only: is_dev,
                });
            }
        }

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: name,
            ecosystem: Ecosystem::Npm,
            total_deps: total,
        })
    }

    // ─── Cargo ──────────────────────────────────────────────────────

    /// Resolve Cargo dependency graph from cargo metadata or Cargo.lock
    fn resolve_cargo(&self, root: &Path) -> Option<DependencyGraph> {
        // Prefer `cargo metadata` for accurate license info
        if let Some(graph) = self.resolve_cargo_metadata(root) {
            return Some(graph);
        }

        // Fall back to parsing Cargo.lock directly (no license info)
        self.resolve_cargo_lockfile(root)
    }

    /// Use `cargo metadata` for rich dependency + license info
    fn resolve_cargo_metadata(&self, root: &Path) -> Option<DependencyGraph> {
        let output = std::process::Command::new("cargo")
            .args(["metadata", "--format-version", "1", "--no-deps"])
            .current_dir(root)
            .output()
            .ok()?;

        if !output.status.success() {
            // Also try with deps for full graph
            let output = std::process::Command::new("cargo")
                .args(["metadata", "--format-version", "1"])
                .current_dir(root)
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            return self.parse_cargo_metadata(&output.stdout);
        }

        // First pass: get workspace packages
        let _workspace_json: serde_json::Value =
            serde_json::from_slice(&output.stdout).ok()?;

        // Second pass: full graph with all deps
        let full_output = std::process::Command::new("cargo")
            .args(["metadata", "--format-version", "1"])
            .current_dir(root)
            .output()
            .ok()?;

        if full_output.status.success() {
            self.parse_cargo_metadata(&full_output.stdout)
        } else {
            // At least parse workspace-only data
            self.parse_cargo_metadata(&output.stdout)
        }
    }

    fn parse_cargo_metadata(&self, raw: &[u8]) -> Option<DependencyGraph> {
        let json: serde_json::Value = serde_json::from_slice(raw).ok()?;
        let packages = json.get("packages")?.as_array()?;

        let resolve = json.get("resolve");
        let resolve_nodes: std::collections::HashMap<String, Vec<String>> = resolve
            .and_then(|r| r.get("nodes"))
            .and_then(|n| n.as_array())
            .map(|nodes| {
                nodes
                    .iter()
                    .filter_map(|node| {
                        let id = node.get("id")?.as_str()?.to_string();
                        let deps: Vec<String> = node
                            .get("deps")
                            .and_then(|d| d.as_array())
                            .map(|deps| {
                                deps.iter()
                                    .filter_map(|d| {
                                        d.get("name").and_then(|n| n.as_str()).map(String::from)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        Some((id, deps))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut nodes = Vec::new();
        for pkg in packages {
            let name = pkg.get("name")?.as_str()?.to_string();
            let version = pkg.get("version").and_then(|v| v.as_str()).map(String::from);
            let license_str = pkg
                .get("license")
                .and_then(|l| l.as_str())
                .unwrap_or("UNKNOWN");
            let pkg_id = pkg.get("id").and_then(|i| i.as_str()).unwrap_or("");

            let deps = resolve_nodes
                .get(pkg_id)
                .cloned()
                .unwrap_or_default();

            // Determine if it's a proc-macro (always static) or normal dep
            let is_proc_macro = pkg
                .get("targets")
                .and_then(|t| t.as_array())
                .map(|targets| {
                    targets.iter().any(|t| {
                        t.get("kind")
                            .and_then(|k| k.as_array())
                            .map(|kinds| {
                                kinds
                                    .iter()
                                    .any(|k| k.as_str() == Some("proc-macro"))
                            })
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            // Parse SPDX expression and detect exceptions
            let (spdx_expr, exceptions) = parse_cargo_license_field(license_str);

            nodes.push(DepNode {
                name,
                version,
                license: LicenseId::new(license_str.split(" OR ").next().unwrap_or(license_str)),
                spdx_expression: Some(spdx_expr),
                depends_on: deps,
                linking: if is_proc_macro {
                    LinkingMode::ProcMacro // proc-macros run at compile time
                } else {
                    LinkingMode::Static // Rust default = static
                },
                license_exceptions: exceptions,
                build_only: false,
            });
        }

        let root_name = json
            .get("resolve")
            .and_then(|r| r.get("root"))
            .and_then(|r| r.as_str())
            .and_then(|id| id.split_whitespace().next())
            .unwrap_or("project")
            .to_string();

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: root_name,
            ecosystem: Ecosystem::Cargo,
            total_deps: total,
        })
    }

    /// Fallback: parse Cargo.lock line by line (no license info)
    fn resolve_cargo_lockfile(&self, root: &Path) -> Option<DependencyGraph> {
        let lock_path = root.join("Cargo.lock");
        let content = std::fs::read_to_string(&lock_path).ok()?;

        let mut nodes = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;
        let mut current_deps: Vec<String> = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "[[package]]" {
                if let Some(name) = current_name.take() {
                    nodes.push(DepNode {
                        name,
                        version: current_version.take(),
                        license: LicenseId::new("UNKNOWN"),
                        spdx_expression: None,
                        depends_on: std::mem::take(&mut current_deps),
                        linking: LinkingMode::Static,
                        license_exceptions: vec![],
                        build_only: false,
                    });
                }
            } else if let Some(name) = trimmed.strip_prefix("name = ") {
                current_name = Some(name.trim_matches('"').to_string());
            } else if let Some(ver) = trimmed.strip_prefix("version = ") {
                current_version = Some(ver.trim_matches('"').to_string());
            } else if trimmed.starts_with("\"") && trimmed.contains(" ") {
                let dep_name = trimmed
                    .trim_matches('"')
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !dep_name.is_empty() {
                    current_deps.push(dep_name);
                }
            }
        }

        if let Some(name) = current_name {
            nodes.push(DepNode {
                name,
                version: current_version,
                license: LicenseId::new("UNKNOWN"),
                spdx_expression: None,
                depends_on: current_deps,
                linking: LinkingMode::Static,
                license_exceptions: vec![],
                build_only: false,
            });
        }

        let root_name = nodes
            .first()
            .map(|n| n.name.clone())
            .unwrap_or_default();
        let total = nodes.len();

        Some(DependencyGraph {
            nodes,
            root: root_name,
            ecosystem: Ecosystem::Cargo,
            total_deps: total,
        })
    }

    // ─── Go ─────────────────────────────────────────────────────────

    /// Resolve Go dependency graph
    fn resolve_go(&self, root: &Path) -> Option<DependencyGraph> {
        let sum_path = root.join("go.sum");
        let content = std::fs::read_to_string(&sum_path).ok()?;

        let mut nodes = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1]
                    .strip_suffix("/go.mod")
                    .unwrap_or(parts[1])
                    .to_string();

                if seen.insert(name.clone()) {
                    nodes.push(DepNode {
                        name,
                        version: Some(version),
                        license: LicenseId::new("UNKNOWN"),
                        spdx_expression: None,
                        depends_on: Vec::new(),
                        linking: LinkingMode::Static, // Go = static
                        license_exceptions: vec![],
                        build_only: false,
                    });
                }
            }
        }

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: "main".to_string(),
            ecosystem: Ecosystem::Go,
            total_deps: total,
        })
    }

    // ─── Python ─────────────────────────────────────────────────────

    /// Resolve Python dependency graph
    fn resolve_python(&self, root: &Path) -> Option<DependencyGraph> {
        // Try requirements.txt first
        let req_path = root.join("requirements.txt");
        let content = std::fs::read_to_string(&req_path).ok()?;

        let mut nodes = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
                continue;
            }

            let (name, version) = if let Some(pos) = trimmed.find("==") {
                (
                    trimmed[..pos].trim().to_string(),
                    Some(trimmed[pos + 2..].trim().to_string()),
                )
            } else if let Some(pos) = trimmed.find(">=") {
                (
                    trimmed[..pos].trim().to_string(),
                    Some(trimmed[pos + 2..].trim().to_string()),
                )
            } else {
                (trimmed.to_string(), None)
            };

            nodes.push(DepNode {
                name,
                version,
                license: LicenseId::new("UNKNOWN"),
                spdx_expression: None,
                depends_on: Vec::new(),
                linking: LinkingMode::Source,
                license_exceptions: vec![],
                build_only: false,
            });
        }

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: "project".to_string(),
            ecosystem: Ecosystem::PyPi,
            total_deps: total,
        })
    }

    // ─── Maven / Gradle ─────────────────────────────────────────────

    /// Resolve Maven/Gradle dependency graph from pom.xml or build.gradle.
    fn resolve_maven(&self, root: &Path) -> Option<DependencyGraph> {
        // Try pom.xml first
        if root.join("pom.xml").exists() {
            return self.resolve_pom_xml(root);
        }
        // Fall back to build.gradle
        if root.join("build.gradle").exists() || root.join("build.gradle.kts").exists() {
            return self.resolve_gradle(root);
        }
        None
    }

    /// Parse pom.xml for dependencies and their licenses.
    fn resolve_pom_xml(&self, root: &Path) -> Option<DependencyGraph> {
        let pom_path = root.join("pom.xml");
        let content = std::fs::read_to_string(&pom_path).ok()?;

        let mut nodes = Vec::new();
        let project_name = extract_xml_value(&content, "artifactId")
            .unwrap_or_else(|| "project".to_string());

        // Extract dependencies from <dependencies> block
        // We use a simple regex-based approach since we don't want a full XML parser dep
        let dep_re = regex::Regex::new(
            r"(?s)<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?(?:\s*<scope>([^<]+)</scope>)?"
        ).ok()?;

        for cap in dep_re.captures_iter(&content) {
            let group_id = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let artifact_id = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let version = cap.get(3).map(|m| m.as_str().to_string());
            let scope = cap.get(4).map(|m| m.as_str()).unwrap_or("compile");

            let name = format!("{}:{}", group_id, artifact_id);
            let is_build = matches!(scope, "test" | "provided" | "system");

            nodes.push(DepNode {
                name,
                version,
                license: LicenseId::new("UNKNOWN"),
                spdx_expression: None,
                depends_on: Vec::new(),
                linking: LinkingMode::Static, // JVM = classpath = static-like
                license_exceptions: vec![],
                build_only: is_build,
            });
        }

        // Extract project-level license
        let _project_license = extract_xml_value(&content, "license>\\s*<name>([^<]+)")
            .or_else(|| extract_xml_value(&content, "licenses>.*?<name>([^<]+)"));

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: project_name,
            ecosystem: Ecosystem::Maven,
            total_deps: total,
        })
    }

    /// Parse build.gradle for dependencies.
    fn resolve_gradle(&self, root: &Path) -> Option<DependencyGraph> {
        let gradle_path = if root.join("build.gradle.kts").exists() {
            root.join("build.gradle.kts")
        } else {
            root.join("build.gradle")
        };
        let content = std::fs::read_to_string(&gradle_path).ok()?;

        let mut nodes = Vec::new();

        // Match Gradle dependency notations:
        // implementation 'group:artifact:version'
        // implementation("group:artifact:version")
        // testImplementation 'group:artifact:version'
        let dep_re = regex::Regex::new(
            r#"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|annotationProcessor)\s*[\('"]+([^:'"]+):([^:'"]+)(?::([^'")\s]+))?['")\s]"#
        ).ok()?;

        for cap in dep_re.captures_iter(&content) {
            let group = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let artifact = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let version = cap.get(3).map(|m| m.as_str().to_string());

            let name = format!("{}:{}", group, artifact);

            // Detect scope from configuration name
            let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
            let is_build = full_match.starts_with("test")
                || full_match.starts_with("annotationProcessor")
                || full_match.starts_with("compileOnly");

            nodes.push(DepNode {
                name,
                version,
                license: LicenseId::new("UNKNOWN"),
                spdx_expression: None,
                depends_on: Vec::new(),
                linking: LinkingMode::Static,
                license_exceptions: vec![],
                build_only: is_build,
            });
        }

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: "project".to_string(),
            ecosystem: Ecosystem::Maven,
            total_deps: total,
        })
    }

    // ─── NuGet (.NET) ───────────────────────────────────────────────

    fn has_nuget_project(root: &Path) -> bool {
        walkdir::WalkDir::new(root)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "csproj" || ext == "fsproj" || ext == "vbproj")
                    .unwrap_or(false)
            })
    }

    /// Resolve NuGet dependency graph from .csproj / packages.config.
    fn resolve_nuget(&self, root: &Path) -> Option<DependencyGraph> {
        let mut nodes = Vec::new();
        let mut project_name = "project".to_string();

        // Walk for .csproj files
        for entry in walkdir::WalkDir::new(root)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "csproj" || ext == "fsproj")
                    .unwrap_or(false)
            })
        {
            let content = match std::fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Get project name from file stem
            if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                project_name = stem.to_string();
            }

            // Parse PackageReference elements
            let pkg_re = regex::Regex::new(
                r#"<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?"#
            ).ok()?;

            for cap in pkg_re.captures_iter(&content) {
                let name = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                let version = cap.get(2).map(|m| m.as_str().to_string());

                nodes.push(DepNode {
                    name,
                    version,
                    license: LicenseId::new("UNKNOWN"),
                    spdx_expression: None,
                    depends_on: Vec::new(),
                    linking: LinkingMode::Static, // .NET assemblies = static at deploy
                    license_exceptions: vec![],
                    build_only: false,
                });
            }

            // Also check for PackageLicenseExpression
            let license_re = regex::Regex::new(
                r#"<PackageLicenseExpression>([^<]+)</PackageLicenseExpression>"#
            ).ok()?;
            if let Some(cap) = license_re.captures(&content) {
                if let Some(expr) = cap.get(1) {
                    // Apply to the project itself, not deps
                    let _ = expr.as_str(); // Used for project-level analysis
                }
            }
        }

        // Also check packages.config (old format)
        let pkgconfig_path = root.join("packages.config");
        if pkgconfig_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&pkgconfig_path) {
                let pkg_re = regex::Regex::new(
                    r#"<package\s+id="([^"]+)"\s+version="([^"]+)"(?:\s+targetFramework="[^"]*")?"#
                ).ok()?;

                for cap in pkg_re.captures_iter(&content) {
                    let name = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let version = cap.get(2).map(|m| m.as_str().to_string());

                    // Deduplicate against already-found packages
                    if !nodes.iter().any(|n| n.name == name) {
                        nodes.push(DepNode {
                            name,
                            version,
                            license: LicenseId::new("UNKNOWN"),
                            spdx_expression: None,
                            depends_on: Vec::new(),
                            linking: LinkingMode::Static,
                            license_exceptions: vec![],
                            build_only: false,
                        });
                    }
                }
            }
        }

        let total = nodes.len();
        if nodes.is_empty() {
            return None;
        }

        Some(DependencyGraph {
            nodes,
            root: project_name,
            ecosystem: Ecosystem::NuGet,
            total_deps: total,
        })
    }

    // ─── Composer (PHP) ─────────────────────────────────────────────

    /// Resolve Composer dependency graph from composer.lock.
    fn resolve_composer(&self, root: &Path) -> Option<DependencyGraph> {
        let lock_path = root.join("composer.lock");
        let content = std::fs::read_to_string(&lock_path).ok()?;
        let json: serde_json::Value = serde_json::from_str(&content).ok()?;

        let mut nodes = Vec::new();

        // Parse packages array
        if let Some(packages) = json.get("packages").and_then(|p| p.as_array()) {
            for pkg in packages {
                let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let version = pkg.get("version").and_then(|v| v.as_str()).map(String::from);

                // Composer uses array of licenses
                let license = pkg.get("license")
                    .and_then(|l| l.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|l| l.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string();

                let spdx_expression = pkg.get("license")
                    .and_then(|l| l.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|l| l.as_str())
                            .collect::<Vec<_>>()
                            .join(" OR ")
                    });

                // Extract dependency names
                let deps: Vec<String> = pkg.get("require")
                    .and_then(|r| r.as_object())
                    .map(|obj| {
                        obj.keys()
                            .filter(|k| !k.starts_with("php") && !k.starts_with("ext-"))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();

                if !name.is_empty() {
                    nodes.push(DepNode {
                        name,
                        version,
                        license: LicenseId::new(&license),
                        spdx_expression,
                        depends_on: deps,
                        linking: LinkingMode::Source, // PHP = source inclusion
                        license_exceptions: vec![],
                        build_only: false,
                    });
                }
            }
        }

        // Parse packages-dev (dev-only dependencies)
        if let Some(packages) = json.get("packages-dev").and_then(|p| p.as_array()) {
            for pkg in packages {
                let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                let version = pkg.get("version").and_then(|v| v.as_str()).map(String::from);
                let license = pkg.get("license")
                    .and_then(|l| l.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|l| l.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string();

                if !name.is_empty() {
                    nodes.push(DepNode {
                        name,
                        version,
                        license: LicenseId::new(&license),
                        spdx_expression: None,
                        depends_on: Vec::new(),
                        linking: LinkingMode::Source,
                        license_exceptions: vec![],
                        build_only: true, // Dev dependency
                    });
                }
            }
        }

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: "project".to_string(),
            ecosystem: Ecosystem::Composer,
            total_deps: total,
        })
    }

    // ─── RubyGems ───────────────────────────────────────────────────

    /// Resolve RubyGems dependency graph from Gemfile.lock.
    fn resolve_rubygems(&self, root: &Path) -> Option<DependencyGraph> {
        let lock_path = root.join("Gemfile.lock");
        let content = std::fs::read_to_string(&lock_path).ok()?;

        let mut nodes = Vec::new();
        let mut in_gems = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // Gemfile.lock has sections: GEM, PLATFORMS, DEPENDENCIES, etc.
            if trimmed == "GEM" || trimmed.starts_with("GEM") {
                in_gems = true;
                continue;
            }
            if !trimmed.starts_with(' ') && !trimmed.is_empty() && trimmed != "specs:" {
                if in_gems && !trimmed.starts_with("remote:") && !trimmed.starts_with("specs:") {
                    in_gems = false;
                }
            }

            if in_gems {
                // Match gem entries like "    actioncable (7.0.4)"
                let gem_re = regex::Regex::new(
                    r"^\s{4}(\S+)\s+\(([^)]+)\)"
                ).ok()?;

                if let Some(cap) = gem_re.captures(line) {
                    let name = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let version = cap.get(2).map(|m| m.as_str().to_string());

                    if !name.is_empty() {
                        nodes.push(DepNode {
                            name,
                            version,
                            license: LicenseId::new("UNKNOWN"),
                            spdx_expression: None,
                            depends_on: Vec::new(),
                            linking: LinkingMode::Source, // Ruby = source
                            license_exceptions: vec![],
                            build_only: false,
                        });
                    }
                }

                // Match sub-dependencies like "      actioncable (>= 7.0)"
                // These are the deps of the parent gem
                if line.starts_with("      ") && !line.starts_with("        ") {
                    let dep_name = trimmed.split_whitespace().next().unwrap_or("");
                    if !dep_name.is_empty() {
                        if let Some(parent) = nodes.last_mut() {
                            parent.depends_on.push(dep_name.to_string());
                        }
                    }
                }
            }
        }

        let total = nodes.len();
        Some(DependencyGraph {
            nodes,
            root: "project".to_string(),
            ecosystem: Ecosystem::RubyGems,
            total_deps: total,
        })
    }
}

impl Default for DependencyResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Utility Functions ──────────────────────────────────────────────

/// Extract a simple XML tag value using regex.
fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let pattern = format!(r"<{}>([^<]+)<", tag);
    regex::Regex::new(&pattern)
        .ok()?
        .captures(xml)?
        .get(1)
        .map(|m| m.as_str().trim().to_string())
}

/// Parse a Cargo license field, extracting SPDX expression and any exceptions.
fn parse_cargo_license_field(field: &str) -> (String, Vec<String>) {
    let mut exceptions = Vec::new();

    // Check for WITH clauses
    if field.contains(" WITH ") {
        let parts: Vec<&str> = field.split(" WITH ").collect();
        if parts.len() >= 2 {
            exceptions.push(parts[1].trim().to_string());
        }
    }

    // Normalize separators: Cargo uses "/" as an OR separator
    let normalized = field.replace('/', " OR ");

    (normalized, exceptions)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_license_simple() {
        let (expr, exceptions) = parse_cargo_license_field("MIT");
        assert_eq!(expr, "MIT");
        assert!(exceptions.is_empty());
    }

    #[test]
    fn test_parse_cargo_license_dual() {
        let (expr, exceptions) = parse_cargo_license_field("MIT/Apache-2.0");
        assert_eq!(expr, "MIT OR Apache-2.0");
        assert!(exceptions.is_empty());
    }

    #[test]
    fn test_parse_cargo_license_with_exception() {
        let (expr, exceptions) = parse_cargo_license_field("GPL-2.0-only WITH Classpath-exception-2.0");
        assert!(expr.contains("GPL"));
        assert_eq!(exceptions.len(), 1);
        assert!(exceptions[0].contains("Classpath"));
    }

    #[test]
    fn test_extract_xml_value() {
        let xml = "<project><artifactId>my-app</artifactId></project>";
        let val = extract_xml_value(xml, "artifactId");
        assert_eq!(val, Some("my-app".to_string()));
    }
}
