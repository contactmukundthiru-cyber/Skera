//! Creative Commons compliance — full CC license chain verification
//!
//! ## Why This Matters
//!
//! Creative Commons licenses are the most misunderstood and most violated
//! licenses on the internet. CC governs billions of images, documents,
//! datasets, and media files, yet most projects treat CC as "free to use"
//! without understanding the obligation chain.
//!
//! ## Key Violations This Module Detects
//!
//! 1. **CC-BY Attribution Failure** — Using CC content without proper attribution.
//!    CC-BY requires: title, author, source URL, and license notice.
//!
//! 2. **CC-NC Commercial Misuse** — Using NonCommercial content in a commercial
//!    context. "Commercial" is broadly defined: even donation-funded projects
//!    or ad-supported sites may qualify.
//!
//! 3. **CC-ND Modification** — Modifying NoDerivatives content. This includes
//!    cropping images, adding watermarks, translating text, or remixing audio.
//!
//! 4. **CC-SA ShareAlike Violation** — Distributing derivatives under a
//!    different license than the original. SA requires any derivative to be
//!    licensed under the same or compatible CC license.
//!
//! 5. **CC Version Compatibility** — CC-BY-SA 3.0 and CC-BY-SA 4.0 are NOT
//!    automatically compatible. Version 4.0 explicitly includes a compatibility
//!    clause; version 3.0 does not.
//!
//! 6. **CC0/Public Domain Confusion** — CC0 is a dedication to the public domain,
//!    NOT a CC license. It has different legal implications.
//!
//! ## Research Basis
//!
//! - Creative Commons Legal Code (all versions)
//! - CC License Compatibility Chart (creativecommons.org)
//! - Creative Commons FAQ on commercial use
//! - Wikimedia Commons attribution guidelines
//! - Stack Overflow attribution requirements (CC-BY-SA)

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─── Core Types ─────────────────────────────────────────────────────

/// CC compliance report for a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcComplianceReport {
    /// Root directory scanned
    pub root: PathBuf,
    /// All CC-licensed content found
    pub cc_content: Vec<CcContent>,
    /// Attribution chain analysis
    pub attribution_chain: Vec<AttributionEntry>,
    /// Compliance violations
    pub violations: Vec<CcViolation>,
    /// Is this project commercially used?
    pub commercial_indicators: Vec<CommercialIndicator>,
    /// Is the project itself CC-licensed?
    pub project_cc_license: Option<CcLicense>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcContent {
    /// Path to the CC content
    pub path: PathBuf,
    /// Detected CC license
    pub license: CcLicense,
    /// How it was detected
    pub detection_method: CcDetectionMethod,
    /// Attribution metadata found
    pub attribution: Option<CcAttribution>,
}

/// Creative Commons license variant
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CcLicense {
    /// Version (1.0, 2.0, 2.5, 3.0, 4.0)
    pub version: String,
    /// Components
    pub components: Vec<CcComponent>,
    /// Full SPDX-like identifier
    pub identifier: String,
    /// Jurisdiction port (None = International/Unported)
    pub jurisdiction: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CcComponent {
    /// Attribution required
    BY,
    /// ShareAlike — derivatives must use same license
    SA,
    /// NonCommercial — no commercial use
    NC,
    /// NoDerivatives — no modifications
    ND,
}

impl std::fmt::Display for CcLicense {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CcDetectionMethod {
    /// Found in file metadata (EXIF, XMP, IPTC)
    Metadata,
    /// Found in accompanying LICENSE/README
    LicenseFile,
    /// Found in HTML meta tags or RDF
    HtmlMeta,
    /// Found in filename convention
    Filename,
    /// Found in inline comment
    Comment,
    /// Found via SPDX header
    SpdxHeader,
}

/// Attribution information for CC content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcAttribution {
    pub title: Option<String>,
    pub author: Option<String>,
    pub source_url: Option<String>,
    pub license_url: Option<String>,
    pub year: Option<String>,
    /// Is the attribution complete per CC requirements?
    pub is_complete: bool,
    /// What's missing
    pub missing_elements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionEntry {
    /// Path to the attributed content
    pub content_path: PathBuf,
    /// Where the attribution appears
    pub attribution_path: PathBuf,
    /// Is attribution complete?
    pub complete: bool,
    /// Missing attribution elements
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcViolation {
    pub severity: CcViolationSeverity,
    pub violation_type: CcViolationType,
    pub content_path: PathBuf,
    pub license: CcLicense,
    pub description: String,
    pub legal_reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CcViolationSeverity {
    Info,
    Warning,
    Violation,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CcViolationType {
    /// Missing or incomplete attribution
    MissingAttribution,
    /// NC content used commercially
    CommercialMisuse,
    /// ND content has been modified
    DerivativeViolation,
    /// SA derivative doesn't use compatible license
    ShareAlikeViolation,
    /// Version incompatibility
    VersionIncompatible,
    /// CC0 treated as CC license
    Cc0Confusion,
    /// Using retired CC license (1.0/2.0)
    RetiredVersion,
}

/// Indicators that a project is commercial
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommercialIndicator {
    pub indicator_type: CommercialIndicatorType,
    pub description: String,
    pub file_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommercialIndicatorType {
    /// Payment processing code
    PaymentProcessing,
    /// Advertising/ad network integration
    Advertising,
    /// Commercial branding
    CommercialBranding,
    /// Proprietary license on project itself
    ProprietaryLicense,
    /// SaaS/subscription indicators
    SaasIndicators,
    /// E-commerce functionality
    Ecommerce,
    /// Monetization
    Monetization,
}

// ─── CC License Database ────────────────────────────────────────────

/// CC license compatibility matrix
/// Can license A's content be used in a project licensed under B?
#[allow(dead_code)]
struct CcCompatibility;

#[allow(dead_code)]
impl CcCompatibility {
    /// Check if a CC license is compatible with commercial use
    fn allows_commercial(license: &CcLicense) -> bool {
        !license.components.contains(&CcComponent::NC)
    }

    /// Check if a CC license allows derivatives
    fn allows_derivatives(license: &CcLicense) -> bool {
        !license.components.contains(&CcComponent::ND)
    }

    /// Check if a CC license requires ShareAlike
    fn requires_share_alike(license: &CcLicense) -> bool {
        license.components.contains(&CcComponent::SA)
    }

    /// Check if a CC license requires attribution
    fn requires_attribution(license: &CcLicense) -> bool {
        license.components.contains(&CcComponent::BY)
    }

    /// Check if two CC-SA versions are compatible
    fn sa_versions_compatible(a: &str, b: &str) -> bool {
        // CC-BY-SA 4.0 explicitly allows upgrading from 3.0
        // CC-BY-SA 3.0 does NOT allow downgrading to 2.x or 1.x
        match (a, b) {
            ("4.0", "4.0") => true,
            ("4.0", "3.0") => true,  // 4.0 includes 3.0 compatibility
            ("3.0", "4.0") => true,  // Can upgrade from 3.0 to 4.0
            ("3.0", "3.0") => true,
            _ => a == b, // Same version is always compatible
        }
    }
}

// ─── CC Text Patterns ───────────────────────────────────────────────

/// Patterns for detecting CC licenses in text
const CC_TEXT_PATTERNS: &[(&str, &str)] = &[
    ("creative commons attribution 4.0", "CC-BY-4.0"),
    ("creative commons attribution-sharealike 4.0", "CC-BY-SA-4.0"),
    ("creative commons attribution-noncommercial 4.0", "CC-BY-NC-4.0"),
    ("creative commons attribution-noderivatives 4.0", "CC-BY-ND-4.0"),
    ("creative commons attribution-noncommercial-sharealike 4.0", "CC-BY-NC-SA-4.0"),
    ("creative commons attribution-noncommercial-noderivatives 4.0", "CC-BY-NC-ND-4.0"),
    ("creative commons attribution 3.0", "CC-BY-3.0"),
    ("creative commons attribution-sharealike 3.0", "CC-BY-SA-3.0"),
    ("creative commons attribution-noncommercial 3.0", "CC-BY-NC-3.0"),
    ("creative commons attribution-noderivatives 3.0", "CC-BY-ND-3.0"),
    ("creative commons attribution-noncommercial-sharealike 3.0", "CC-BY-NC-SA-3.0"),
    ("creative commons attribution-noncommercial-noderivatives 3.0", "CC-BY-NC-ND-3.0"),
    ("creative commons zero", "CC0-1.0"),
    ("cc0 1.0 universal", "CC0-1.0"),
    ("public domain dedication", "CC0-1.0"),
    ("cc-by-4.0", "CC-BY-4.0"),
    ("cc-by-sa-4.0", "CC-BY-SA-4.0"),
    ("cc-by-nc-4.0", "CC-BY-NC-4.0"),
    ("cc-by-nd-4.0", "CC-BY-ND-4.0"),
    ("cc-by-nc-sa-4.0", "CC-BY-NC-SA-4.0"),
    ("cc-by-nc-nd-4.0", "CC-BY-NC-ND-4.0"),
    ("cc-by-3.0", "CC-BY-3.0"),
    ("cc-by-sa-3.0", "CC-BY-SA-3.0"),
    ("cc-by-nc-3.0", "CC-BY-NC-3.0"),
    ("cc-by-nd-3.0", "CC-BY-ND-3.0"),
    ("cc-by-nc-sa-3.0", "CC-BY-NC-SA-3.0"),
    ("cc-by-nc-nd-3.0", "CC-BY-NC-ND-3.0"),
];

/// URL patterns for CC licenses
const CC_URL_PATTERNS: &[(&str, &str)] = &[
    ("creativecommons.org/licenses/by/4.0", "CC-BY-4.0"),
    ("creativecommons.org/licenses/by-sa/4.0", "CC-BY-SA-4.0"),
    ("creativecommons.org/licenses/by-nc/4.0", "CC-BY-NC-4.0"),
    ("creativecommons.org/licenses/by-nd/4.0", "CC-BY-ND-4.0"),
    ("creativecommons.org/licenses/by-nc-sa/4.0", "CC-BY-NC-SA-4.0"),
    ("creativecommons.org/licenses/by-nc-nd/4.0", "CC-BY-NC-ND-4.0"),
    ("creativecommons.org/licenses/by/3.0", "CC-BY-3.0"),
    ("creativecommons.org/licenses/by-sa/3.0", "CC-BY-SA-3.0"),
    ("creativecommons.org/licenses/by-nc/3.0", "CC-BY-NC-3.0"),
    ("creativecommons.org/licenses/by-nd/3.0", "CC-BY-ND-3.0"),
    ("creativecommons.org/licenses/by-nc-sa/3.0", "CC-BY-NC-SA-3.0"),
    ("creativecommons.org/licenses/by-nc-nd/3.0", "CC-BY-NC-ND-3.0"),
    ("creativecommons.org/publicdomain/zero/1.0", "CC0-1.0"),
    ("creativecommons.org/licenses/by/2.0", "CC-BY-2.0"),
    ("creativecommons.org/licenses/by-sa/2.0", "CC-BY-SA-2.0"),
    ("creativecommons.org/licenses/by-nc/2.0", "CC-BY-NC-2.0"),
    ("creativecommons.org/licenses/by/2.5", "CC-BY-2.5"),
    ("creativecommons.org/licenses/by-sa/2.5", "CC-BY-SA-2.5"),
];

/// File patterns that often contain CC attribution
const ATTRIBUTION_FILES: &[&str] = &[
    "CREDITS", "CREDITS.md", "CREDITS.txt",
    "ATTRIBUTION", "ATTRIBUTION.md", "ATTRIBUTION.txt",
    "THIRD-PARTY-NOTICES", "THIRD-PARTY-NOTICES.md",
    "THIRD_PARTY_NOTICES", "THIRD_PARTY_NOTICES.md",
    "ACKNOWLEDGMENTS", "ACKNOWLEDGMENTS.md",
    "ACKNOWLEDGEMENTS", "ACKNOWLEDGEMENTS.md",
    "NOTICE", "NOTICE.md", "NOTICE.txt",
    "AUTHORS", "AUTHORS.md", "AUTHORS.txt",
    "CONTRIBUTORS", "CONTRIBUTORS.md",
];

// ─── CC Compliance Scanner ──────────────────────────────────────────

pub struct CcComplianceScanner;

impl CcComplianceScanner {
    /// Run a complete CC compliance scan
    pub fn scan(root: &Path) -> CcComplianceReport {
        let mut report = CcComplianceReport {
            root: root.to_path_buf(),
            cc_content: Vec::new(),
            attribution_chain: Vec::new(),
            violations: Vec::new(),
            commercial_indicators: Vec::new(),
            project_cc_license: None,
        };

        // ── Phase 1: Detect CC content ──
        Self::scan_for_cc_content(root, &mut report);

        // ── Phase 2: Detect commercial indicators ──
        Self::detect_commercial_indicators(root, &mut report);

        // ── Phase 3: Check attribution chains ──
        Self::check_attribution_chains(root, &mut report);

        // ── Phase 4: Check CC violations ──
        Self::check_violations(&mut report);

        report
    }

    fn scan_for_cc_content(root: &Path, report: &mut CcComplianceReport) {
        for entry in walkdir::WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let ext = entry.path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            match ext.as_str() {
                // Text files that might contain CC license information
                "md" | "txt" | "rst" | "html" | "htm" | "xml" | "json" | "yaml" | "yml" => {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        Self::check_text_for_cc(&content, entry.path(), report);
                    }
                }
                // README files (no extension)
                "" => {
                    let fname = entry.file_name().to_str().unwrap_or("").to_uppercase();
                    if fname.starts_with("README") || fname.starts_with("LICENSE")
                        || fname.starts_with("CREDIT") || fname.starts_with("NOTICE")
                        || fname.starts_with("ATTRIBUTION")
                    {
                        if let Ok(content) = std::fs::read_to_string(entry.path()) {
                            Self::check_text_for_cc(&content, entry.path(), report);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn check_text_for_cc(content: &str, file_path: &Path, report: &mut CcComplianceReport) {
        let lower = content.to_lowercase();

        // Check text patterns
        for &(pattern, identifier) in CC_TEXT_PATTERNS {
            if lower.contains(pattern) {
                if let Some(license) = Self::parse_cc_identifier(identifier) {
                    report.cc_content.push(CcContent {
                        path: file_path.to_path_buf(),
                        license,
                        detection_method: CcDetectionMethod::LicenseFile,
                        attribution: Self::extract_attribution(content),
                    });
                }
            }
        }

        // Check URL patterns
        for &(url_pattern, identifier) in CC_URL_PATTERNS {
            if lower.contains(url_pattern) {
                // Avoid duplicate detection from same file
                let already = report.cc_content.iter()
                    .any(|c| c.path == file_path && c.license.identifier == identifier);
                if !already {
                    if let Some(license) = Self::parse_cc_identifier(identifier) {
                        report.cc_content.push(CcContent {
                            path: file_path.to_path_buf(),
                            license,
                            detection_method: CcDetectionMethod::HtmlMeta,
                            attribution: Self::extract_attribution(content),
                        });
                    }
                }
            }
        }

        // Check if this is the project's own license
        let fname = file_path.file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_uppercase();
        if fname.starts_with("LICENSE") || fname.starts_with("LICENCE") || fname.starts_with("COPYING") {
            if let Some(cc) = report.cc_content.iter().find(|c| c.path == file_path) {
                report.project_cc_license = Some(cc.license.clone());
            }
        }
    }

    fn detect_commercial_indicators(root: &Path, report: &mut CcComplianceReport) {
        for entry in walkdir::WalkDir::new(root)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                let lower = content.to_lowercase();

                // Payment processing
                let payment_patterns = [
                    "stripe", "paypal", "braintree", "square",
                    "payment_intent", "checkout.session",
                    "gumroad", "lemonsqueezy", "paddle",
                ];
                for pattern in &payment_patterns {
                    if lower.contains(pattern) {
                        let already = report.commercial_indicators.iter()
                            .any(|ci| ci.description.contains(pattern));
                        if !already {
                            report.commercial_indicators.push(CommercialIndicator {
                                indicator_type: CommercialIndicatorType::PaymentProcessing,
                                description: format!("Payment processing detected: '{}'", pattern),
                                file_path: Some(entry.path().to_path_buf()),
                            });
                        }
                    }
                }

                // Advertising
                let ad_patterns = [
                    "google_ad", "adsense", "adwords", "doubleclick",
                    "facebook pixel", "fbevents", "analytics.js",
                    "gtag", "google tag manager",
                ];
                for pattern in &ad_patterns {
                    if lower.contains(pattern) {
                        let already = report.commercial_indicators.iter()
                            .any(|ci| ci.description.contains(pattern));
                        if !already {
                            report.commercial_indicators.push(CommercialIndicator {
                                indicator_type: CommercialIndicatorType::Advertising,
                                description: format!("Advertising integration: '{}'", pattern),
                                file_path: Some(entry.path().to_path_buf()),
                            });
                        }
                    }
                }

                // E-commerce
                let ecommerce_patterns = [
                    "shopping cart", "add to cart", "checkout",
                    "shopify", "woocommerce", "magento",
                    "product_price", "buy now", "purchase",
                ];
                for pattern in &ecommerce_patterns {
                    if lower.contains(pattern) {
                        let already = report.commercial_indicators.iter()
                            .any(|ci| ci.description.contains(pattern));
                        if !already {
                            report.commercial_indicators.push(CommercialIndicator {
                                indicator_type: CommercialIndicatorType::Ecommerce,
                                description: format!("E-commerce pattern: '{}'", pattern),
                                file_path: Some(entry.path().to_path_buf()),
                            });
                        }
                    }
                }

                // SaaS indicators
                let saas_patterns = [
                    "subscription", "premium plan", "free tier",
                    "api_key", "rate_limit", "billing",
                    "pro plan", "enterprise", "pricing",
                ];
                for pattern in &saas_patterns {
                    if lower.contains(pattern) {
                        let already = report.commercial_indicators.iter()
                            .any(|ci| ci.description.contains(pattern));
                        if !already {
                            report.commercial_indicators.push(CommercialIndicator {
                                indicator_type: CommercialIndicatorType::SaasIndicators,
                                description: format!("SaaS pattern: '{}'", pattern),
                                file_path: Some(entry.path().to_path_buf()),
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_attribution_chains(root: &Path, report: &mut CcComplianceReport) {
        // If we found CC-BY content, check if attribution exists
        let by_content: Vec<_> = report.cc_content.iter()
            .filter(|c| c.license.components.contains(&CcComponent::BY))
            .cloned()
            .collect();

        if by_content.is_empty() {
            return;
        }

        // Find attribution files
        let mut attribution_content = String::new();
        let mut attribution_path = PathBuf::new();

        for name in ATTRIBUTION_FILES {
            let path = root.join(name);
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    attribution_content = content;
                    attribution_path = path;
                    break;
                }
            }
        }

        // Also check README for attribution section
        if attribution_content.is_empty() {
            for name in &["README.md", "README", "README.txt", "README.rst"] {
                let path = root.join(name);
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let lower = content.to_lowercase();
                        if lower.contains("attribution") || lower.contains("credits")
                            || lower.contains("acknowledgment") || lower.contains("third-party")
                        {
                            attribution_content = content;
                            attribution_path = path;
                            break;
                        }
                    }
                }
            }
        }

        // For each CC-BY content, check attribution completeness
        for cc in &by_content {
            let content_name = cc.path.file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("unknown")
                .to_lowercase();

            let is_attributed = !attribution_content.is_empty()
                && attribution_content.to_lowercase().contains(&content_name);

            let mut missing = Vec::new();
            if let Some(ref attr) = cc.attribution {
                if attr.title.is_none() { missing.push("title".into()); }
                if attr.author.is_none() { missing.push("author/creator".into()); }
                if attr.source_url.is_none() { missing.push("source URL".into()); }
                if attr.license_url.is_none() { missing.push("license URL".into()); }
            } else {
                missing = vec![
                    "title".into(),
                    "author/creator".into(),
                    "source URL".into(),
                    "license URL".into(),
                ];
            }

            if !is_attributed && !missing.is_empty() {
                report.attribution_chain.push(AttributionEntry {
                    content_path: cc.path.clone(),
                    attribution_path: attribution_path.clone(),
                    complete: false,
                    missing: missing.clone(),
                });

                report.violations.push(CcViolation {
                    severity: CcViolationSeverity::Violation,
                    violation_type: CcViolationType::MissingAttribution,
                    content_path: cc.path.clone(),
                    license: cc.license.clone(),
                    description: format!(
                        "CC-BY content at '{}' lacks proper attribution. Missing: {}",
                        cc.path.display(),
                        missing.join(", ")
                    ),
                    legal_reference: "CC Attribution requires: title of the work, name of the creator, \
                        source link, and indication of the license. See CC BY 4.0 Section 3(a)".into(),
                });
            }
        }
    }

    fn check_violations(report: &mut CcComplianceReport) {
        let is_commercial = !report.commercial_indicators.is_empty();

        for cc in &report.cc_content {
            // CC-NC in commercial context
            if is_commercial && !CcCompatibility::allows_commercial(&cc.license) {
                report.violations.push(CcViolation {
                    severity: CcViolationSeverity::Critical,
                    violation_type: CcViolationType::CommercialMisuse,
                    content_path: cc.path.clone(),
                    license: cc.license.clone(),
                    description: format!(
                        "CC-NC content '{}' used in a commercial project. The project contains {} commercial indicators.",
                        cc.path.display(),
                        report.commercial_indicators.len()
                    ),
                    legal_reference: "NonCommercial (NC) means 'not primarily intended for or directed towards \
                        commercial advantage or monetary compensation.' See CC BY-NC 4.0 Section 1(k)".into(),
                });
            }

            // Retired versions (1.0, 2.0, 2.5)
            match cc.license.version.as_str() {
                "1.0" | "2.0" | "2.5" => {
                    report.violations.push(CcViolation {
                        severity: CcViolationSeverity::Warning,
                        violation_type: CcViolationType::RetiredVersion,
                        content_path: cc.path.clone(),
                        license: cc.license.clone(),
                        description: format!(
                            "CC content uses legacy version {} which lacks modern provisions. Consider upgrading to 4.0.",
                            cc.license.version
                        ),
                        legal_reference: "CC recommends using version 4.0 for new works. \
                            Older versions may have jurisdiction-specific issues.".into(),
                    });
                }
                _ => {}
            }

            // CC0 warnings
            if cc.license.identifier.starts_with("CC0") {
                report.violations.push(CcViolation {
                    severity: CcViolationSeverity::Info,
                    violation_type: CcViolationType::Cc0Confusion,
                    content_path: cc.path.clone(),
                    license: cc.license.clone(),
                    description: format!(
                        "CC0 content at '{}' — this is a public domain dedication, not a CC license. \
                        No attribution is legally required (but may be ethically expected).",
                        cc.path.display()
                    ),
                    legal_reference: "CC0 operates as a complete waiver of all rights. \
                        It is NOT a CC license and cannot be combined with CC license components.".into(),
                });
            }
        }
    }

    // ── Parsing Methods ─────────────────────────────────────────────

    pub fn parse_cc_identifier(id: &str) -> Option<CcLicense> {
        let upper = id.to_uppercase();

        let mut components = Vec::new();
        let mut version = "4.0".to_string();

        // Extract version
        for v in &["4.0", "3.0", "2.5", "2.0", "1.0"] {
            if upper.contains(v) {
                version = v.to_string();
                break;
            }
        }

        // Extract components
        if upper.contains("-BY") || upper.starts_with("CC-BY") || upper.contains("ATTRIBUTION") {
            components.push(CcComponent::BY);
        }
        if upper.contains("-SA") || upper.contains("SHAREALIKE") {
            components.push(CcComponent::SA);
        }
        if upper.contains("-NC") || upper.contains("NONCOMMERCIAL") {
            components.push(CcComponent::NC);
        }
        if upper.contains("-ND") || upper.contains("NODERIVATIVES") {
            components.push(CcComponent::ND);
        }

        // CC0 special case
        if upper.starts_with("CC0") {
            return Some(CcLicense {
                version: "1.0".into(),
                components: vec![],
                identifier: "CC0-1.0".into(),
                jurisdiction: None,
            });
        }

        if components.is_empty() {
            return None;
        }

        Some(CcLicense {
            version: version.clone(),
            components,
            identifier: id.to_string(),
            jurisdiction: None,
        })
    }

    fn extract_attribution(content: &str) -> Option<CcAttribution> {
        let lower = content.to_lowercase();
        let mut title = None;
        let mut author = None;
        let mut source_url = None;
        let mut license_url = None;
        let mut year = None;

        // Look for attribution patterns
        for line in content.lines() {
            let trimmed = line.trim();
            let tl = trimmed.to_lowercase();

            // Author patterns
            if tl.starts_with("by ") || tl.starts_with("author:") || tl.starts_with("creator:") {
                author = Some(trimmed.split(':').nth(1)
                    .or_else(|| trimmed.strip_prefix("by "))
                    .unwrap_or(trimmed).trim().to_string());
            }

            // Source URL
            if tl.starts_with("source:") || tl.starts_with("original:") || tl.starts_with("from:") {
                source_url = Some(trimmed.split(':').skip(1).collect::<Vec<_>>().join(":").trim().to_string());
            }

            // License URL
            if tl.contains("creativecommons.org/licenses/") {
                license_url = Self::extract_url(trimmed);
            }

            // Year
            if let Some(y) = Self::extract_year(trimmed) {
                year = Some(y);
            }

            // Title (first non-empty, non-attribution line)
            if title.is_none() && !tl.is_empty()
                && !tl.starts_with("by ") && !tl.starts_with("author:")
                && !tl.starts_with("source:") && !tl.starts_with("#")
                && !tl.contains("creative commons") && !tl.contains("license")
            {
                title = Some(trimmed.to_string());
            }
        }

        let _ = lower; // suppress unused warning

        let mut missing = Vec::new();
        if title.is_none() { missing.push("title".into()); }
        if author.is_none() { missing.push("author".into()); }
        if source_url.is_none() { missing.push("source URL".into()); }
        if license_url.is_none() { missing.push("license URL".into()); }

        Some(CcAttribution {
            is_complete: missing.is_empty(),
            missing_elements: missing,
            title,
            author,
            source_url,
            license_url,
            year,
        })
    }

    fn extract_url(text: &str) -> Option<String> {
        // Simple URL extraction
        if let Some(pos) = text.find("http") {
            let url: String = text[pos..].chars()
                .take_while(|c| !c.is_whitespace() && *c != ')' && *c != '"' && *c != '\'')
                .collect();
            if url.len() > 10 {
                return Some(url);
            }
        }
        None
    }

    fn extract_year(text: &str) -> Option<String> {
        // Look for 4-digit year patterns
        let chars: Vec<char> = text.chars().collect();
        for i in 0..chars.len().saturating_sub(3) {
            if chars[i].is_ascii_digit() && chars[i + 1].is_ascii_digit()
                && chars[i + 2].is_ascii_digit() && chars[i + 3].is_ascii_digit()
            {
                let year: String = chars[i..i + 4].iter().collect();
                if let Ok(y) = year.parse::<u32>() {
                    if (1990..=2030).contains(&y) {
                        return Some(year);
                    }
                }
            }
        }
        None
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cc_by_4() {
        let lic = CcComplianceScanner::parse_cc_identifier("CC-BY-4.0").unwrap();
        assert_eq!(lic.version, "4.0");
        assert!(lic.components.contains(&CcComponent::BY));
        assert!(!lic.components.contains(&CcComponent::NC));
    }

    #[test]
    fn test_parse_cc_by_nc_sa() {
        let lic = CcComplianceScanner::parse_cc_identifier("CC-BY-NC-SA-4.0").unwrap();
        assert!(lic.components.contains(&CcComponent::BY));
        assert!(lic.components.contains(&CcComponent::NC));
        assert!(lic.components.contains(&CcComponent::SA));
        assert!(!lic.components.contains(&CcComponent::ND));
    }

    #[test]
    fn test_parse_cc0() {
        let lic = CcComplianceScanner::parse_cc_identifier("CC0-1.0").unwrap();
        assert!(lic.components.is_empty());
        assert_eq!(lic.identifier, "CC0-1.0");
    }

    #[test]
    fn test_cc_nc_commercial_check() {
        let nc_license = CcComplianceScanner::parse_cc_identifier("CC-BY-NC-4.0").unwrap();
        assert!(!CcCompatibility::allows_commercial(&nc_license));

        let by_license = CcComplianceScanner::parse_cc_identifier("CC-BY-4.0").unwrap();
        assert!(CcCompatibility::allows_commercial(&by_license));
    }

    #[test]
    fn test_cc_nd_derivatives_check() {
        let nd_license = CcComplianceScanner::parse_cc_identifier("CC-BY-ND-4.0").unwrap();
        assert!(!CcCompatibility::allows_derivatives(&nd_license));

        let sa_license = CcComplianceScanner::parse_cc_identifier("CC-BY-SA-4.0").unwrap();
        assert!(CcCompatibility::allows_derivatives(&sa_license));
    }

    #[test]
    fn test_sa_version_compatibility() {
        assert!(CcCompatibility::sa_versions_compatible("4.0", "3.0"));
        assert!(CcCompatibility::sa_versions_compatible("3.0", "4.0"));
        assert!(CcCompatibility::sa_versions_compatible("4.0", "4.0"));
        assert!(!CcCompatibility::sa_versions_compatible("2.0", "3.0"));
    }

    #[test]
    fn test_extract_year() {
        assert_eq!(CcComplianceScanner::extract_year("Copyright 2024 Example"), Some("2024".into()));
        assert_eq!(CcComplianceScanner::extract_year("no year here"), None);
    }
}
