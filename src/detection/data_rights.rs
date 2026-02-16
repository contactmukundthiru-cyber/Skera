//! Data rights and database rights — GDPR, CCPA, database copyright
//!
//! ## Why This Matters
//!
//! Data has its own unique copyright regime that is separate from software
//! licensing. In the EU, databases have a *sui generis* right under the
//! Database Directive (96/9/EC). In the US, data cannot be copyrighted
//! (Feist v. Rural Tel.), but the "sweat of the brow" doctrine still
//! applies in other jurisdictions.
//!
//! Additionally, data that contains personal information triggers GDPR/CCPA
//! obligations that intersect with license compliance. An MIT-licensed
//! project that ships with a CSV of 50,000 email addresses has a *data
//! rights* problem, not a *license* problem.
//!
//! ## What This Module Detects
//!
//! 1. **Database Licenses** — ODbL, CDLA, DbCL, CC licenses applied to data,
//!    Open Data Commons, government open data licenses
//!
//! 2. **PII Detection** — emails, phone numbers, SSNs, IP addresses, names
//!    in bundled data files that trigger GDPR/CCPA obligations
//!
//! 3. **Data File Analysis** — scans CSV, JSON, JSONL, Parquet, SQLite, XML
//!    for licensing headers and PII patterns
//!
//! 4. **API Key Exposure** — detects bundled API keys, tokens, credentials
//!    that may indicate scraped/unauthorized data
//!
//! 5. **Geodata Licensing** — OpenStreetMap (ODbL), Google Maps ToS,
//!    Mapbox licensing, Census data (public domain)
//!
//! 6. **Training Data** — ML datasets with their own licenses (ImageNet,
//!    Common Crawl, LAION, etc.)
//!
//! 7. **Government Data** — US government data is public domain, but
//!    other governments have varying open data licenses

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─── Core Types ─────────────────────────────────────────────────────

/// Complete data rights analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRightsReport {
    /// Root directory scanned
    pub root: PathBuf,
    /// Data files found
    pub data_files: Vec<DataFileAnalysis>,
    /// PII findings
    pub pii_findings: Vec<PiiFinding>,
    /// Database/data license detections
    pub data_licenses: Vec<DataLicense>,
    /// Exposed secrets (API keys, tokens)
    pub exposed_secrets: Vec<ExposedSecret>,
    /// Geodata usage
    pub geodata_usage: Vec<GeodataUsage>,
    /// ML training data
    pub ml_datasets: Vec<MlDatasetUsage>,
    /// Total files scanned
    pub files_scanned: usize,
    /// Overall risk score
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFileAnalysis {
    pub path: PathBuf,
    pub format: DataFormat,
    pub size_bytes: u64,
    pub record_count: Option<usize>,
    pub has_license_header: bool,
    pub detected_license: Option<String>,
    pub pii_risk: PiiRiskLevel,
    pub column_names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFormat {
    Csv,
    Tsv,
    Json,
    JsonLines,
    Xml,
    Yaml,
    Sqlite,
    Parquet,
    Excel,
    Sql,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PiiRiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFinding {
    pub pii_type: PiiType,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub sample: String,
    pub confidence: f64,
    pub regulations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PiiType {
    Email,
    PhoneNumber,
    SocialSecurityNumber,
    IpAddress,
    CreditCardNumber,
    DateOfBirth,
    Address,
    Name,
    Passport,
    DriverLicense,
    MedicalRecord,
    BiometricData,
    GpsCoordinates,
    DeviceIdentifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLicense {
    pub license_type: DataLicenseType,
    pub identifier: String,
    pub file_path: PathBuf,
    pub obligations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataLicenseType {
    /// Open Database License (ODbL) — used by OpenStreetMap
    ODbL,
    /// Community Data License Agreement — Permissive
    CdlaPermissive,
    /// Community Data License Agreement — Sharing
    CdlaSharing,
    /// Database Contents License (DbCL)
    DbCL,
    /// Open Data Commons — Attribution
    OdcBy,
    /// Open Data Commons — Public Domain Dedication
    Pddl,
    /// Creative Commons (applied to data)
    CreativeCommons,
    /// US Government Public Domain
    UsGovPublicDomain,
    /// UK Open Government License
    UkOgl,
    /// Custom/proprietary
    Proprietary,
    /// Unknown
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedSecret {
    pub secret_type: SecretType,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub pattern: String,
    pub redacted_value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    ApiKey,
    OAuthToken,
    JwtToken,
    DatabaseUrl,
    AwsAccessKey,
    AwsSecretKey,
    GcpServiceAccount,
    StripeKey,
    SendgridKey,
    TwilioKey,
    SlackToken,
    GitHubToken,
    PrivateKey,
    Password,
    GenericSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeodataUsage {
    pub provider: GeodataProvider,
    pub file_path: PathBuf,
    pub license: String,
    pub attribution_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeodataProvider {
    OpenStreetMap,
    GoogleMaps,
    Mapbox,
    Here,
    TomTom,
    CensusGov,
    NaturalEarth,
    Overture,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlDatasetUsage {
    pub dataset_name: String,
    pub license: String,
    pub restrictions: Vec<String>,
    pub file_path: PathBuf,
}

// ─── Data License Patterns ──────────────────────────────────────────

const DATA_LICENSE_PATTERNS: &[(&str, DataLicenseType, &str)] = &[
    ("opendatacommons.org/licenses/odbl", DataLicenseType::ODbL, "ODbL-1.0"),
    ("open database license", DataLicenseType::ODbL, "ODbL-1.0"),
    ("odbl", DataLicenseType::ODbL, "ODbL-1.0"),
    ("cdla-permissive", DataLicenseType::CdlaPermissive, "CDLA-Permissive-2.0"),
    ("community data license agreement.*permissive", DataLicenseType::CdlaPermissive, "CDLA-Permissive-2.0"),
    ("cdla-sharing", DataLicenseType::CdlaSharing, "CDLA-Sharing-1.0"),
    ("community data license agreement.*sharing", DataLicenseType::CdlaSharing, "CDLA-Sharing-1.0"),
    ("database contents license", DataLicenseType::DbCL, "DbCL-1.0"),
    ("odc-by", DataLicenseType::OdcBy, "ODC-By-1.0"),
    ("open data commons attribution", DataLicenseType::OdcBy, "ODC-By-1.0"),
    ("pddl", DataLicenseType::Pddl, "PDDL-1.0"),
    ("public domain dedication and licence", DataLicenseType::Pddl, "PDDL-1.0"),
    ("open government licence", DataLicenseType::UkOgl, "OGL-UK-3.0"),
    ("nationalarchives.gov.uk/doc/open-government-licence", DataLicenseType::UkOgl, "OGL-UK-3.0"),
];

/// Known ML datasets and their licenses
const ML_DATASET_LICENSES: &[(&str, &str, &[&str])] = &[
    ("imagenet", "Custom (research-only)", &["non-commercial use only", "no redistribution"]),
    ("common crawl", "Public Domain (CC0)", &["no restrictions on use"]),
    ("laion", "CC-BY-4.0 (metadata), Various (images)", &["attribution required for metadata"]),
    ("openimages", "CC-BY-4.0", &["attribution required"]),
    ("coco", "CC-BY-4.0", &["attribution required"]),
    ("wikitext", "CC-BY-SA-3.0", &["attribution required", "share-alike"]),
    ("squad", "CC-BY-SA-4.0", &["attribution required", "share-alike"]),
    ("glue", "Various per sub-dataset", &["check individual dataset licenses"]),
    ("mnist", "CC-BY-SA-3.0", &["attribution required", "share-alike"]),
    ("cifar", "Custom (research)", &["citation required"]),
    ("librispeech", "CC-BY-4.0", &["attribution required"]),
    ("voxceleb", "CC-BY-SA-4.0", &["non-commercial use only in practice"]),
    ("the pile", "Various per sub-dataset", &["check component licenses"]),
    ("c4", "ODC-By-1.0 / Public Domain", &["attribution preferred"]),
    ("redpajama", "Various per sub-dataset", &["check component licenses"]),
    ("starcoder", "Various per repository", &["opt-out respected"]),
    ("dolma", "ODC-By-1.0", &["attribution required"]),
];

/// PII-suggestive column/field names
const PII_COLUMN_NAMES: &[(&str, PiiType)] = &[
    ("email", PiiType::Email),
    ("e_mail", PiiType::Email),
    ("email_address", PiiType::Email),
    ("phone", PiiType::PhoneNumber),
    ("phone_number", PiiType::PhoneNumber),
    ("telephone", PiiType::PhoneNumber),
    ("mobile", PiiType::PhoneNumber),
    ("ssn", PiiType::SocialSecurityNumber),
    ("social_security", PiiType::SocialSecurityNumber),
    ("ip_address", PiiType::IpAddress),
    ("ip_addr", PiiType::IpAddress),
    ("client_ip", PiiType::IpAddress),
    ("user_ip", PiiType::IpAddress),
    ("credit_card", PiiType::CreditCardNumber),
    ("card_number", PiiType::CreditCardNumber),
    ("cc_num", PiiType::CreditCardNumber),
    ("date_of_birth", PiiType::DateOfBirth),
    ("dob", PiiType::DateOfBirth),
    ("birthdate", PiiType::DateOfBirth),
    ("birthday", PiiType::DateOfBirth),
    ("address", PiiType::Address),
    ("street_address", PiiType::Address),
    ("home_address", PiiType::Address),
    ("first_name", PiiType::Name),
    ("last_name", PiiType::Name),
    ("full_name", PiiType::Name),
    ("username", PiiType::Name),
    ("user_name", PiiType::Name),
    ("passport", PiiType::Passport),
    ("passport_number", PiiType::Passport),
    ("driver_license", PiiType::DriverLicense),
    ("drivers_license", PiiType::DriverLicense),
    ("latitude", PiiType::GpsCoordinates),
    ("longitude", PiiType::GpsCoordinates),
    ("lat", PiiType::GpsCoordinates),
    ("lng", PiiType::GpsCoordinates),
    ("device_id", PiiType::DeviceIdentifier),
    ("device_fingerprint", PiiType::DeviceIdentifier),
    ("imei", PiiType::DeviceIdentifier),
];

/// Secret patterns
const SECRET_PATTERNS: &[(&str, SecretType, &str)] = &[
    ("AIza[0-9A-Za-z_-]{35}", SecretType::ApiKey, "Google API Key"),
    ("AKIA[0-9A-Z]{16}", SecretType::AwsAccessKey, "AWS Access Key"),
    ("sk_live_[0-9a-zA-Z]{24}", SecretType::StripeKey, "Stripe Live Key"),
    ("sk_test_[0-9a-zA-Z]{24}", SecretType::StripeKey, "Stripe Test Key"),
    ("SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}", SecretType::SendgridKey, "SendGrid Key"),
    ("ghp_[0-9A-Za-z]{36}", SecretType::GitHubToken, "GitHub Personal Token"),
    ("gho_[0-9A-Za-z]{36}", SecretType::GitHubToken, "GitHub OAuth Token"),
    ("xoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", SecretType::SlackToken, "Slack Bot Token"),
    ("xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-f]{32}", SecretType::SlackToken, "Slack User Token"),
    ("-----BEGIN RSA PRIVATE KEY-----", SecretType::PrivateKey, "RSA Private Key"),
    ("-----BEGIN EC PRIVATE KEY-----", SecretType::PrivateKey, "EC Private Key"),
    ("-----BEGIN PRIVATE KEY-----", SecretType::PrivateKey, "Private Key"),
    ("password", SecretType::Password, "Password in file"),
];

// ─── Data Rights Scanner ────────────────────────────────────────────

pub struct DataRightsScanner;

impl DataRightsScanner {
    /// Run a complete data rights scan
    pub fn scan(root: &Path) -> DataRightsReport {
        let mut report = DataRightsReport {
            root: root.to_path_buf(),
            data_files: Vec::new(),
            pii_findings: Vec::new(),
            data_licenses: Vec::new(),
            exposed_secrets: Vec::new(),
            geodata_usage: Vec::new(),
            ml_datasets: Vec::new(),
            files_scanned: 0,
            risk_score: 0,
        };

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

            let format = match ext.as_str() {
                "csv" => Some(DataFormat::Csv),
                "tsv" => Some(DataFormat::Tsv),
                "json" => Some(DataFormat::Json),
                "jsonl" | "ndjson" => Some(DataFormat::JsonLines),
                "xml" => Some(DataFormat::Xml),
                "yaml" | "yml" => Some(DataFormat::Yaml),
                "sqlite" | "db" | "sqlite3" => Some(DataFormat::Sqlite),
                "parquet" => Some(DataFormat::Parquet),
                "xlsx" | "xls" => Some(DataFormat::Excel),
                "sql" => Some(DataFormat::Sql),
                _ => None,
            };

            if let Some(fmt) = format {
                report.files_scanned += 1;
                Self::analyze_data_file(entry.path(), fmt, &mut report);
            }

            // Also scan code files for secrets and geodata
            match ext.as_str() {
                "py" | "js" | "ts" | "rs" | "go" | "java" | "rb" | "php"
                | "env" | "cfg" | "conf" | "ini" | "toml" => {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        Self::scan_for_secrets(&content, entry.path(), &mut report);
                        Self::scan_for_geodata(&content, entry.path(), &mut report);
                        Self::scan_for_ml_datasets(&content, entry.path(), &mut report);
                    }
                }
                _ => {}
            }
        }

        // Check for data license files
        Self::scan_for_data_licenses(root, &mut report);

        // Calculate risk
        report.risk_score = Self::calculate_risk(&report);

        report
    }

    fn analyze_data_file(path: &Path, format: DataFormat, report: &mut DataRightsReport) {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        // For very large files, only read the header
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let header = if content.len() > 10_000 {
            &content[..10_000]
        } else {
            &content
        };

        let lower = header.to_lowercase();

        // Extract column names
        let column_names = Self::extract_column_names(header, format);

        // Check for license in header
        let has_license_header = lower.contains("license") || lower.contains("licence")
            || lower.contains("copyright") || lower.contains("odbl")
            || lower.contains("creative commons");

        let detected_license = if has_license_header {
            DATA_LICENSE_PATTERNS.iter()
                .find(|&&(pat, _, _)| lower.contains(pat))
                .map(|&(_, _, id)| id.to_string())
        } else {
            None
        };

        // Check PII risk
        let pii_risk = Self::assess_pii_risk(&column_names, header, path, report);

        // Count records (approximate)
        let record_count = match format {
            DataFormat::Csv | DataFormat::Tsv => {
                Some(content.lines().count().saturating_sub(1)) // minus header
            }
            DataFormat::JsonLines => Some(content.lines().count()),
            _ => None,
        };

        report.data_files.push(DataFileAnalysis {
            path: path.to_path_buf(),
            format,
            size_bytes: size,
            record_count,
            has_license_header,
            detected_license,
            pii_risk,
            column_names,
        });
    }

    fn extract_column_names(content: &str, format: DataFormat) -> Vec<String> {
        match format {
            DataFormat::Csv => {
                content.lines().next()
                    .map(|line| line.split(',')
                        .map(|col| col.trim().trim_matches('"').to_lowercase())
                        .collect())
                    .unwrap_or_default()
            }
            DataFormat::Tsv => {
                content.lines().next()
                    .map(|line| line.split('\t')
                        .map(|col| col.trim().trim_matches('"').to_lowercase())
                        .collect())
                    .unwrap_or_default()
            }
            DataFormat::Json => {
                // Try to extract top-level keys from first object
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
                    match val {
                        serde_json::Value::Object(map) => {
                            map.keys().map(|k| k.to_lowercase()).collect()
                        }
                        serde_json::Value::Array(arr) => {
                            if let Some(serde_json::Value::Object(map)) = arr.first() {
                                map.keys().map(|k| k.to_lowercase()).collect()
                            } else {
                                Vec::new()
                            }
                        }
                        _ => Vec::new(),
                    }
                } else {
                    Vec::new()
                }
            }
            DataFormat::JsonLines => {
                content.lines().next()
                    .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .and_then(|val| {
                        if let serde_json::Value::Object(map) = val {
                            Some(map.keys().map(|k| k.to_lowercase()).collect())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        }
    }

    fn assess_pii_risk(
        columns: &[String],
        content: &str,
        path: &Path,
        report: &mut DataRightsReport,
    ) -> PiiRiskLevel {
        let mut risk = PiiRiskLevel::None;

        // Check column names against PII patterns
        for col in columns {
            let col_normalized = col.replace(' ', "_").replace('-', "_");
            for &(pattern, pii_type) in PII_COLUMN_NAMES {
                if col_normalized == pattern || col_normalized.contains(pattern) {
                    report.pii_findings.push(PiiFinding {
                        pii_type,
                        file_path: path.to_path_buf(),
                        line_number: 1,
                        sample: format!("Column: '{}'", col),
                        confidence: 0.9,
                        regulations: Self::regulations_for_pii(pii_type),
                    });
                    risk = Self::max_pii_risk(risk, Self::pii_risk_for_type(pii_type));
                }
            }
        }

        // Pattern-based detection in content
        let lower = content.to_lowercase();

        // Email detection (simple)
        if Self::contains_email_pattern(content) {
            let existing = report.pii_findings.iter()
                .any(|f| f.pii_type == PiiType::Email && f.file_path == path);
            if !existing {
                report.pii_findings.push(PiiFinding {
                    pii_type: PiiType::Email,
                    file_path: path.to_path_buf(),
                    line_number: 0,
                    sample: "(email pattern detected in data)".into(),
                    confidence: 0.8,
                    regulations: vec!["GDPR Art. 4(1)".into(), "CCPA §1798.140(o)".into()],
                });
                risk = Self::max_pii_risk(risk, PiiRiskLevel::Medium);
            }
        }

        // IP address detection
        if Self::contains_ip_pattern(content) {
            let existing = report.pii_findings.iter()
                .any(|f| f.pii_type == PiiType::IpAddress && f.file_path == path);
            if !existing {
                report.pii_findings.push(PiiFinding {
                    pii_type: PiiType::IpAddress,
                    file_path: path.to_path_buf(),
                    line_number: 0,
                    sample: "(IP address pattern detected in data)".into(),
                    confidence: 0.7,
                    regulations: vec!["GDPR Art. 4(1) — IP addresses are personal data".into()],
                });
                risk = Self::max_pii_risk(risk, PiiRiskLevel::Low);
            }
        }

        let _ = lower;
        risk
    }

    fn scan_for_secrets(content: &str, path: &Path, report: &mut DataRightsReport) {
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            // Skip comments and obvious non-secret lines
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
                // Even comments can have secrets
            }

            // Check each secret pattern
            for &(pattern_desc, secret_type, description) in SECRET_PATTERNS {
                let check = match secret_type {
                    SecretType::AwsAccessKey => line.contains("AKIA"),
                    SecretType::StripeKey => line.contains("sk_live_") || line.contains("sk_test_"),
                    SecretType::GitHubToken => line.contains("ghp_") || line.contains("gho_"),
                    SecretType::PrivateKey => line.contains("-----BEGIN") && line.contains("PRIVATE KEY"),
                    SecretType::SlackToken => line.contains("xoxb-") || line.contains("xoxp-"),
                    SecretType::Password => {
                        let lower = line.to_lowercase();
                        (lower.contains("password") || lower.contains("passwd"))
                            && (lower.contains("=") || lower.contains(":"))
                            && !lower.contains("password_hash") // Exclude hash references
                            && !lower.contains("passwordreset")
                            && !lower.contains("password_field")
                    }
                    _ => line.contains(pattern_desc),
                };

                if check {
                    // Redact the value
                    let redacted = Self::redact_value(line);

                    report.exposed_secrets.push(ExposedSecret {
                        secret_type,
                        file_path: path.to_path_buf(),
                        line_number: i + 1,
                        pattern: description.to_string(),
                        redacted_value: redacted,
                    });
                }
            }
        }
    }

    fn scan_for_geodata(content: &str, path: &Path, report: &mut DataRightsReport) {
        let lower = content.to_lowercase();

        let geo_patterns: &[(&str, GeodataProvider, &str, bool)] = &[
            ("openstreetmap", GeodataProvider::OpenStreetMap, "ODbL-1.0", true),
            ("osm", GeodataProvider::OpenStreetMap, "ODbL-1.0", true),
            ("maps.googleapis.com", GeodataProvider::GoogleMaps, "Google Maps ToS (not freely redistributable)", true),
            ("google.maps", GeodataProvider::GoogleMaps, "Google Maps ToS", true),
            ("api.mapbox.com", GeodataProvider::Mapbox, "Mapbox ToS", true),
            ("mapbox.com", GeodataProvider::Mapbox, "Mapbox ToS", true),
            ("here.com/maps", GeodataProvider::Here, "HERE Maps ToS", true),
            ("api.tomtom.com", GeodataProvider::TomTom, "TomTom ToS", true),
            ("census.gov", GeodataProvider::CensusGov, "US Government Public Domain", false),
            ("naturalearthdata.com", GeodataProvider::NaturalEarth, "Public Domain", false),
            ("overturemaps", GeodataProvider::Overture, "CDLA-Permissive-2.0 / ODbL", true),
        ];

        for &(pattern, provider, license, attr_required) in geo_patterns {
            if lower.contains(pattern) {
                let already = report.geodata_usage.iter()
                    .any(|g| g.provider == provider && g.file_path == path);
                if !already {
                    report.geodata_usage.push(GeodataUsage {
                        provider,
                        file_path: path.to_path_buf(),
                        license: license.to_string(),
                        attribution_required: attr_required,
                    });
                }
            }
        }
    }

    fn scan_for_ml_datasets(content: &str, path: &Path, report: &mut DataRightsReport) {
        let lower = content.to_lowercase();

        for &(name, license, restrictions) in ML_DATASET_LICENSES {
            if lower.contains(name) {
                let already = report.ml_datasets.iter()
                    .any(|d| d.dataset_name == name);
                if !already {
                    report.ml_datasets.push(MlDatasetUsage {
                        dataset_name: name.to_string(),
                        license: license.to_string(),
                        restrictions: restrictions.iter().map(|r| r.to_string()).collect(),
                        file_path: path.to_path_buf(),
                    });
                }
            }
        }
    }

    fn scan_for_data_licenses(root: &Path, report: &mut DataRightsReport) {
        // Check common data license file locations
        let license_files = [
            "DATA-LICENSE", "DATA-LICENSE.md", "DATA-LICENSE.txt",
            "DATA_LICENSE", "DATA_LICENSE.md",
            "LICENSE-DATA", "LICENSE-DATA.md",
        ];

        for name in &license_files {
            let path = root.join(name);
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let lower = content.to_lowercase();
                    for &(pattern, lic_type, identifier) in DATA_LICENSE_PATTERNS {
                        if lower.contains(pattern) {
                            report.data_licenses.push(DataLicense {
                                license_type: lic_type,
                                identifier: identifier.to_string(),
                                file_path: path.clone(),
                                obligations: Self::obligations_for_license(lic_type),
                            });
                            break;
                        }
                    }
                }
            }
        }

        // Also check main LICENSE files for data-specific licenses
        for name in &["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md"] {
            let path = root.join(name);
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let lower = content.to_lowercase();
                    for &(pattern, lic_type, identifier) in DATA_LICENSE_PATTERNS {
                        if lower.contains(pattern) {
                            let already = report.data_licenses.iter()
                                .any(|d| d.identifier == identifier);
                            if !already {
                                report.data_licenses.push(DataLicense {
                                    license_type: lic_type,
                                    identifier: identifier.to_string(),
                                    file_path: path.clone(),
                                    obligations: Self::obligations_for_license(lic_type),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Utility Methods ─────────────────────────────────────────────

    fn contains_email_pattern(text: &str) -> bool {
        // Simple check: word@word.word
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let mut i = 0;
        while i < len.saturating_sub(5) {
            if chars[i] == '@' && i > 0 && i + 2 < len {
                let before = chars[i - 1].is_alphanumeric();
                let after = chars[i + 1].is_alphanumeric();
                // Look for dot after @
                let end = (i + 50).min(len);
                let has_dot = end > i + 3 && text[i..end].contains('.');
                if before && after && has_dot {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn contains_ip_pattern(text: &str) -> bool {
        // Look for patterns like 192.168.1.1
        let parts: Vec<&str> = text.split(|c: char| !c.is_ascii_digit() && c != '.').collect();
        for part in parts {
            let octets: Vec<&str> = part.split('.').collect();
            if octets.len() == 4 {
                let valid = octets.iter().all(|o| {
                    o.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
                });
                if valid {
                    return true;
                }
            }
        }
        false
    }

    fn redact_value(line: &str) -> String {
        // Replace actual secret values with asterisks
        let trimmed = line.trim();
        if trimmed.len() > 20 {
            format!("{}...{}", &trimmed[..8], &trimmed[trimmed.len() - 4..])
        } else {
            format!("{}...", &trimmed[..trimmed.len().min(8)])
        }
    }

    fn regulations_for_pii(pii_type: PiiType) -> Vec<String> {
        match pii_type {
            PiiType::Email => vec![
                "GDPR Art. 4(1) — personal data".into(),
                "CCPA §1798.140(o) — personal information".into(),
            ],
            PiiType::PhoneNumber => vec![
                "GDPR Art. 4(1)".into(),
                "TCPA — telephone consumer protection".into(),
            ],
            PiiType::SocialSecurityNumber | PiiType::Passport | PiiType::DriverLicense => vec![
                "GDPR Art. 9 — special categories".into(),
                "CCPA §1798.140(o) — sensitive personal information".into(),
                "HIPAA — if health-related".into(),
            ],
            PiiType::IpAddress => vec![
                "GDPR Art. 4(1) — IP addresses are personal data (CJEU ruling)".into(),
            ],
            PiiType::CreditCardNumber => vec![
                "PCI DSS — payment card data".into(),
                "GDPR Art. 4(1)".into(),
            ],
            PiiType::MedicalRecord | PiiType::BiometricData => vec![
                "GDPR Art. 9 — special categories of data".into(),
                "HIPAA — health information".into(),
                "BIPA — biometric data (Illinois)".into(),
            ],
            _ => vec![
                "GDPR Art. 4(1)".into(),
                "CCPA §1798.140(o)".into(),
            ],
        }
    }

    fn pii_risk_for_type(pii_type: PiiType) -> PiiRiskLevel {
        match pii_type {
            PiiType::SocialSecurityNumber | PiiType::CreditCardNumber
            | PiiType::MedicalRecord | PiiType::BiometricData => PiiRiskLevel::Critical,
            PiiType::Passport | PiiType::DriverLicense => PiiRiskLevel::High,
            PiiType::Email | PiiType::PhoneNumber | PiiType::DateOfBirth
            | PiiType::Name | PiiType::Address => PiiRiskLevel::Medium,
            PiiType::IpAddress | PiiType::GpsCoordinates
            | PiiType::DeviceIdentifier => PiiRiskLevel::Low,
        }
    }

    fn max_pii_risk(a: PiiRiskLevel, b: PiiRiskLevel) -> PiiRiskLevel {
        let rank = |r: PiiRiskLevel| match r {
            PiiRiskLevel::None => 0,
            PiiRiskLevel::Low => 1,
            PiiRiskLevel::Medium => 2,
            PiiRiskLevel::High => 3,
            PiiRiskLevel::Critical => 4,
        };
        if rank(a) >= rank(b) { a } else { b }
    }

    fn obligations_for_license(lic_type: DataLicenseType) -> Vec<String> {
        match lic_type {
            DataLicenseType::ODbL => vec![
                "Attribution required".into(),
                "Share-alike: derivatives must be ODbL".into(),
                "Keep open: API access must not restrict".into(),
            ],
            DataLicenseType::CdlaPermissive => vec![
                "Attribution required".into(),
                "No copyleft on enhanced data".into(),
            ],
            DataLicenseType::CdlaSharing => vec![
                "Attribution required".into(),
                "Share-alike: enhanced data must be CDLA-Sharing".into(),
            ],
            DataLicenseType::DbCL => vec![
                "No restrictions on individual contents".into(),
                "Database structure may have separate protection".into(),
            ],
            DataLicenseType::OdcBy => vec![
                "Attribution required".into(),
                "No share-alike requirement".into(),
            ],
            DataLicenseType::Pddl => vec![
                "No restrictions — public domain".into(),
            ],
            DataLicenseType::UkOgl => vec![
                "Attribution to Crown copyright".into(),
                "No restrictions on commercial use".into(),
            ],
            _ => vec![],
        }
    }

    fn calculate_risk(report: &DataRightsReport) -> u32 {
        let mut score: u32 = 0;

        // PII findings
        for finding in &report.pii_findings {
            score += match finding.pii_type {
                PiiType::SocialSecurityNumber | PiiType::CreditCardNumber => 25,
                PiiType::MedicalRecord | PiiType::BiometricData => 25,
                PiiType::Passport | PiiType::DriverLicense => 20,
                PiiType::Email | PiiType::PhoneNumber => 10,
                _ => 5,
            };
        }

        // Exposed secrets
        score += report.exposed_secrets.len() as u32 * 15;

        // Unlicensed data files
        let unlicensed = report.data_files.iter()
            .filter(|f| f.detected_license.is_none() && f.size_bytes > 1000)
            .count();
        score += unlicensed as u32 * 3;

        score.min(100)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        assert!(DataRightsScanner::contains_email_pattern("user@example.com"));
        assert!(DataRightsScanner::contains_email_pattern("data,user@test.org,more"));
        assert!(!DataRightsScanner::contains_email_pattern("no emails here"));
    }

    #[test]
    fn test_ip_detection() {
        assert!(DataRightsScanner::contains_ip_pattern("192.168.1.1"));
        assert!(DataRightsScanner::contains_ip_pattern("log: 10.0.0.1 connected"));
        assert!(!DataRightsScanner::contains_ip_pattern("version 1.2.3.4.5"));
    }

    #[test]
    fn test_pii_risk_levels() {
        assert_eq!(
            DataRightsScanner::pii_risk_for_type(PiiType::SocialSecurityNumber),
            PiiRiskLevel::Critical
        );
        assert_eq!(
            DataRightsScanner::pii_risk_for_type(PiiType::Email),
            PiiRiskLevel::Medium
        );
        assert_eq!(
            DataRightsScanner::pii_risk_for_type(PiiType::IpAddress),
            PiiRiskLevel::Low
        );
    }

    #[test]
    fn test_obligations() {
        let odbl = DataRightsScanner::obligations_for_license(DataLicenseType::ODbL);
        assert!(odbl.iter().any(|o| o.contains("Attribution")));
        assert!(odbl.iter().any(|o| o.contains("Share-alike")));

        let pddl = DataRightsScanner::obligations_for_license(DataLicenseType::Pddl);
        assert!(pddl.iter().any(|o| o.contains("public domain")));
    }

    #[test]
    fn test_csv_column_extraction() {
        let csv = "name,email,phone\nJohn,john@x.com,555\n";
        let cols = DataRightsScanner::extract_column_names(csv, DataFormat::Csv);
        assert_eq!(cols, vec!["name", "email", "phone"]);
    }

    #[test]
    fn test_max_risk() {
        assert_eq!(
            DataRightsScanner::max_pii_risk(PiiRiskLevel::Low, PiiRiskLevel::High),
            PiiRiskLevel::High
        );
        assert_eq!(
            DataRightsScanner::max_pii_risk(PiiRiskLevel::Critical, PiiRiskLevel::Low),
            PiiRiskLevel::Critical
        );
    }
}
