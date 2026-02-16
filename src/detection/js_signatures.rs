//! Data-driven signature loading from TOML files
//!
//! ALL signatures live in external TOML files under `data/signatures/`.
//! They are embedded at compile time via `include_str!()` so the binary
//! is self-contained, but adding new signatures only requires editing
//! TOML — zero Rust code changes.
//!
//! # Adding a new library signature
//!
//! Edit `data/signatures/libraries.toml` and add a new `[[lib]]` entry:
//!
//! ```toml
//! [[lib]]
//! name = "MyLibrary"
//! author = "Author Name"
//! license = "MIT"
//! family = "permissive"
//! min_hits = 2
//! copyright = "(c) Author Name"
//! source = "https://github.com/..."
//! strings = [
//!   { p = "unique error message", d = "description", c = 0.99 },
//! ]
//! ```

use super::js_bundle_forensics::{
    LibrarySignature, LicenseFamily, StringFingerprint, StructuralPattern,
    StructuralPatternKind, VersionPattern,
};
use serde::Deserialize;
use std::sync::OnceLock;

// ─── Embedded TOML Data ────────────────────────────────────────────

const LIBRARIES_TOML: &str = include_str!("../../data/signatures/libraries.toml");
const ASSETS_TOML: &str = include_str!("../../data/signatures/assets.toml");

// ─── Singleton Database ────────────────────────────────────────────

static SIGNATURE_DB: OnceLock<Vec<LibrarySignature>> = OnceLock::new();

/// Get the full signature database (loaded once, cached forever).
///
/// Returns all library, font, CSS framework, and icon set signatures
/// loaded from the embedded TOML files.
pub fn signature_database() -> &'static [LibrarySignature] {
    SIGNATURE_DB.get_or_init(|| {
        let mut sigs = Vec::new();

        // ── Load library code signatures ───────────────────────
        match toml::from_str::<LibraryDatabase>(LIBRARIES_TOML) {
            Ok(db) => {
                tracing::info!("Loaded {} library signatures", db.lib.len());
                for entry in db.lib {
                    sigs.push(entry.into_signature());
                }
            }
            Err(e) => {
                tracing::error!("Failed to parse libraries.toml: {}", e);
            }
        }

        // ── Load asset signatures (fonts, CSS, icons) ──────────
        match toml::from_str::<AssetDatabase>(ASSETS_TOML) {
            Ok(db) => {
                let count = db.font.len() + db.css.len() + db.icon.len();
                tracing::info!("Loaded {} asset signatures", count);
                for entry in db.font {
                    sigs.push(entry.into_signature());
                }
                for entry in db.css {
                    sigs.push(entry.into_signature());
                }
                for entry in db.icon {
                    sigs.push(entry.into_signature());
                }
            }
            Err(e) => {
                tracing::error!("Failed to parse assets.toml: {}", e);
            }
        }

        sigs
    })
}

/// Load additional signatures from an external TOML file at runtime.
/// Returns the parsed signatures (caller merges into their scanner).
pub fn load_external_signatures(toml_content: &str) -> Vec<LibrarySignature> {
    let mut sigs = Vec::new();

    if let Ok(db) = toml::from_str::<LibraryDatabase>(toml_content) {
        for entry in db.lib {
            sigs.push(entry.into_signature());
        }
    }

    if let Ok(db) = toml::from_str::<AssetDatabase>(toml_content) {
        for entry in db.font {
            sigs.push(entry.into_signature());
        }
        for entry in db.css {
            sigs.push(entry.into_signature());
        }
        for entry in db.icon {
            sigs.push(entry.into_signature());
        }
    }

    sigs
}

// ─── TOML Schema: Libraries ───────────────────────────────────────

#[derive(Deserialize)]
struct LibraryDatabase {
    #[serde(default)]
    lib: Vec<LibEntry>,
}

#[derive(Deserialize)]
struct LibEntry {
    name: String,
    author: String,
    license: String,
    family: String,
    min_hits: usize,
    copyright: String,
    source: String,
    #[serde(default)]
    commercial_restriction: Option<String>,
    #[serde(default)]
    strings: Vec<FpEntry>,
    #[serde(default)]
    constants: Vec<ConstEntry>,
    #[serde(default)]
    versions: Vec<VerEntry>,
}

/// Fingerprint entry: p=pattern, d=description, c=confidence
#[derive(Deserialize)]
struct FpEntry {
    p: String,
    d: String,
    c: f64,
}

/// Structural constant entry: v=value, d=description, c=confidence, k=kind
#[derive(Deserialize)]
struct ConstEntry {
    v: String,
    d: String,
    c: f64,
    #[serde(default = "default_const_kind")]
    k: String,
}

fn default_const_kind() -> String {
    "magic".into()
}

/// Version pattern entry: r=regex, d=description
#[derive(Deserialize)]
struct VerEntry {
    r: String,
    d: String,
}

// ─── TOML Schema: Assets (Fonts, CSS, Icons) ──────────────────────

#[derive(Deserialize)]
struct AssetDatabase {
    #[serde(default)]
    font: Vec<FontEntry>,
    #[serde(default)]
    css: Vec<CssEntry>,
    #[serde(default)]
    icon: Vec<IconEntry>,
}

#[derive(Deserialize)]
struct FontEntry {
    name: String,
    foundry: String,
    license: String,
    family: String,
    source: String,
    #[serde(default)]
    requires_license: bool,
    #[serde(default)]
    detection_strings: Vec<String>,
    #[serde(default)]
    css_families: Vec<String>,
    #[serde(default)]
    file_patterns: Vec<String>,
}

#[derive(Deserialize)]
struct CssEntry {
    name: String,
    author: String,
    license: String,
    family: String,
    source: String,
    #[serde(default)]
    class_patterns: Vec<String>,
    #[serde(default)]
    strings: Vec<String>,
}

#[derive(Deserialize)]
struct IconEntry {
    name: String,
    author: String,
    license: String,
    family: String,
    source: String,
    #[serde(default)]
    pro_license: Option<String>,
    #[serde(default)]
    class_patterns: Vec<String>,
    #[serde(default)]
    strings: Vec<String>,
}

// ─── Conversion: TOML → LibrarySignature ──────────────────────────

fn parse_family(s: &str) -> LicenseFamily {
    match s {
        "permissive" => LicenseFamily::Permissive,
        "permissive_notice" => LicenseFamily::PermissiveNotice,
        "weak_copyleft" => LicenseFamily::WeakCopyleft,
        "strong_copyleft" => LicenseFamily::StrongCopyleft,
        "commercial_restricted" => LicenseFamily::CommercialRestricted,
        "source_available" => LicenseFamily::SourceAvailable,
        "proprietary" => LicenseFamily::Proprietary,
        "sil_ofl" => LicenseFamily::Permissive,
        _ => LicenseFamily::Permissive,
    }
}

impl LibEntry {
    fn into_signature(self) -> LibrarySignature {
        let string_fingerprints = self
            .strings
            .into_iter()
            .map(|fp| StringFingerprint {
                pattern: fp.p,
                description: fp.d,
                confidence: fp.c,
                version_specific: false,
            })
            .collect();

        let structural_patterns = self
            .constants
            .into_iter()
            .map(|cp| {
                let kind = match cp.k.as_str() {
                    "crypto" => StructuralPatternKind::CryptoConstant,
                    "module" => StructuralPatternKind::ModulePattern,
                    "internal" => StructuralPatternKind::InternalString,
                    "hex" => StructuralPatternKind::HexConstant,
                    _ => StructuralPatternKind::MagicNumber,
                };
                StructuralPattern {
                    kind,
                    value: cp.v,
                    description: cp.d,
                    confidence: cp.c,
                }
            })
            .collect();

        let version_patterns = self
            .versions
            .into_iter()
            .map(|vp| VersionPattern {
                regex: vp.r,
                description: vp.d,
            })
            .collect();

        LibrarySignature {
            name: self.name,
            author: self.author,
            license: self.license,
            license_family: parse_family(&self.family),
            string_fingerprints,
            structural_patterns,
            version_patterns,
            min_fingerprint_hits: self.min_hits,
            expected_copyright: self.copyright,
            canonical_source: self.source,
            commercial_restriction: self.commercial_restriction,
        }
    }
}

impl FontEntry {
    fn into_signature(self) -> LibrarySignature {
        let mut fps = Vec::new();

        for s in &self.detection_strings {
            fps.push(StringFingerprint {
                pattern: s.clone(),
                description: format!("Font name reference: {}", self.name),
                confidence: 0.90,
                version_specific: false,
            });
        }
        for s in &self.css_families {
            fps.push(StringFingerprint {
                pattern: s.clone(),
                description: format!("CSS font-family declaration for {}", self.name),
                confidence: 0.85,
                version_specific: false,
            });
        }
        for s in &self.file_patterns {
            fps.push(StringFingerprint {
                pattern: s.clone(),
                description: format!("Font file reference for {}", self.name),
                confidence: 0.90,
                version_specific: false,
            });
        }

        LibrarySignature {
            name: format!("[Font] {}", self.name),
            author: self.foundry,
            license: self.license,
            license_family: parse_family(&self.family),
            string_fingerprints: fps,
            structural_patterns: vec![],
            version_patterns: vec![],
            min_fingerprint_hits: 1,
            expected_copyright: String::new(),
            canonical_source: self.source,
            commercial_restriction: if self.requires_license {
                Some("Commercial font — requires purchased license for redistribution".into())
            } else {
                None
            },
        }
    }
}

impl CssEntry {
    fn into_signature(self) -> LibrarySignature {
        let mut fps = Vec::new();

        for s in &self.class_patterns {
            fps.push(StringFingerprint {
                pattern: s.clone(),
                description: format!("CSS class from {}", self.name),
                confidence: 0.55,
                version_specific: false,
            });
        }
        for s in &self.strings {
            fps.push(StringFingerprint {
                pattern: s.clone(),
                description: format!("{} identifier string", self.name),
                confidence: 0.85,
                version_specific: false,
            });
        }

        LibrarySignature {
            name: format!("[CSS] {}", self.name),
            author: self.author,
            license: self.license,
            license_family: parse_family(&self.family),
            string_fingerprints: fps,
            structural_patterns: vec![],
            version_patterns: vec![],
            min_fingerprint_hits: 3, // Need multiple class matches to avoid FPs
            expected_copyright: String::new(),
            canonical_source: self.source,
            commercial_restriction: None,
        }
    }
}

impl IconEntry {
    fn into_signature(self) -> LibrarySignature {
        let mut fps = Vec::new();

        for s in &self.class_patterns {
            fps.push(StringFingerprint {
                pattern: s.clone(),
                description: format!("Icon class from {}", self.name),
                confidence: 0.70,
                version_specific: false,
            });
        }
        for s in &self.strings {
            fps.push(StringFingerprint {
                pattern: s.clone(),
                description: format!("{} identifier", self.name),
                confidence: 0.90,
                version_specific: false,
            });
        }

        LibrarySignature {
            name: format!("[Icon] {}", self.name),
            author: self.author,
            license: self.license.clone(),
            license_family: parse_family(&self.family),
            string_fingerprints: fps,
            structural_patterns: vec![],
            version_patterns: vec![],
            min_fingerprint_hits: 2,
            expected_copyright: String::new(),
            canonical_source: self.source,
            commercial_restriction: self.pro_license.map(|l| {
                format!("Pro/premium icons require commercial license: {}", l)
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_library_signatures() {
        let sigs = signature_database();
        assert!(sigs.len() > 30, "Expected 30+ signatures, got {}", sigs.len());
    }

    #[test]
    fn test_all_signatures_have_fingerprints() {
        for sig in signature_database() {
            let total = sig.string_fingerprints.len() + sig.structural_patterns.len();
            assert!(
                total >= sig.min_fingerprint_hits,
                "Signature '{}' has {} fingerprints but requires {} hits",
                sig.name,
                total,
                sig.min_fingerprint_hits
            );
        }
    }

    #[test]
    fn test_external_signature_loading() {
        let custom_toml = r#"
        [[lib]]
        name = "TestLib"
        author = "Test Author"
        license = "MIT"
        family = "permissive"
        min_hits = 1
        copyright = "(c) Test"
        source = "https://example.com"
        strings = [
            { p = "TestLib.init", d = "TestLib init method", c = 0.99 },
        ]
        "#;

        let sigs = load_external_signatures(custom_toml);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "TestLib");
    }
}
