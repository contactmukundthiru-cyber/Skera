//! SBOM Generator — CycloneDX and SPDX output for enterprise compliance
//!
//! Generates Software Bill of Materials in industry-standard formats.
//! Required by US Executive Order 14028 for government suppliers.

use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;

use super::dependency_resolver::{DependencyTree, Ecosystem};

// ─── SBOM Types ────────────────────────────────────────────────────

/// SBOM output format
#[derive(Debug, Clone, Copy)]
pub enum SbomFormat {
    /// CycloneDX JSON (v1.5)
    CycloneDxJson,
    /// CycloneDX XML
    CycloneDxXml,
    /// SPDX JSON (v2.3)
    SpdxJson,
    /// SPDX Tag-Value
    SpdxTagValue,
}

/// Generated SBOM document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDocument {
    pub format: String,
    pub content: String,
    pub component_count: usize,
    pub generated_at: String,
    pub tool_name: String,
    pub tool_version: String,
}

// ─── Generator ─────────────────────────────────────────────────────

pub struct SbomGenerator;

impl SbomGenerator {
    /// Generate an SBOM from resolved dependency trees
    pub fn generate(trees: &[DependencyTree], format: SbomFormat) -> SbomDocument {
        match format {
            SbomFormat::CycloneDxJson => Self::generate_cyclonedx_json(trees),
            SbomFormat::CycloneDxXml => Self::generate_cyclonedx_xml(trees),
            SbomFormat::SpdxJson => Self::generate_spdx_json(trees),
            SbomFormat::SpdxTagValue => Self::generate_spdx_tag_value(trees),
        }
    }

    // ── CycloneDX JSON ──────────────────────────────────────────────

    fn generate_cyclonedx_json(trees: &[DependencyTree]) -> SbomDocument {
        let serial = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();

        let mut components = Vec::new();

        for tree in trees {
            for dep in tree.dependencies.values() {
                let purl = make_purl(&dep.name, &dep.version, dep.ecosystem);
                let license_id = dep.declared_license.as_ref()
                    .map(|l| format!("{:?}", l))
                    .or(dep.license_raw.clone())
                    .unwrap_or_default();

                let mut component = serde_json::json!({
                    "type": "library",
                    "name": dep.name,
                    "version": dep.version,
                    "purl": purl,
                    "scope": if dep.depth <= 1 { "required" } else { "optional" },
                });

                if !license_id.is_empty() {
                    component["licenses"] = serde_json::json!([{
                        "license": {
                            "id": license_id
                        }
                    }]);
                }

                components.push(component);
            }
        }

        let component_count = components.len();

        let root_name = trees.first()
            .map(|t| t.root_name.as_str())
            .unwrap_or("unknown");

        let document = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": format!("urn:uuid:{}", serial),
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [{
                    "vendor": "Santh",
                    "name": "skera",
                    "version": env!("CARGO_PKG_VERSION")
                }],
                "component": {
                    "type": "application",
                    "name": root_name,
                    "version": trees.first().map(|t| t.root_version.as_str()).unwrap_or("0.0.0")
                }
            },
            "components": components
        });

        SbomDocument {
            format: "CycloneDX/JSON v1.5".to_string(),
            content: serde_json::to_string_pretty(&document).unwrap_or_default(),
            component_count,
            generated_at: timestamp,
            tool_name: "skera".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    // ── CycloneDX XML ───────────────────────────────────────────────

    fn generate_cyclonedx_xml(trees: &[DependencyTree]) -> SbomDocument {
        let serial = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        let mut xml = String::new();

        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.5\" serialNumber=\"urn:uuid:{}\" version=\"1\">\n",
            serial
        ));
        xml.push_str("  <metadata>\n");
        xml.push_str(&format!("    <timestamp>{}</timestamp>\n", timestamp));
        xml.push_str("    <tools>\n");
        xml.push_str("      <tool>\n");
        xml.push_str("        <vendor>Santh</vendor>\n");
        xml.push_str("        <name>skera</name>\n");
        xml.push_str(&format!("        <version>{}</version>\n", env!("CARGO_PKG_VERSION")));
        xml.push_str("      </tool>\n");
        xml.push_str("    </tools>\n");
        xml.push_str("  </metadata>\n");
        xml.push_str("  <components>\n");

        let mut count = 0;
        for tree in trees {
            for dep in tree.dependencies.values() {
                let purl = make_purl(&dep.name, &dep.version, dep.ecosystem);
                xml.push_str("    <component type=\"library\">\n");
                xml.push_str(&format!("      <name>{}</name>\n", xml_escape(&dep.name)));
                xml.push_str(&format!("      <version>{}</version>\n", xml_escape(&dep.version)));
                xml.push_str(&format!("      <purl>{}</purl>\n", xml_escape(&purl)));

                if let Some(ref lic) = dep.license_raw {
                    xml.push_str("      <licenses>\n");
                    xml.push_str("        <license>\n");
                    xml.push_str(&format!("          <id>{}</id>\n", xml_escape(lic)));
                    xml.push_str("        </license>\n");
                    xml.push_str("      </licenses>\n");
                }

                xml.push_str("    </component>\n");
                count += 1;
            }
        }

        xml.push_str("  </components>\n");
        xml.push_str("</bom>\n");

        SbomDocument {
            format: "CycloneDX/XML v1.5".to_string(),
            content: xml,
            component_count: count,
            generated_at: timestamp,
            tool_name: "skera".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    // ── SPDX JSON ───────────────────────────────────────────────────

    fn generate_spdx_json(trees: &[DependencyTree]) -> SbomDocument {
        let doc_uuid = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();

        let mut packages = Vec::new();
        let mut relationships = Vec::new();

        let root_spdx_id = "SPDXRef-DOCUMENT";

        for tree in trees {
            let root_pkg_id = format!("SPDXRef-Package-{}", sanitize_spdx_id(&tree.root_name));

            packages.push(serde_json::json!({
                "SPDXID": root_pkg_id,
                "name": tree.root_name,
                "versionInfo": tree.root_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "licenseConcluded": tree.root_license.as_ref()
                    .map(|l| format!("{:?}", l))
                    .unwrap_or_else(|| "NOASSERTION".to_string()),
                "licenseDeclared": tree.root_license.as_ref()
                    .map(|l| format!("{:?}", l))
                    .unwrap_or_else(|| "NOASSERTION".to_string()),
                "copyrightText": "NOASSERTION"
            }));

            relationships.push(serde_json::json!({
                "spdxElementId": root_spdx_id,
                "relatedSpdxElement": root_pkg_id,
                "relationshipType": "DESCRIBES"
            }));

            for dep in tree.dependencies.values() {
                let dep_id = format!("SPDXRef-Package-{}", sanitize_spdx_id(&dep.name));
                let purl = make_purl(&dep.name, &dep.version, dep.ecosystem);

                packages.push(serde_json::json!({
                    "SPDXID": dep_id,
                    "name": dep.name,
                    "versionInfo": dep.version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "licenseConcluded": dep.declared_license.as_ref()
                        .map(|l| format!("{:?}", l))
                        .or(dep.license_raw.clone())
                        .unwrap_or_else(|| "NOASSERTION".to_string()),
                    "licenseDeclared": dep.license_raw.as_deref()
                        .unwrap_or("NOASSERTION"),
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [{
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl
                    }]
                }));

                relationships.push(serde_json::json!({
                    "spdxElementId": root_pkg_id,
                    "relatedSpdxElement": dep_id,
                    "relationshipType": "DEPENDS_ON"
                }));
            }
        }

        let component_count = packages.len();

        let document = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": root_spdx_id,
            "name": format!("skera-sbom-{}", doc_uuid),
            "documentNamespace": format!("https://spdx.org/spdxdocs/skera-{}", doc_uuid),
            "creationInfo": {
                "created": timestamp,
                "creators": [
                    format!("Tool: skera-{}", env!("CARGO_PKG_VERSION"))
                ],
                "licenseListVersion": "3.22"
            },
            "packages": packages,
            "relationships": relationships
        });

        SbomDocument {
            format: "SPDX/JSON v2.3".to_string(),
            content: serde_json::to_string_pretty(&document).unwrap_or_default(),
            component_count,
            generated_at: timestamp,
            tool_name: "skera".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    // ── SPDX Tag-Value ──────────────────────────────────────────────

    fn generate_spdx_tag_value(trees: &[DependencyTree]) -> SbomDocument {
        let doc_uuid = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        let mut output = String::new();

        output.push_str("SPDXVersion: SPDX-2.3\n");
        output.push_str("DataLicense: CC0-1.0\n");
        output.push_str("SPDXID: SPDXRef-DOCUMENT\n");
        output.push_str(&format!("DocumentName: skera-sbom-{}\n", doc_uuid));
        output.push_str(&format!("DocumentNamespace: https://spdx.org/spdxdocs/skera-{}\n", doc_uuid));
        output.push_str(&format!("Creator: Tool: skera-{}\n", env!("CARGO_PKG_VERSION")));
        output.push_str(&format!("Created: {}\n", timestamp));
        output.push_str("LicenseListVersion: 3.22\n\n");

        let mut count = 0;
        for tree in trees {
            for dep in tree.dependencies.values() {
                let dep_id = sanitize_spdx_id(&dep.name);
                output.push_str(&format!("##### Package: {}\n\n", dep.name));
                output.push_str(&format!("PackageName: {}\n", dep.name));
                output.push_str(&format!("SPDXID: SPDXRef-Package-{}\n", dep_id));
                output.push_str(&format!("PackageVersion: {}\n", dep.version));
                output.push_str("PackageDownloadLocation: NOASSERTION\n");
                output.push_str("FilesAnalyzed: false\n");
                output.push_str(&format!(
                    "PackageLicenseConcluded: {}\n",
                    dep.license_raw.as_deref().unwrap_or("NOASSERTION")
                ));
                output.push_str(&format!(
                    "PackageLicenseDeclared: {}\n",
                    dep.license_raw.as_deref().unwrap_or("NOASSERTION")
                ));
                output.push_str("PackageCopyrightText: NOASSERTION\n\n");
                count += 1;
            }
        }

        SbomDocument {
            format: "SPDX/Tag-Value v2.3".to_string(),
            content: output,
            component_count: count,
            generated_at: timestamp,
            tool_name: "skera".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

// ─── Helpers ───────────────────────────────────────────────────────

fn make_purl(name: &str, version: &str, ecosystem: Ecosystem) -> String {
    let (pkg_type, ns, pkg_name) = match ecosystem {
        Ecosystem::Npm => {
            if name.starts_with('@') {
                let parts: Vec<&str> = name.splitn(2, '/').collect();
                ("npm", Some(parts[0].to_string()), parts.get(1).unwrap_or(&name).to_string())
            } else {
                ("npm", None, name.to_string())
            }
        }
        Ecosystem::Cargo => ("cargo", None, name.to_string()),
        Ecosystem::Go => {
            let parts: Vec<&str> = name.rsplitn(2, '/').collect();
            if parts.len() > 1 {
                ("golang", Some(parts[1].to_string()), parts[0].to_string())
            } else {
                ("golang", None, name.to_string())
            }
        }
        Ecosystem::PyPi => ("pypi", None, name.to_string()),
        Ecosystem::Maven | Ecosystem::Gradle => {
            let parts: Vec<&str> = name.splitn(2, ':').collect();
            if parts.len() == 2 {
                ("maven", Some(parts[0].to_string()), parts[1].to_string())
            } else {
                ("maven", None, name.to_string())
            }
        }
        Ecosystem::Ruby => ("gem", None, name.to_string()),
        Ecosystem::Composer => {
            let parts: Vec<&str> = name.splitn(2, '/').collect();
            if parts.len() == 2 {
                ("composer", Some(parts[0].to_string()), parts[1].to_string())
            } else {
                ("composer", None, name.to_string())
            }
        }
        Ecosystem::DotNet => ("nuget", None, name.to_string()),
        Ecosystem::Unknown => ("generic", None, name.to_string()),
    };

    if let Some(namespace) = ns {
        format!("pkg:{}/{}/{}@{}", pkg_type, namespace, pkg_name, version)
    } else {
        format!("pkg:{}/{}@{}", pkg_type, pkg_name, version)
    }
}

fn sanitize_spdx_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '-' })
        .collect()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_purl_npm() {
        assert_eq!(make_purl("lodash", "4.17.21", Ecosystem::Npm), "pkg:npm/lodash@4.17.21");
        assert_eq!(make_purl("@babel/core", "7.23.0", Ecosystem::Npm), "pkg:npm/@babel/core@7.23.0");
    }

    #[test]
    fn test_make_purl_cargo() {
        assert_eq!(make_purl("serde", "1.0.197", Ecosystem::Cargo), "pkg:cargo/serde@1.0.197");
    }

    #[test]
    fn test_make_purl_maven() {
        assert_eq!(
            make_purl("org.apache:commons-lang3", "3.14", Ecosystem::Maven),
            "pkg:maven/org.apache/commons-lang3@3.14"
        );
    }

    #[test]
    fn test_sanitize_spdx_id() {
        assert_eq!(sanitize_spdx_id("@babel/core"), "-babel-core");
        assert_eq!(sanitize_spdx_id("lodash"), "lodash");
    }
}
