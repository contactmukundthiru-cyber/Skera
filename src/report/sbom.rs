//! SBOM generation — CycloneDX and SPDX formats
//!
//! Generates Software Bill of Materials from scan results for supply chain
//! compliance (Executive Order 14028, EU Cyber Resilience Act).

use crate::engine::ScanReport;
use crate::SkeraResult;
use serde_json::json;

/// Render CycloneDX 1.5 SBOM
pub fn render_cyclonedx(report: &ScanReport) -> SkeraResult<String> {
    let timestamp = chrono::Utc::now().to_rfc3339();

    let components: Vec<serde_json::Value> = report
        .detection_result
        .dependency_licenses
        .iter()
        .map(|(name, license)| {
            json!({
                "type": "library",
                "name": name,
                "licenses": [{
                    "license": {
                        "id": license.to_string()
                    }
                }],
                "purl": format!("pkg:generic/{}", name),
            })
        })
        .collect();

    let sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "metadata": {
            "timestamp": timestamp,
            "tools": [{
                "vendor": "Santh",
                "name": "Skera",
                "version": report.scanner_version
            }],
            "component": {
                "type": "application",
                "name": &report.target,
                "licenses": report.project_license.as_ref().map(|l| {
                    json!([{
                        "license": {
                            "id": l.to_string()
                        }
                    }])
                }).unwrap_or_else(|| json!([]))
            }
        },
        "components": components,
        "dependencies": []
    });

    serde_json::to_string_pretty(&sbom).map_err(crate::SkeraError::SerdeError)
}

/// Render SPDX 2.3 SBOM
pub fn render_spdx(report: &ScanReport) -> SkeraResult<String> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let doc_namespace = format!(
        "https://spdx.org/spdxdocs/skera-scan-{}",
        uuid::Uuid::new_v4()
    );

    let packages: Vec<serde_json::Value> = report
        .detection_result
        .dependency_licenses
        .iter()
        .enumerate()
        .map(|(i, (name, license))| {
            json!({
                "SPDXID": format!("SPDXRef-Package-{}", i),
                "name": name,
                "versionInfo": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "licenseConcluded": license.to_string(),
                "licenseDeclared": license.to_string(),
                "copyrightText": "NOASSERTION"
            })
        })
        .collect();

    let spdx = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("skera-scan-{}", &report.target),
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": [
                format!("Tool: Skera {}", report.scanner_version),
                "Organization: Santh"
            ],
            "licenseListVersion": "3.22"
        },
        "packages": packages,
        "relationships": []
    });

    serde_json::to_string_pretty(&spdx).map_err(crate::SkeraError::SerdeError)
}
