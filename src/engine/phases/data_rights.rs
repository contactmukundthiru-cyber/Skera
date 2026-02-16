//! Phase 3f: Data rights scanning — PII, secrets, data license compliance

use crate::detection::data_rights;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct DataRightsPhase;

impl DataRightsPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for DataRightsPhase {
    fn name(&self) -> &str {
        "Data Rights Scanning"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let report = data_rights::DataRightsScanner::scan(&ctx.source_dir);
        let mut violations = Vec::new();

        // PII findings (aggregated at report level)
        for pii in &report.pii_findings {
            violations.push(Violation {
                violation_type: ViolationType::PiiExposure,
                severity: Severity::High,
                confidence: pii.confidence,
                description: format!(
                    "PII ({:?}) found in {}: {}",
                    pii.pii_type, pii.file_path.display(), pii.sample
                ),
                files: vec![pii.file_path.clone()],
                licenses: vec![],
                obligations_violated: vec![],
                evidence: vec![EvidenceItem::from_file(
                    &pii.file_path,
                    pii.line_number,
                    &pii.sample,
                    format!("PII {:?} detected with {:.0}% confidence", pii.pii_type, pii.confidence * 100.0),
                )],
                claimed_license: None,
                actual_license: None,
            });
        }

        // Exposed secrets
        for secret in &report.exposed_secrets {
            violations.push(Violation {
                violation_type: ViolationType::ExposedSecrets,
                severity: Severity::Critical,
                confidence: 0.90,
                description: format!(
                    "Secret ({:?}) found in {} line {}",
                    secret.secret_type, secret.file_path.display(), secret.line_number
                ),
                files: vec![secret.file_path.clone()],
                licenses: vec![],
                obligations_violated: vec![],
                evidence: vec![EvidenceItem::from_file(
                    &secret.file_path,
                    secret.line_number,
                    &secret.redacted_value,
                    format!("Exposed {:?} secret in source", secret.secret_type),
                )],
                claimed_license: None,
                actual_license: None,
            });
        }

        // Geodata
        for geo in &report.geodata_usage {
            violations.push(Violation {
                violation_type: ViolationType::UnlicensedGeodata,
                severity: Severity::Medium,
                confidence: 0.8,
                description: format!(
                    "Geodata from {:?} found — verify attribution compliance",
                    geo.provider
                ),
                files: vec![geo.file_path.clone()],
                licenses: vec![],
                obligations_violated: vec![crate::license::LicenseObligation::Attribution],
                evidence: vec![EvidenceItem::from_file(
                    &geo.file_path,
                    0,
                    &format!("Geodata provider: {:?}", geo.provider),
                    "Geodata attribution compliance check required",
                )],
                claimed_license: None,
                actual_license: None,
            });
        }

        // ML datasets
        for ds in &report.ml_datasets {
            violations.push(Violation {
                violation_type: ViolationType::MlDatasetViolation,
                severity: Severity::High,
                confidence: 0.75,
                description: format!(
                    "ML dataset '{}' reference found — verify license compliance",
                    ds.dataset_name
                ),
                files: vec![ds.file_path.clone()],
                licenses: vec![],
                obligations_violated: vec![],
                evidence: vec![EvidenceItem::from_file(
                    &ds.file_path,
                    0,
                    &format!("Dataset: {}", ds.dataset_name),
                    "ML dataset license compliance verification needed",
                )],
                claimed_license: None,
                actual_license: None,
            });
        }

        Ok(PhaseOutput::with_violations(violations, report.data_files.len()))
    }
}
