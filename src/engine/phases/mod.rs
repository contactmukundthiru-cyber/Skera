//! Scan phases — each detection module as an independent, parallelizable phase

pub mod source_scan;
pub mod header_analysis;
pub mod dependency;
pub mod fingerprinting;
pub mod js_forensics;
pub mod cross_language;
pub mod media_scan;
pub mod asset_scan;
pub mod yara_scan;
pub mod supply_chain;
pub mod web_assets;
pub mod creative_commons;
pub mod data_rights;
pub mod license_forensics;
pub mod binary_analysis;
pub mod ai_verification;
pub mod scancode_phase;
pub mod deobfuscation;

use super::pipeline::ScanPhase;

/// Build all detection phases in the correct order
pub fn build_detection_phases() -> Vec<Box<dyn ScanPhase>> {
    vec![
        Box::new(header_analysis::HeaderAnalysisPhase::new()),
        Box::new(dependency::DependencyPhase::new()),
        Box::new(fingerprinting::FingerprintingPhase::new()),
        Box::new(js_forensics::JsForensicsPhase::new()),
        Box::new(cross_language::CrossLanguagePhase::new()),
        Box::new(media_scan::MediaScanPhase::new()),
        Box::new(asset_scan::AssetScanPhase::new()),
        Box::new(yara_scan::YaraScanPhase::new()),
        Box::new(supply_chain::SupplyChainPhase::new()),
        Box::new(web_assets::WebAssetsPhase::new()),
        Box::new(creative_commons::CreativeCommonsPhase::new()),
        Box::new(data_rights::DataRightsPhase::new()),
        Box::new(license_forensics::LicenseForensicsPhase::new()),
        Box::new(binary_analysis::BinaryAnalysisPhase::new()),
        Box::new(deobfuscation::DeobfuscationPhase::new()),
        Box::new(scancode_phase::ScanCodePhase::new()),
    ]
}
