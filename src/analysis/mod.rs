//! Analysis engines — source scanning, binary inspection, dependency resolution

pub mod source_scanner;
pub mod binary_inspector;
pub mod dependency_graph;
pub mod git_forensics;
pub mod dependency_resolver;
pub mod copyrightability;
pub mod sbom;

pub use source_scanner::SourceScan;
pub use binary_inspector::BinaryInspection;
pub use dependency_graph::DependencyGraph;
