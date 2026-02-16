//! Evidence collection system
//!
//! Produces litigation-ready evidence bundles with:
//! - SHA-256 content hashing for tamper detection
//! - Timestamped evidence chains
//! - Exact file paths, line numbers, and byte offsets
//! - Content excerpts with surrounding context

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// A single piece of evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Human-readable description of what this evidence shows
    pub description: String,
    /// File path where evidence was found
    pub file_path: Option<PathBuf>,
    /// Line number (1-indexed)
    pub line_number: Option<usize>,
    /// Byte offset in file
    pub byte_offset: Option<u64>,
    /// SHA-256 hash of the evidence content
    pub sha256: Option<String>,
    /// Text excerpt showing the violation
    pub content_excerpt: Option<String>,
    /// When this evidence was collected
    pub timestamp: DateTime<Utc>,
}

impl EvidenceItem {
    /// Create a new evidence item from a file excerpt
    pub fn from_file(
        path: &Path,
        line: usize,
        excerpt: &str,
        description: impl Into<String>,
    ) -> Self {
        let hash = hex::encode(Sha256::digest(excerpt.as_bytes()));
        Self {
            description: description.into(),
            file_path: Some(path.to_path_buf()),
            line_number: Some(line),
            byte_offset: None,
            sha256: Some(hash),
            content_excerpt: Some(excerpt.to_string()),
            timestamp: Utc::now(),
        }
    }

    /// Create evidence from a binary offset
    pub fn from_binary(
        path: &Path,
        offset: u64,
        data: &[u8],
        description: impl Into<String>,
    ) -> Self {
        let hash = hex::encode(Sha256::digest(data));
        Self {
            description: description.into(),
            file_path: Some(path.to_path_buf()),
            line_number: None,
            byte_offset: Some(offset),
            sha256: Some(hash),
            content_excerpt: Some(String::from_utf8_lossy(data).to_string()),
            timestamp: Utc::now(),
        }
    }
}

/// A chain of evidence items linked together
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    /// Unique ID for this chain
    pub id: String,
    /// What this chain proves
    pub thesis: String,
    /// Ordered evidence items
    pub items: Vec<EvidenceItem>,
    /// SHA-256 of the entire chain (for tamper detection)
    pub chain_hash: String,
    /// When the chain was finalized
    pub finalized_at: DateTime<Utc>,
}

impl EvidenceChain {
    /// Start building a new evidence chain
    pub fn builder(thesis: impl Into<String>) -> EvidenceChainBuilder {
        EvidenceChainBuilder {
            thesis: thesis.into(),
            items: Vec::new(),
        }
    }
}

impl std::fmt::Display for EvidenceChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EvidenceChain[{}]: \"{}\" ({} items, hash={}...)",
            &self.id[..8.min(self.id.len())],
            self.thesis,
            self.items.len(),
            &self.chain_hash[..12.min(self.chain_hash.len())]
        )
    }
}

/// Builder for evidence chains
pub struct EvidenceChainBuilder {
    thesis: String,
    items: Vec<EvidenceItem>,
}

impl EvidenceChainBuilder {
    pub fn add(mut self, item: EvidenceItem) -> Self {
        self.items.push(item);
        self
    }

    pub fn add_all(mut self, items: Vec<EvidenceItem>) -> Self {
        self.items.extend(items);
        self
    }

    /// Finalize the chain with a tamper-proof hash
    pub fn finalize(self) -> EvidenceChain {
        let now = Utc::now();
        let id = Uuid::new_v4().to_string();

        // Compute chain hash over all items
        let mut hasher = Sha256::new();
        hasher.update(self.thesis.as_bytes());
        hasher.update(id.as_bytes());
        for item in &self.items {
            if let Some(ref hash) = item.sha256 {
                hasher.update(hash.as_bytes());
            }
            hasher.update(item.description.as_bytes());
            hasher.update(item.timestamp.to_rfc3339().as_bytes());
        }
        hasher.update(now.to_rfc3339().as_bytes());

        EvidenceChain {
            id,
            thesis: self.thesis,
            items: self.items,
            chain_hash: hex::encode(hasher.finalize()),
            finalized_at: now,
        }
    }
}

/// A complete evidence bundle for a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Unique bundle ID
    pub id: String,
    /// Target that was scanned
    pub target: String,
    /// All evidence chains
    pub chains: Vec<EvidenceChain>,
    /// Overall bundle hash
    pub bundle_hash: String,
    /// When the bundle was created
    pub created_at: DateTime<Utc>,
    /// Scanner version
    pub scanner_version: String,
}

impl EvidenceBundle {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            target: target.into(),
            chains: Vec::new(),
            bundle_hash: String::new(),
            created_at: Utc::now(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn add_chain(&mut self, chain: EvidenceChain) {
        self.chains.push(chain);
    }

    /// Finalize the bundle with a master hash
    pub fn finalize(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.target.as_bytes());
        for chain in &self.chains {
            hasher.update(chain.chain_hash.as_bytes());
        }
        self.bundle_hash = hex::encode(hasher.finalize());
    }

    /// Total evidence items across all chains
    pub fn total_items(&self) -> usize {
        self.chains.iter().map(|c| c.items.len()).sum()
    }

    /// Whether the bundle has any evidence
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    /// Verify the integrity of the bundle by re-computing the master hash
    pub fn verify_integrity(&self) -> bool {
        if self.bundle_hash.is_empty() {
            return false;
        }
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.target.as_bytes());
        for chain in &self.chains {
            hasher.update(chain.chain_hash.as_bytes());
        }
        let computed = hex::encode(hasher.finalize());
        computed == self.bundle_hash
    }
}

impl std::fmt::Display for EvidenceBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EvidenceBundle[{}]: target=\"{}\", {} chains, {} items, integrity={}",
            &self.id[..8.min(self.id.len())],
            self.target,
            self.chains.len(),
            self.total_items(),
            if self.verify_integrity() { "OK" } else { "UNVERIFIED" }
        )
    }
}
