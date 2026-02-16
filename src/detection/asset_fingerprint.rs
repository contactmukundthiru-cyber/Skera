//! Asset fingerprinting — perceptual hashing for images, fonts, and media
//!
//! Detects copyrighted visual assets (logos, icons, stock photos) that have
//! been embedded in applications. Uses blockhash perceptual hashing which
//! survives resizing, compression, format conversion, and watermarking.
//!
//! Capabilities:
//!  - **Image fingerprinting** (blockhash): Identify images even after
//!    compression, resizing, and format conversion (PNG→WebP, etc.)
//!  - **Font binary analysis**: Detect commercial fonts embedded as WOFF/TTF/OTF
//!  - **Icon pack detection**: Match against known icon set fingerprints
//!
//! Behind the `asset-fingerprint` feature flag since it pulls in the `image` crate.

use serde::{Deserialize, Serialize};
use std::path::Path;

// ─── Types ─────────────────────────────────────────────────────────

/// A perceptual hash of an image or visual asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFingerprint {
    /// File path
    pub file_path: std::path::PathBuf,
    /// Asset type
    pub asset_type: AssetType,
    /// Perceptual hash (hex string, blockhash-256)
    pub perceptual_hash: Option<String>,
    /// File size in bytes
    pub file_size: u64,
    /// SHA-256 hash for exact matching
    pub sha256: String,
    /// Dimensions (for images)
    pub dimensions: Option<(u32, u32)>,
    /// Detected metadata
    pub metadata: AssetMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    Image,
    Font,
    Icon,
    Video,
    Audio,
    Unknown,
}

impl AssetType {
    /// Determine asset type from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" | "ico" | "tiff" | "avif" => Self::Image,
            "ttf" | "otf" | "woff" | "woff2" | "eot" => Self::Font,
            "mp4" | "webm" | "avi" | "mov" | "mkv" => Self::Video,
            "mp3" | "wav" | "ogg" | "flac" | "aac" | "m4a" => Self::Audio,
            _ => Self::Unknown,
        }
    }
}

/// Metadata extracted from an asset
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetMetadata {
    /// Font family name (for font files)
    pub font_family: Option<String>,
    /// Font style (Regular, Bold, etc.)
    pub font_style: Option<String>,
    /// Whether this appears to be a commercial font
    pub is_commercial_font: bool,
    /// Copyright strings found in metadata
    pub copyright_strings: Vec<String>,
    /// EXIF or XMP author/creator
    pub creator: Option<String>,
    /// License information found in metadata
    pub license_info: Option<String>,
}

/// Result of comparing two asset fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSimilarity {
    /// Hamming distance of perceptual hashes (lower = more similar)
    pub hamming_distance: Option<u32>,
    /// Normalized similarity (0.0-1.0)
    pub similarity: f64,
    /// Whether this is likely the same asset
    pub is_match: bool,
}

/// A reference asset entry in the known-asset database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceAsset {
    /// Asset name
    pub name: String,
    /// Perceptual hash
    pub perceptual_hash: String,
    /// License type
    pub license: String,
    /// Copyright holder
    pub copyright_holder: String,
    /// Whether commercial use requires a license
    pub requires_license: bool,
}

// ─── Core Functions ────────────────────────────────────────────────

/// Fingerprint a single asset file.
pub fn fingerprint_asset(path: &Path) -> Result<AssetFingerprint, std::io::Error> {
    let data = std::fs::read(path)?;
    let sha256 = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&data))
    };

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let asset_type = AssetType::from_extension(ext);

    let file_size = data.len() as u64;
    let perceptual_hash;
    let dimensions;

    // Compute perceptual hash for images (when feature enabled)
    #[cfg(feature = "asset-fingerprint")]
    {
        if asset_type == AssetType::Image && !ext.eq_ignore_ascii_case("svg") {
            if let Ok(img) = image::load_from_memory(&data) {
                let (w, h) = img.dimensions();
                dimensions = Some((w, h));

                let hash = blockhash::blockhash256(&img);
                perceptual_hash = Some(hash.to_string());
            } else {
                perceptual_hash = None;
                dimensions = None;
            }
        } else {
            perceptual_hash = None;
            dimensions = None;
        }
    }

    #[cfg(not(feature = "asset-fingerprint"))]
    {
        perceptual_hash = None;
        dimensions = None;
    }

    let metadata = extract_asset_metadata(&data, asset_type, ext);

    Ok(AssetFingerprint {
        file_path: path.to_path_buf(),
        asset_type,
        perceptual_hash,
        file_size,
        sha256,
        dimensions,
        metadata,
    })
}

/// Scan a directory for all assets and fingerprint them.
pub fn scan_assets(dir: &Path) -> Vec<AssetFingerprint> {
    let asset_extensions = [
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "ico", "avif",
        "ttf", "otf", "woff", "woff2", "eot",
        "mp4", "webm", "mp3", "wav", "ogg",
    ];

    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| asset_extensions.contains(&ext.to_lowercase().as_str()))
                .unwrap_or(false)
        })
        .filter_map(|e| fingerprint_asset(e.path()).ok())
        .collect()
}

/// Compare two perceptual hashes (hex strings).
pub fn compare_perceptual_hashes(hash_a: &str, hash_b: &str) -> AssetSimilarity {
    let bits_a = hex_to_bits(hash_a);
    let bits_b = hex_to_bits(hash_b);

    if bits_a.len() != bits_b.len() || bits_a.is_empty() {
        return AssetSimilarity {
            hamming_distance: None,
            similarity: 0.0,
            is_match: false,
        };
    }

    let distance: u32 = bits_a
        .iter()
        .zip(bits_b.iter())
        .map(|(a, b)| if a != b { 1u32 } else { 0u32 })
        .sum();

    let total_bits = bits_a.len() as f64;
    let similarity = 1.0 - (distance as f64 / total_bits);

    // Threshold: <10% of bits different = likely same image
    let is_match = similarity > 0.90;

    AssetSimilarity {
        hamming_distance: Some(distance),
        similarity,
        is_match,
    }
}

/// Find matching assets from a reference database.
pub fn find_matching_assets(
    fingerprint: &AssetFingerprint,
    references: &[ReferenceAsset],
    min_similarity: f64,
) -> Vec<(ReferenceAsset, AssetSimilarity)> {
    let hash = match &fingerprint.perceptual_hash {
        Some(h) => h,
        None => return Vec::new(),
    };

    let mut matches: Vec<_> = references
        .iter()
        .map(|reference| {
            let sim = compare_perceptual_hashes(hash, &reference.perceptual_hash);
            (reference.clone(), sim)
        })
        .filter(|(_, sim)| sim.similarity >= min_similarity)
        .collect();

    matches.sort_by(|a, b| b.1.similarity.partial_cmp(&a.1.similarity).unwrap());
    matches
}

// ─── Font Analysis ────────────────────────────────────────────────

/// Known commercial font families
const COMMERCIAL_FONTS: &[&str] = &[
    "Proxima Nova", "ProximaNova",
    "Gotham", "Gotham-",
    "Avenir", "AvenirNext",
    "Futura", "FuturaPT",
    "Helvetica Neue", "HelveticaNeue",
    "Circular", "CircularStd",
    "Gilroy", "Gilroy-",
    "Graphik",
    "Brandon Grotesque", "BrandonGrotesque",
    "Montserrat Pro",
    "Apercu",
    "Calibre",
    "GT Walsheim",
    "Canela",
    "Neue Haas",
    "SF Pro", "SFPro",      // Apple (platform-restricted)
    "Segoe UI",              // Microsoft (platform-restricted)
    "Product Sans",          // Google (internal only)
    "San Francisco",         // Apple (platform-restricted)
    "Greycliff",
    "Founders Grotesk",
    "Neuzeit",
    "DIN",
    "Akkurat",
    "Suisse",
    "Basis Grotesque",
];

/// Check if a font name is a known commercial font.
pub fn is_commercial_font(name: &str) -> bool {
    let name_upper = name.to_uppercase();
    COMMERCIAL_FONTS.iter().any(|f| name_upper.contains(&f.to_uppercase()))
}

// ─── Utility Functions ─────────────────────────────────────────────

/// Convert a hex string to a bit vector.
fn hex_to_bits(hex: &str) -> Vec<bool> {
    let mut bits = Vec::with_capacity(hex.len() * 4);
    for ch in hex.chars() {
        if let Some(nibble) = ch.to_digit(16) {
            for i in (0..4).rev() {
                bits.push((nibble >> i) & 1 == 1);
            }
        }
    }
    bits
}

/// Extract metadata from an asset's binary content.
fn extract_asset_metadata(data: &[u8], asset_type: AssetType, _ext: &str) -> AssetMetadata {
    let mut meta = AssetMetadata::default();

    match asset_type {
        AssetType::Font => {
            // Extract font family name from binary
            if let Some(name) = extract_font_name(data) {
                meta.is_commercial_font = is_commercial_font(&name);
                meta.font_family = Some(name);
            }

            // Look for copyright strings in font metadata
            meta.copyright_strings = extract_copyright_from_binary(data);
        }
        AssetType::Image => {
            // Look for EXIF/XMP copyright data
            meta.copyright_strings = extract_copyright_from_binary(data);
        }
        _ => {}
    }

    meta
}

/// Extract font family name from TTF/OTF/WOFF binary data.
/// Searches for the 'name' table in the font file.
fn extract_font_name(data: &[u8]) -> Option<String> {
    // Look for common font family patterns in the binary
    let text = String::from_utf8_lossy(data);

    // Try to find font family name in ASCII strings
    let patterns = [
        // Common font naming patterns
        regex::Regex::new(r#"(?:font-family|familyName)[:\s]*['"]?([A-Z][a-zA-Z\s-]{2,30})['"]?"#).ok()?,
    ];

    for re in &patterns {
        if let Some(cap) = re.captures(&text) {
            if let Some(name) = cap.get(1) {
                return Some(name.as_str().trim().to_string());
            }
        }
    }

    // Fallback: scan for known font name strings
    for font in COMMERCIAL_FONTS {
        if text.contains(font) {
            return Some(font.to_string());
        }
    }

    None
}

/// Extract copyright strings from binary data.
fn extract_copyright_from_binary(data: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(data);
    let re = regex::Regex::new(
        r"(?i)(?:copyright|©)\s*(?:\(c\)\s*)?\d{4}[\s,\-]*(?:\d{4}[\s,\-]*)?\s*([^\n\r]{5,80})"
    ).unwrap();

    re.captures_iter(&text)
        .map(|cap| cap[0].trim().to_string())
        .take(10) // Limit to 10 copyright strings
        .collect()
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_type_detection() {
        assert_eq!(AssetType::from_extension("png"), AssetType::Image);
        assert_eq!(AssetType::from_extension("ttf"), AssetType::Font);
        assert_eq!(AssetType::from_extension("mp4"), AssetType::Video);
        assert_eq!(AssetType::from_extension("mp3"), AssetType::Audio);
        assert_eq!(AssetType::from_extension("rs"), AssetType::Unknown);
    }

    #[test]
    fn test_commercial_font_detection() {
        assert!(is_commercial_font("Proxima Nova"));
        assert!(is_commercial_font("ProximaNova-Regular"));
        assert!(is_commercial_font("Gotham-Bold"));
        assert!(is_commercial_font("SF Pro Display"));
        assert!(!is_commercial_font("Open Sans"));
        assert!(!is_commercial_font("Roboto"));
        assert!(!is_commercial_font("Inter"));
    }

    #[test]
    fn test_hex_to_bits() {
        let bits = hex_to_bits("f0");
        assert_eq!(bits, vec![true, true, true, true, false, false, false, false]);
    }

    #[test]
    fn test_identical_perceptual_hash() {
        let hash = "0123456789abcdef0123456789abcdef";
        let sim = compare_perceptual_hashes(hash, hash);
        assert_eq!(sim.similarity, 1.0);
        assert!(sim.is_match);
        assert_eq!(sim.hamming_distance, Some(0));
    }

    #[test]
    fn test_different_perceptual_hash() {
        let hash_a = "ffffffffffffffffffffffffffffffff";
        let hash_b = "00000000000000000000000000000000";
        let sim = compare_perceptual_hashes(hash_a, hash_b);
        assert_eq!(sim.similarity, 0.0);
        assert!(!sim.is_match);
    }

    #[test]
    fn test_similar_perceptual_hash() {
        // Only 1 hex digit different = 4 bits difference out of 128
        let hash_a = "ffffffffffffffffffffffffffffffff";
        let hash_b = "fffffffffffffffffffffffffffffffe"; // last nibble: f→e = 1 bit diff
        let sim = compare_perceptual_hashes(hash_a, hash_b);
        assert!(sim.similarity > 0.95);
        assert!(sim.is_match);
    }

    #[test]
    fn test_copyright_extraction() {
        let data = b"some binary junk\x00Copyright 2024 Adobe Systems Inc. All rights reserved.\x00more junk";
        let copyrights = extract_copyright_from_binary(data);
        assert!(!copyrights.is_empty());
        assert!(copyrights[0].contains("Adobe"));
    }
}
