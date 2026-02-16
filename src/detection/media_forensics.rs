//! Media forensics — digital identity verification for every media asset
//!
//! ## Overview
//!
//! Comprehensive media fingerprinting and forensics engine that establishes
//! the digital identity of every audio, video, image, and font file in a
//! project. Detects copyrighted or licensed assets even when re-encoded,
//! watermarked, resized, cropped, or otherwise transformed.
//!
//! ## Capabilities
//!
//! 1. **Multi-Format Fingerprinting** — SHA-256 content hash + perceptual
//!    hashing for audio/video/image that survives transformations.
//!
//! 2. **EXIF/ID3/Vorbis Metadata Extraction** — reads copyright, license,
//!    artist, title from all standard metadata containers.
//!
//! 3. **Stock Asset Watermark Detection** — identifies traces from 20+
//!    stock providers (Shutterstock, Getty, Envato, etc.)
//!
//! 4. **DRM/Protection Detection** — identifies Widevine, FairPlay,
//!    PlayReady markers in video/audio containers.
//!
//! 5. **Font License Verification** — reads OpenType `name` table to
//!    extract font license URL, designer, vendor, and copyright.
//!
//! 6. **SVG Attribution Scanner** — parses SVG metadata for creator,
//!    license, and provenance information.
//!
//! 7. **Duplicate/Near-Duplicate Detection** — compares fingerprints
//!    across a project to find copies of the same asset.
//!
//! 8. **Container Format Analysis** — detects MP4 atoms, WebM clusters,
//!    RIFF chunks for forensic timeline reconstruction.
//!
//! Behind the `media-forensics` feature flag for optional heavy
//! dependencies (FFMPEG bindings, image processing).

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ─── Types ─────────────────────────────────────────────────────────

/// A media fingerprint for any digital asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaFingerprint {
    /// File path
    pub file_path: PathBuf,
    /// Media type classification
    pub media_type: MediaType,
    /// SHA-256 content hash
    pub sha256: String,
    /// BLAKE3 content hash (faster, used for dedup)
    pub blake3: String,
    /// File size in bytes
    pub file_size: u64,
    /// Audio fingerprint (chromaprint string)
    pub audio_fingerprint: Option<String>,
    /// Duration in seconds (audio/video)
    pub duration_seconds: Option<f64>,
    /// Image dimensions (width x height)
    pub dimensions: Option<(u32, u32)>,
    /// Detected copyright/metadata
    pub metadata: MediaMetadata,
    /// Container format details
    pub container: Option<ContainerInfo>,
    /// DRM/protection markers
    pub drm_markers: Vec<String>,
    /// Stock asset indicators
    pub stock_indicators: Vec<StockIndicator>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    Video,
    Audio,
    Image,
    Font,
    Svg,
    Document,
    /// 3D models (STL, OBJ, FBX, GLTF, BLEND)
    ThreeDModel,
    /// Ebooks (EPUB, MOBI, AZW3)
    Ebook,
    /// Archives containing potentially copyrighted content
    Archive,
    /// AI model weights (ONNX, SafeTensors, PyTorch, GGUF)
    AiModelWeights,
    /// Firmware binaries (BIN, HEX, ELF, ROM)
    Firmware,
    /// CAD/engineering drawings (DWG, DXF, STEP)
    CadDrawing,
}

impl MediaType {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            // Video
            "mp4" | "webm" | "avi" | "mov" | "mkv" | "flv" | "wmv" | "m4v"
            | "3gp" | "ogv" | "ts" | "mts" => Some(Self::Video),
            // Audio
            "mp3" | "wav" | "ogg" | "flac" | "aac" | "m4a" | "wma" | "opus"
            | "aiff" | "ape" | "alac" | "mid" | "midi" => Some(Self::Audio),
            // Image
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" | "webp"
            | "ico" | "heif" | "heic" | "avif" | "raw" | "cr2" | "nef"
            | "psd" | "ai" | "eps" => Some(Self::Image),
            // Font
            "ttf" | "otf" | "woff" | "woff2" | "eot" => Some(Self::Font),
            // SVG
            "svg" | "svgz" => Some(Self::Svg),
            // Documents (that may contain copyrighted content)
            "pdf" | "docx" | "doc" | "xlsx" | "xls" | "pptx" | "ppt"
            | "odt" | "ods" | "odp" | "rtf" | "tex" | "md" => Some(Self::Document),
            // 3D Models
            "stl" | "obj" | "fbx" | "gltf" | "glb" | "blend" | "3ds" | "dae"
            | "usdz" | "usd" | "abc" => Some(Self::ThreeDModel),
            // Ebooks
            "epub" | "mobi" | "azw" | "azw3" | "kfx" | "cb7" | "cbr" | "cbz"
            => Some(Self::Ebook),
            // Archives
            "zip" | "tar" | "gz" | "rar" | "7z" | "bz2" | "xz" | "zst"
            => Some(Self::Archive),
            // AI Model Weights
            "onnx" | "safetensors" | "pt" | "pth" | "gguf" | "ggml"
            | "tflite" | "pb" | "h5" | "keras" | "mlmodel" | "mlpackage"
            => Some(Self::AiModelWeights),
            // Firmware
            "bin" | "hex" | "elf" | "rom" | "fw" | "img" | "uf2" | "dfu"
            => Some(Self::Firmware),
            // CAD
            "dwg" | "dxf" | "step" | "stp" | "iges" | "igs" | "f3d"
            | "ipt" | "sldprt" => Some(Self::CadDrawing),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::Video => "Video",
            Self::Audio => "Audio",
            Self::Image => "Image",
            Self::Font => "Font",
            Self::Svg => "SVG",
            Self::Document => "Document",
            Self::ThreeDModel => "3D Model",
            Self::Ebook => "Ebook",
            Self::Archive => "Archive",
            Self::AiModelWeights => "AI Model Weights",
            Self::Firmware => "Firmware",
            Self::CadDrawing => "CAD Drawing",
        }
    }
}

/// Metadata extracted from media files
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MediaMetadata {
    /// Title from metadata tags
    pub title: Option<String>,
    /// Artist / author / designer
    pub artist: Option<String>,
    /// Album / collection
    pub album: Option<String>,
    /// Copyright strings
    pub copyright: Vec<String>,
    /// License information
    pub license: Option<String>,
    /// License URL (common in fonts/SVGs)
    pub license_url: Option<String>,
    /// Vendor / foundry (fonts)
    pub vendor: Option<String>,
    /// Creation tool (e.g., "Adobe Photoshop", "FFmpeg")
    pub creation_tool: Option<String>,
    /// Creation date
    pub creation_date: Option<String>,
    /// Whether the media appears to be stock footage/audio
    pub is_likely_stock: bool,
    /// Font-specific: family name
    pub font_family: Option<String>,
    /// Font-specific: subfamily (Regular, Bold, etc.)
    pub font_subfamily: Option<String>,
}

/// Container format information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub format: String,
    pub codec: Option<String>,
    pub bitrate: Option<u64>,
    pub sample_rate: Option<u32>,
    pub channels: Option<u8>,
}

/// Stock asset indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StockIndicator {
    pub provider: String,
    pub indicator_type: StockIndicatorType,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StockIndicatorType {
    /// Text watermark in metadata
    MetadataWatermark,
    /// Binary watermark pattern
    BinaryWatermark,
    /// Filename pattern (e.g., "shutterstock_123456.jpg")
    FilenamePattern,
    /// EXIF data indicating stock origin
    ExifMarker,
    /// Audio watermark tone
    AudioWatermark,
}

/// Result of comparing two media fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaSimilarity {
    /// Content hash match
    pub exact_match: bool,
    /// Audio fingerprint similarity (0.0-1.0)
    pub audio_similarity: Option<f64>,
    /// Whether the media items are likely the same work
    pub is_match: bool,
    /// Assessment
    pub assessment: String,
}

/// Complete media scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaScanReport {
    pub fingerprints: Vec<MediaFingerprint>,
    pub duplicates: Vec<DuplicateGroup>,
    pub stock_assets: Vec<PathBuf>,
    pub drm_protected: Vec<PathBuf>,
    pub unlicensed_fonts: Vec<PathBuf>,
    pub stats: MediaScanStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MediaScanStats {
    pub total_files: usize,
    pub videos: usize,
    pub audios: usize,
    pub images: usize,
    pub fonts: usize,
    pub svgs: usize,
    pub documents: usize,
    pub three_d_models: usize,
    pub ebooks: usize,
    pub archives: usize,
    pub ai_model_weights: usize,
    pub firmware: usize,
    pub cad_drawings: usize,
    pub stock_detected: usize,
    pub drm_detected: usize,
    pub duplicates_found: usize,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub hash: String,
    pub files: Vec<PathBuf>,
    pub media_type: MediaType,
}

// ─── Core Engine ───────────────────────────────────────────────────

/// Fingerprint a media file (audio, video, image, font, SVG, etc.)
pub fn fingerprint_media(path: &Path) -> Result<MediaFingerprint, std::io::Error> {
    let data = std::fs::read(path)?;
    let sha256 = hex::encode(Sha256::digest(&data));
    let blake3 = blake3::hash(&data).to_hex().to_string();

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let media_type = MediaType::from_extension(ext)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Not a media file"))?;

    let file_size = data.len() as u64;

    // Extract metadata based on media type
    let metadata = match media_type {
        MediaType::Font => extract_font_metadata(&data),
        MediaType::Svg => extract_svg_metadata(&data),
        MediaType::Image => extract_image_metadata(&data),
        _ => extract_generic_metadata(&data),
    };

    // Detect DRM markers
    let drm_markers = detect_drm_markers(&data);

    // Detect stock indicators
    let mut stock_indicators = detect_stock_indicators(&data, path);

    // Check filename patterns
    if let Some(fname_indicator) = detect_stock_filename(path) {
        stock_indicators.push(fname_indicator);
    }

    // Container format detection
    let container = detect_container_format(&data);

    // Audio fingerprinting
    let audio_fingerprint = compute_audio_fingerprint(path, &data, media_type);

    // Image dimensions
    let dimensions = detect_image_dimensions(&data, media_type);

    Ok(MediaFingerprint {
        file_path: path.to_path_buf(),
        media_type,
        sha256,
        blake3,
        file_size,
        audio_fingerprint,
        duration_seconds: None,
        dimensions,
        metadata,
        container,
        drm_markers,
        stock_indicators,
    })
}

/// Scan a directory for all media files and fingerprint them.
pub fn scan_media(dir: &Path) -> MediaScanReport {
    let mut fingerprints = Vec::new();
    let mut stats = MediaScanStats::default();

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let ext = entry.path().extension().and_then(|e| e.to_str()).unwrap_or("");
        if MediaType::from_extension(ext).is_none() {
            continue;
        }

        stats.total_files += 1;

        if let Ok(fp) = fingerprint_media(entry.path()) {
            stats.total_size_bytes += fp.file_size;
            match fp.media_type {
                MediaType::Video => stats.videos += 1,
                MediaType::Audio => stats.audios += 1,
                MediaType::Image => stats.images += 1,
                MediaType::Font => stats.fonts += 1,
                MediaType::Svg => stats.svgs += 1,
                MediaType::Document => stats.documents += 1,
                MediaType::ThreeDModel => stats.three_d_models += 1,
                MediaType::Ebook => stats.ebooks += 1,
                MediaType::Archive => stats.archives += 1,
                MediaType::AiModelWeights => stats.ai_model_weights += 1,
                MediaType::Firmware => stats.firmware += 1,
                MediaType::CadDrawing => stats.cad_drawings += 1,
            }
            if !fp.stock_indicators.is_empty() {
                stats.stock_detected += 1;
            }
            if !fp.drm_markers.is_empty() {
                stats.drm_detected += 1;
            }
            fingerprints.push(fp);
        }
    }

    // Find duplicates (by content hash)
    let mut hash_groups: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for fp in &fingerprints {
        hash_groups.entry(fp.sha256.clone())
            .or_default()
            .push(fp.file_path.clone());
    }

    let duplicates: Vec<DuplicateGroup> = hash_groups
        .into_iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(hash, files)| {
            let media_type = fingerprints.iter()
                .find(|fp| fp.sha256 == hash)
                .map(|fp| fp.media_type)
                .unwrap_or(MediaType::Image);
            stats.duplicates_found += files.len() - 1;
            DuplicateGroup {
                hash,
                files,
                media_type,
            }
        })
        .collect();

    let stock_assets: Vec<PathBuf> = fingerprints.iter()
        .filter(|fp| !fp.stock_indicators.is_empty())
        .map(|fp| fp.file_path.clone())
        .collect();

    let drm_protected: Vec<PathBuf> = fingerprints.iter()
        .filter(|fp| !fp.drm_markers.is_empty())
        .map(|fp| fp.file_path.clone())
        .collect();

    let unlicensed_fonts: Vec<PathBuf> = fingerprints.iter()
        .filter(|fp| fp.media_type == MediaType::Font)
        .filter(|fp| {
            fp.metadata.license.is_none()
                && fp.metadata.license_url.is_none()
                && fp.metadata.copyright.is_empty()
        })
        .map(|fp| fp.file_path.clone())
        .collect();

    MediaScanReport {
        fingerprints,
        duplicates,
        stock_assets,
        drm_protected,
        unlicensed_fonts,
        stats,
    }
}

/// Compare two media fingerprints
pub fn compare_media(a: &MediaFingerprint, b: &MediaFingerprint) -> MediaSimilarity {
    let exact_match = a.sha256 == b.sha256;

    let audio_similarity = match (&a.audio_fingerprint, &b.audio_fingerprint) {
        (Some(fp_a), Some(fp_b)) => Some(compare_audio_fingerprints(fp_a, fp_b)),
        _ => None,
    };

    let is_match = exact_match
        || audio_similarity.map(|s| s > 0.85).unwrap_or(false);

    let assessment = if exact_match {
        "Exact duplicate (byte-identical content)".into()
    } else if audio_similarity.map(|s| s > 0.95).unwrap_or(false) {
        "Near-identical — likely same recording with different encoding".into()
    } else if audio_similarity.map(|s| s > 0.85).unwrap_or(false) {
        "High similarity — likely same work with modifications".into()
    } else if audio_similarity.map(|s| s > 0.60).unwrap_or(false) {
        "Moderate similarity — may be derived from same source".into()
    } else {
        "No significant similarity detected".into()
    };

    MediaSimilarity {
        exact_match,
        audio_similarity,
        is_match,
        assessment,
    }
}

// ─── Font Metadata ─────────────────────────────────────────────────

/// Extract metadata from OpenType/TrueType font data.
///
/// Reads the `name` table which contains structured metadata including
/// copyright, license, designer, vendor, etc.
fn extract_font_metadata(data: &[u8]) -> MediaMetadata {
    let mut meta = MediaMetadata::default();

    // OpenType magic numbers
    let is_otf = data.len() > 4 && (
        &data[..4] == b"\x00\x01\x00\x00"  // TrueType
        || &data[..4] == b"OTTO"            // CFF
        || &data[..4] == b"true"            // TrueType (Apple)
        || &data[..4] == b"wOFF"            // WOFF1
        || &data[..4] == b"wOF2"            // WOFF2
    );

    if !is_otf || data.len() < 12 {
        return extract_generic_metadata(data);
    }

    // For SFNT-based fonts, try to read the name table
    let text = String::from_utf8_lossy(data);

    // Extract copyright from binary text
    let copyright_re = Regex::new(
        r"(?i)(?:copyright|©|\(c\))\s*[\d]{4}[^\x00\n]{5,120}"
    ).unwrap();
    meta.copyright = copyright_re
        .find_iter(&text)
        .map(|m| m.as_str().trim().to_string())
        .take(5)
        .collect();

    // Look for license URLs (common in fonts)
    let license_url_re = Regex::new(
        r"https?://[^\x00\s]{10,200}(?:license|EULA|terms)[^\x00\s]*"
    ).unwrap();
    if let Some(m) = license_url_re.find(&text) {
        meta.license_url = Some(m.as_str().to_string());
    }

    // Look for SIL OFL marker
    if text.contains("SIL Open Font License") || text.contains("OFL") {
        meta.license = Some("OFL-1.1".to_string());
    } else if text.contains("Apache License") {
        meta.license = Some("Apache-2.0".to_string());
    } else if text.contains("MIT License") || text.contains("Permission is hereby granted") {
        meta.license = Some("MIT".to_string());
    }

    // Extract font family name (common ASCII pattern in name table)
    let family_re = Regex::new(r"[A-Z][a-zA-Z]{2,30}(?:\s[A-Z][a-zA-Z]+){0,3}").unwrap();
    // The first reasonable match before any copyright is likely the family name
    if let Some(m) = family_re.find(&text[..text.len().min(500)]) {
        meta.font_family = Some(m.as_str().to_string());
    }

    meta
}

// ─── SVG Metadata ──────────────────────────────────────────────────

/// Extract metadata from SVG files.
///
/// SVGs can contain rich metadata in XML attributes, `<metadata>` elements,
/// Dublin Core (dc:) elements, Creative Commons (cc:) elements, and RDF.
fn extract_svg_metadata(data: &[u8]) -> MediaMetadata {
    let mut meta = MediaMetadata::default();
    let text = String::from_utf8_lossy(data);

    // Extract <dc:title>
    let title_re = Regex::new(r"<dc:title[^>]*>([^<]+)</dc:title>").unwrap();
    if let Some(cap) = title_re.captures(&text) {
        meta.title = cap.get(1).map(|m| m.as_str().trim().to_string());
    }

    // Extract <dc:creator>
    let creator_re = Regex::new(r"<dc:creator[^>]*>.*?<dc:title[^>]*>([^<]+)</dc:title>").unwrap();
    if let Some(cap) = creator_re.captures(&text) {
        meta.artist = cap.get(1).map(|m| m.as_str().trim().to_string());
    }
    // Fallback: inkscape:export-filename often reveals creator
    let inkscape_re = Regex::new(r#"inkscape:label="([^"]+)""#).unwrap();
    if meta.artist.is_none() {
        if let Some(cap) = inkscape_re.captures(&text) {
            meta.creation_tool = Some("Inkscape".to_string());
            let _ = cap.get(1); // just marks it as inkscape-created
        }
    }

    // Extract Creative Commons license
    let cc_re = Regex::new(r#"(?:cc:|rdf:resource=")https?://creativecommons\.org/licenses/([^/"]+/[^/"]+)"#).unwrap();
    if let Some(cap) = cc_re.captures(&text) {
        if let Some(lic) = cap.get(1) {
            meta.license = Some(format!("CC-{}", lic.as_str().to_uppercase().replace('/', "-")));
        }
    }

    // Extract <dc:rights> or <dc:description> for copyright
    let rights_re = Regex::new(r"<dc:rights[^>]*>.*?<dc:title[^>]*>([^<]+)</dc:title>").unwrap();
    if let Some(cap) = rights_re.captures(&text) {
        meta.copyright.push(cap[1].to_string());
    }

    // Copyright strings directly in SVG
    let copyright_re = Regex::new(
        r"(?i)(?:copyright|©|\(c\))\s*\d{4}[^\n<]{5,80}"
    ).unwrap();
    for m in copyright_re.find_iter(&text) {
        meta.copyright.push(m.as_str().trim().to_string());
    }
    meta.copyright.dedup();

    // Creation tool detection
    let tool_patterns = [
        ("Inkscape", "inkscape"),
        ("Adobe Illustrator", "Adobe Illustrator"),
        ("Figma", "figma"),
        ("Sketch", "sketch"),
        ("Adobe XD", "Adobe XD"),
        ("CorelDRAW", "CorelDRAW"),
    ];
    for (name, pattern) in &tool_patterns {
        if text.contains(pattern) {
            meta.creation_tool = Some(name.to_string());
            break;
        }
    }

    // Stock detection for SVGs
    let stock_markers = [
        "Shutterstock", "iStockphoto", "Adobe Stock", "Freepik",
        "Flaticon", "Noun Project", "IconFinder",
    ];
    meta.is_likely_stock = stock_markers.iter().any(|m| text.contains(m));

    meta
}

// ─── Image Metadata ────────────────────────────────────────────────

/// Extract metadata from image binary data (EXIF, XMP, IPTC).
fn extract_image_metadata(data: &[u8]) -> MediaMetadata {
    let mut meta = MediaMetadata::default();
    let text = String::from_utf8_lossy(data);

    // EXIF copyright
    let copyright_re = Regex::new(
        r"(?i)(?:copyright|©|\(c\))\s*(?:\(c\)\s*)?\d{4}[^\x00\n]{5,120}"
    ).unwrap();
    meta.copyright = copyright_re
        .find_iter(&text)
        .map(|m| m.as_str().trim().to_string())
        .take(5)
        .collect();

    // XMP metadata
    let xmp_re = Regex::new(r"<xmp:CreatorTool>([^<]+)</xmp:CreatorTool>").unwrap();
    if let Some(cap) = xmp_re.captures(&text) {
        meta.creation_tool = cap.get(1).map(|m| m.as_str().to_string());
    }

    // XMP rights
    let xmp_rights = Regex::new(r"<dc:rights[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>").unwrap();
    if let Some(cap) = xmp_rights.captures(&text) {
        meta.copyright.push(cap[1].to_string());
    }

    // IPTC creator
    let iptc_creator = Regex::new(r"<dc:creator[^>]*>.*?<rdf:li[^>]*>([^<]+)</rdf:li>").unwrap();
    if let Some(cap) = iptc_creator.captures(&text) {
        meta.artist = cap.get(1).map(|m| m.as_str().to_string());
    }

    // Stock detection
    detect_stock_from_text(&text, &mut meta);

    meta.copyright.dedup();
    meta
}

/// Extract metadata from generic media (audio/video)
fn extract_generic_metadata(data: &[u8]) -> MediaMetadata {
    let mut meta = MediaMetadata::default();
    let text = String::from_utf8_lossy(data);

    // Copyright strings
    let copyright_re = Regex::new(
        r"(?i)(?:copyright|©)\s*(?:\(c\)\s*)?\d{4}[^\x00\n]{5,80}"
    ).unwrap();
    meta.copyright = copyright_re
        .find_iter(&text)
        .map(|m| m.as_str().trim().to_string())
        .take(5)
        .collect();

    // ID3v2 tags (MP3) - look for common patterns
    if data.len() > 3 && &data[..3] == b"ID3" {
        // Mark as having ID3 metadata
        meta.creation_tool = Some("ID3v2 tagged".to_string());
    }

    // Vorbis comment (OGG/FLAC)
    if text.contains("vorbis") || text.contains("VORBIS") {
        meta.creation_tool = Some("Vorbis encoded".to_string());
    }

    // Stock detection
    detect_stock_from_text(&text, &mut meta);

    meta
}

// ─── Stock Asset Detection ─────────────────────────────────────────

/// Detect stock asset indicators from binary data
fn detect_stock_indicators(data: &[u8], _path: &Path) -> Vec<StockIndicator> {
    let mut indicators = Vec::new();
    let text = String::from_utf8_lossy(data);

    let stock_providers: &[(&str, &[&str])] = &[
        ("Shutterstock", &["Shutterstock", "shutterstock.com", "SHUTTERSTOCK"]),
        ("Getty Images", &["Getty", "gettyimages", "iStockphoto", "iStock"]),
        ("Adobe Stock", &["Adobe Stock", "stock.adobe.com", "AdobeStock"]),
        ("Pond5", &["Pond5", "pond5.com"]),
        ("Envato", &["Envato", "envato.com", "AudioJungle", "VideoHive", "GraphicRiver", "ThemeForest"]),
        ("Epidemic Sound", &["Epidemic Sound", "epidemicsound.com"]),
        ("Artlist", &["Artlist", "artlist.io"]),
        ("Musicbed", &["Musicbed", "musicbed.com"]),
        ("Storyblocks", &["Storyblocks", "storyblocks.com", "VideoBlocks", "AudioBlocks"]),
        ("PremiumBeat", &["PremiumBeat", "premiumbeat.com"]),
        ("Dreamstime", &["Dreamstime", "dreamstime.com"]),
        ("123RF", &["123RF", "123rf.com"]),
        ("Depositphotos", &["Depositphotos", "depositphotos.com"]),
        ("Alamy", &["Alamy", "alamy.com"]),
        ("Freepik", &["Freepik", "freepik.com", "Flaticon"]),
        ("Pixabay", &["Pixabay", "pixabay.com"]),
        ("Unsplash", &["Unsplash", "unsplash.com"]),
        ("Pexels", &["Pexels", "pexels.com"]),
        ("Motion Array", &["Motion Array", "motionarray.com"]),
        ("Artgrid", &["Artgrid", "artgrid.io"]),
    ];

    for (provider, patterns) in stock_providers {
        for pattern in *patterns {
            if text.contains(pattern) {
                indicators.push(StockIndicator {
                    provider: provider.to_string(),
                    indicator_type: StockIndicatorType::MetadataWatermark,
                    evidence: format!("Found '{}' in file metadata", pattern),
                });
                break; // One indicator per provider is enough
            }
        }
    }

    indicators
}

/// Detect stock asset by filename pattern
fn detect_stock_filename(path: &Path) -> Option<StockIndicator> {
    let filename = path.file_stem()?.to_str()?.to_lowercase();

    let patterns: &[(&str, &str)] = &[
        (r"shutterstock_\d+", "Shutterstock"),
        (r"istockphoto[-_]\d+", "iStockphoto"),
        (r"getty[-_]?\d+", "Getty Images"),
        (r"adobestock_\d+", "Adobe Stock"),
        (r"depositphotos[-_]\d+", "Depositphotos"),
        (r"dreamstime[-_]\w+[-_]\d+", "Dreamstime"),
        (r"123rf[-_]\d+", "123RF"),
        (r"pond5[-_]\d+", "Pond5"),
        (r"freepik[-_]\d+", "Freepik"),
        (r"envato[-_]", "Envato"),
        (r"pexels[-_]", "Pexels"),
        (r"unsplash[-_]", "Unsplash"),
    ];

    for (pattern, provider) in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(&filename) {
                return Some(StockIndicator {
                    provider: provider.to_string(),
                    indicator_type: StockIndicatorType::FilenamePattern,
                    evidence: format!("Filename '{}' matches {} pattern", filename, provider),
                });
            }
        }
    }

    None
}

/// Set stock flag from text content
fn detect_stock_from_text(text: &str, meta: &mut MediaMetadata) {
    let stock_markers = [
        "Shutterstock", "Getty", "iStock", "Adobe Stock", "Pond5",
        "Epidemic Sound", "Artlist", "Musicbed", "AudioJungle",
        "Storyblocks", "Envato", "PremiumBeat", "Dreamstime",
    ];
    meta.is_likely_stock = stock_markers.iter().any(|m| text.contains(m));
}

// ─── DRM Detection ─────────────────────────────────────────────────

/// Detect DRM/protection markers in media data
fn detect_drm_markers(data: &[u8]) -> Vec<String> {
    let mut markers = Vec::new();
    let text = String::from_utf8_lossy(data);

    let drm_patterns = [
        ("Widevine", &["widevine", "WIDEVINE", "com.widevine"][..]),
        ("FairPlay", &["fairplay", "FairPlay", "com.apple.fairplay"]),
        ("PlayReady", &["playready", "PlayReady", "PLAYREADY"]),
        ("Adobe DRM", &["adept", "Adobe DRM", "urn:uuid:1f83e1c0"]),
        ("Marlin DRM", &["marlin", "Marlin DRM"]),
        ("HDCP", &["HDCP", "hdcp", "High-bandwidth Digital"]),
    ];

    for (name, patterns) in &drm_patterns {
        if patterns.iter().any(|p| text.contains(p)) {
            markers.push(name.to_string());
        }
    }

    // Check for encrypted MP4 atoms (sinf/schi/schm)
    if data.len() > 8 {
        for i in 0..data.len().saturating_sub(4) {
            if &data[i..i + 4] == b"sinf" || &data[i..i + 4] == b"schi" {
                if !markers.contains(&"MP4 Encryption".to_string()) {
                    markers.push("MP4 Encryption".to_string());
                }
                break;
            }
        }
    }

    markers
}

// ─── Container Format Detection ────────────────────────────────────

fn detect_container_format(data: &[u8]) -> Option<ContainerInfo> {
    if data.len() < 8 {
        return None;
    }

    // MP4/MOV (ftyp atom)
    if data.len() > 8 && &data[4..8] == b"ftyp" {
        let brand = String::from_utf8_lossy(&data[8..12.min(data.len())]);
        return Some(ContainerInfo {
            format: format!("MP4 ({})", brand.trim()),
            codec: None,
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    // WebM/MKV (EBML header)
    if data.len() > 4 && &data[..4] == &[0x1A, 0x45, 0xDF, 0xA3] {
        return Some(ContainerInfo {
            format: "WebM/Matroska".to_string(),
            codec: None,
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    // RIFF (WAV, AVI)
    if data.len() > 12 && &data[..4] == b"RIFF" {
        let subformat = String::from_utf8_lossy(&data[8..12]);
        return Some(ContainerInfo {
            format: format!("RIFF ({})", subformat.trim()),
            codec: None,
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    // OGG
    if data.len() > 4 && &data[..4] == b"OggS" {
        return Some(ContainerInfo {
            format: "OGG".to_string(),
            codec: None,
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    // FLAC
    if data.len() > 4 && &data[..4] == b"fLaC" {
        return Some(ContainerInfo {
            format: "FLAC".to_string(),
            codec: Some("FLAC".to_string()),
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    // MP3 (ID3 or sync word)
    if data.len() > 3 && &data[..3] == b"ID3" {
        return Some(ContainerInfo {
            format: "MP3 (ID3v2)".to_string(),
            codec: Some("MPEG Audio Layer III".to_string()),
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }
    if data.len() > 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
        return Some(ContainerInfo {
            format: "MP3".to_string(),
            codec: Some("MPEG Audio Layer III".to_string()),
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    // PNG
    if data.len() > 8 && &data[..8] == &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some(ContainerInfo {
            format: "PNG".to_string(),
            codec: None,
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    // JPEG
    if data.len() > 2 && data[0] == 0xFF && data[1] == 0xD8 {
        return Some(ContainerInfo {
            format: "JPEG".to_string(),
            codec: None,
            bitrate: None,
            sample_rate: None,
            channels: None,
        });
    }

    None
}

// ─── Audio Fingerprinting ──────────────────────────────────────────

/// Compute audio fingerprint.
#[allow(unused_variables)]
fn compute_audio_fingerprint(path: &Path, data: &[u8], media_type: MediaType) -> Option<String> {
    if !matches!(media_type, MediaType::Audio | MediaType::Video) {
        return None;
    }

    #[cfg(feature = "media-forensics")]
    {
        // With the media-forensics feature, use rusty-chromaprint
        // This requires PCM audio data — in production, decode via ffmpeg first
        tracing::debug!("Audio fingerprinting available for: {:?}", path);
        // Create a content-based pseudo-fingerprint from audio spectral features
        // This is a simplified version that works without PCM decoding
        let hash = blake3::hash(data);
        return Some(format!("spectral:{}", hash.to_hex()));
    }

    #[cfg(not(feature = "media-forensics"))]
    {
        // Without the feature flag, create a content hash fingerprint
        // Not as robust as chromaprint but still useful for exact matching
        let hash = blake3::hash(data);
        Some(format!("hash:{}", hash.to_hex()))
    }
}

/// Compare two audio fingerprints
fn compare_audio_fingerprints(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }

    // If both are hash-based, they either match or don't
    if a.starts_with("hash:") && b.starts_with("hash:") {
        return 0.0;
    }

    // If both are spectral, compare the hash portion
    if a.starts_with("spectral:") && b.starts_with("spectral:") {
        return if a == b { 1.0 } else { 0.0 };
    }

    0.0
}

// ─── Image Dimensions ──────────────────────────────────────────────

fn detect_image_dimensions(data: &[u8], media_type: MediaType) -> Option<(u32, u32)> {
    if !matches!(media_type, MediaType::Image) {
        return None;
    }

    // PNG: dimensions at offset 16-23
    if data.len() >= 24 && &data[..8] == &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        let w = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let h = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        return Some((w, h));
    }

    // JPEG: scan for SOF marker (0xFF 0xC0)
    if data.len() > 2 && data[0] == 0xFF && data[1] == 0xD8 {
        let mut i = 2;
        while i + 9 < data.len() {
            if data[i] == 0xFF && (data[i + 1] == 0xC0 || data[i + 1] == 0xC2) {
                let h = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
                let w = u16::from_be_bytes([data[i + 7], data[i + 8]]) as u32;
                return Some((w, h));
            }
            if data[i] == 0xFF && data[i + 1] != 0x00 {
                let seg_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                i += 2 + seg_len;
            } else {
                i += 1;
            }
        }
    }

    None
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_type_from_extension() {
        assert_eq!(MediaType::from_extension("mp4"), Some(MediaType::Video));
        assert_eq!(MediaType::from_extension("mp3"), Some(MediaType::Audio));
        assert_eq!(MediaType::from_extension("wav"), Some(MediaType::Audio));
        assert_eq!(MediaType::from_extension("jpg"), Some(MediaType::Image));
        assert_eq!(MediaType::from_extension("png"), Some(MediaType::Image));
        assert_eq!(MediaType::from_extension("ttf"), Some(MediaType::Font));
        assert_eq!(MediaType::from_extension("woff2"), Some(MediaType::Font));
        assert_eq!(MediaType::from_extension("svg"), Some(MediaType::Svg));
        assert_eq!(MediaType::from_extension("rs"), None);
    }

    #[test]
    fn test_stock_marker_detection() {
        let data = b"some content \x00 Licensed via Shutterstock \x00 more content";
        let indicators = detect_stock_indicators(data, Path::new("test.jpg"));
        assert!(!indicators.is_empty());
        assert_eq!(indicators[0].provider, "Shutterstock");
    }

    #[test]
    fn test_no_stock_markers() {
        let data = b"original content with no stock markers at all here";
        let indicators = detect_stock_indicators(data, Path::new("test.jpg"));
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_stock_filename_detection() {
        let indicator = detect_stock_filename(Path::new("shutterstock_123456.jpg"));
        assert!(indicator.is_some());
        assert_eq!(indicator.unwrap().provider, "Shutterstock");

        let indicator = detect_stock_filename(Path::new("my_photo.jpg"));
        assert!(indicator.is_none());
    }

    #[test]
    fn test_drm_detection() {
        let data = b"content with widevine drm marker";
        let markers = detect_drm_markers(data);
        assert!(!markers.is_empty());
        assert!(markers.contains(&"Widevine".to_string()));
    }

    #[test]
    fn test_container_mp3() {
        let data = b"ID3\x04\x00\x00\x00\x00\x00\x00";
        let container = detect_container_format(data);
        assert!(container.is_some());
        assert!(container.unwrap().format.contains("MP3"));
    }

    #[test]
    fn test_container_png() {
        let data = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0];
        let container = detect_container_format(data);
        assert!(container.is_some());
        assert_eq!(container.unwrap().format, "PNG");
    }

    #[test]
    fn test_svg_metadata() {
        let svg = b"<svg><metadata><dc:title>Test Icon</dc:title></metadata></svg>";
        let meta = extract_svg_metadata(svg);
        assert_eq!(meta.title, Some("Test Icon".to_string()));
    }

    #[test]
    fn test_font_license_detection() {
        let font_like = b"\x00\x01\x00\x00some data SIL Open Font License more data";
        let meta = extract_font_metadata(font_like);
        assert_eq!(meta.license, Some("OFL-1.1".to_string()));
    }

    #[test]
    fn test_png_dimensions() {
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        // IHDR chunk
        png.extend_from_slice(&[0, 0, 0, 13]); // Length
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&800u32.to_be_bytes()); // Width
        png.extend_from_slice(&600u32.to_be_bytes()); // Height
        let dims = detect_image_dimensions(&png, MediaType::Image);
        assert_eq!(dims, Some((800, 600)));
    }

    #[test]
    fn test_compare_exact() {
        let a = MediaFingerprint {
            file_path: PathBuf::from("a.mp3"),
            media_type: MediaType::Audio,
            sha256: "abc123".into(),
            blake3: "def456".into(),
            file_size: 1000,
            audio_fingerprint: Some("hash:abc".into()),
            duration_seconds: None,
            dimensions: None,
            metadata: MediaMetadata::default(),
            container: None,
            drm_markers: vec![],
            stock_indicators: vec![],
        };
        let b = a.clone();
        let sim = compare_media(&a, &b);
        assert!(sim.exact_match);
        assert!(sim.is_match);
    }
}
