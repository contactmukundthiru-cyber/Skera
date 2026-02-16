//! Web asset copyright scanner — CDN, fonts, icons, CSS frameworks, embedded assets
//!
//! ## Why This Matters
//!
//! Modern web projects embed copyrighted assets from dozens of sources:
//! fonts loaded from CDNs, icon libraries with tiered licensing (FontAwesome
//! Free vs Pro), CSS frameworks with different licenses, JavaScript libraries
//! loaded from unpkg/cdnjs/jsdelivr, Base64-encoded images, and stock photos.
//!
//! **No existing license scanner handles web assets properly.**
//!
//! ## What This Module Detects
//!
//! 1. **CDN-loaded libraries** — extracts library names and versions from
//!    `<script src="cdn...">` and `<link href="cdn...">` tags, checks license
//!
//! 2. **Web fonts** — detects @font-face declarations, Google Fonts usage,
//!    Adobe Fonts (Typekit), commercial font services, and local font files
//!    with licensing obligations
//!
//! 3. **Icon libraries** — FontAwesome (Free GPL/MIT vs Pro commercial),
//!    Material Icons, Bootstrap Icons, Feather, Heroicons, Phosphor, etc.
//!
//! 4. **CSS frameworks** — Bootstrap, Tailwind, Foundation, Bulma, Material,
//!    Semantic UI, and their respective licenses
//!
//! 5. **Embedded Base64 assets** — detects inline images/fonts that may be
//!    copyrighted stock photos or commercial fonts
//!
//! 6. **Source maps** — analyzes .map files to detect what source code was
//!    compiled into bundles (may reveal copyrighted upstream code)
//!
//! 7. **Meta tag analysis** — og:image, twitter:image, favicon, apple-touch-icon
//!    all may use copyrighted images
//!
//! 8. **robots.txt compliance** — if the project is a scraper or crawler,
//!    verify it respects robots.txt directives

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─── Core Types ─────────────────────────────────────────────────────

/// Complete web asset scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAssetReport {
    /// Root directory scanned
    pub root: PathBuf,
    /// CDN references found
    pub cdn_references: Vec<CdnReference>,
    /// Web font usage
    pub web_fonts: Vec<WebFontUsage>,
    /// Icon library usage
    pub icon_libraries: Vec<IconLibraryUsage>,
    /// CSS framework usage
    pub css_frameworks: Vec<CssFrameworkUsage>,
    /// Embedded Base64 assets
    pub embedded_assets: Vec<EmbeddedAsset>,
    /// Source map analysis
    pub source_maps: Vec<SourceMapAnalysis>,
    /// Meta tag images
    pub meta_images: Vec<MetaImage>,
    /// robots.txt findings
    pub robots_findings: Vec<RobotsFinding>,
    /// Google Analytics / tracking pixel detection
    pub tracking_scripts: Vec<TrackingScript>,
    /// Total findings
    pub total_findings: usize,
    /// Total files scanned
    pub files_scanned: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdnReference {
    pub url: String,
    pub library_name: Option<String>,
    pub version: Option<String>,
    pub cdn_provider: CdnProvider,
    pub resource_type: CdnResourceType,
    pub license: Option<String>,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub integrity_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdnProvider {
    Cdnjs,
    JsDelivr,
    Unpkg,
    GoogleCdn,
    CloudflareCdn,
    BootstrapCdn,
    JqueryCdn,
    MicrosoftCdn,
    StackPathCdn,
    FontAwesomeCdn,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdnResourceType {
    JavaScript,
    Css,
    Font,
    Image,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFontUsage {
    pub font_name: String,
    pub source: FontSource,
    pub license: Option<FontLicense>,
    pub file_path: PathBuf,
    pub line_number: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FontSource {
    GoogleFonts,
    AdobeFonts,
    FontFaceLocal,
    FontFaceUrl(String),
    Bundled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FontLicense {
    /// SIL Open Font License
    OFL,
    /// Apache 2.0 (e.g., Roboto)
    Apache2,
    /// Ubuntu Font License
    UFL,
    /// Commercial/proprietary
    Commercial,
    /// Free for personal use
    PersonalUseOnly,
    /// Unknown
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IconLibraryUsage {
    pub library: IconLibrary,
    pub tier: IconTier,
    pub references: usize,
    pub file_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IconLibrary {
    FontAwesome,
    MaterialIcons,
    BootstrapIcons,
    FeatherIcons,
    Heroicons,
    PhosphorIcons,
    Ionicons,
    RemixIcon,
    Lucide,
    TablerIcons,
    LineAwesome,
    BoxIcons,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IconTier {
    /// Free/open version (MIT, Apache, etc.)
    Free,
    /// Pro/commercial version (requires license)
    Pro,
    /// Unknown tier
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CssFrameworkUsage {
    pub framework: CssFramework,
    pub version: Option<String>,
    pub license: String,
    pub file_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CssFramework {
    Bootstrap,
    Tailwind,
    Foundation,
    Bulma,
    MaterialDesign,
    SemanticUi,
    UIKit,
    Primer,
    Chakra,
    AntDesign,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedAsset {
    pub mime_type: String,
    pub size_bytes: usize,
    pub encoding: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    /// Was this originally from a stock photo site?
    pub stock_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapAnalysis {
    pub map_file: PathBuf,
    pub source_files: Vec<String>,
    /// Detected third-party code in the source map
    pub third_party_sources: Vec<String>,
    pub total_sources: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaImage {
    pub tag_type: String,
    pub url: String,
    pub file_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotsFinding {
    pub finding_type: RobotsFindingType,
    pub description: String,
    pub file_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RobotsFindingType {
    /// Project is a scraper but doesn't check robots.txt
    ScraperWithoutRobotsCheck,
    /// Project has a robots.txt that disallows all
    DisallowsAll,
    /// Uses known scraping libraries
    UsesScrapingLibrary,
    /// Explicitly ignores robots.txt
    IgnoresRobots,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingScript {
    pub provider: String,
    pub script_url: Option<String>,
    pub file_path: PathBuf,
    pub privacy_concern: String,
}

// ─── CDN → License Database ────────────────────────────────────────

/// Known CDN-hosted library licenses
const CDN_LIBRARY_LICENSES: &[(&str, &str)] = &[
    ("jquery", "MIT"),
    ("react", "MIT"),
    ("react-dom", "MIT"),
    ("vue", "MIT"),
    ("angular", "MIT"),
    ("d3", "ISC"),
    ("lodash", "MIT"),
    ("moment", "MIT"),
    ("axios", "MIT"),
    ("bootstrap", "MIT"),
    ("tailwindcss", "MIT"),
    ("foundation", "MIT"),
    ("bulma", "MIT"),
    ("popper.js", "MIT"),
    ("chart.js", "MIT"),
    ("three.js", "MIT"),
    ("socket.io", "MIT"),
    ("leaflet", "BSD-2-Clause"),
    ("underscore", "MIT"),
    ("backbone", "MIT"),
    ("ember", "MIT"),
    ("handlebars", "MIT"),
    ("mustache", "MIT"),
    ("knockout", "MIT"),
    ("mithril", "MIT"),
    ("preact", "MIT"),
    ("svelte", "MIT"),
    ("alpine", "MIT"),
    ("htmx", "BSD-2-Clause"),
    ("highlight.js", "BSD-3-Clause"),
    ("prism", "MIT"),
    ("animate.css", "MIT"),
    ("normalize.css", "MIT"),
    ("font-awesome", "Font: SIL OFL 1.1, CSS: MIT, Pro: Commercial"),
    ("material-icons", "Apache-2.0"),
    ("ionicons", "MIT"),
    ("feather-icons", "MIT"),
    ("heroicons", "MIT"),
    ("swiper", "MIT"),
    ("gsap", "Standard: Free, Business: Commercial GSAP License"),
    ("lottie", "MIT"),
    ("howler", "MIT"),
    ("tone.js", "MIT"),
    ("wavesurfer.js", "BSD-3-Clause"),
    ("plyr", "MIT"),
];

/// Google Fonts that are known to be Apache-2.0 or OFL
const GOOGLE_FONT_LICENSES: &[(&str, FontLicense)] = &[
    ("Roboto", FontLicense::Apache2),
    ("Open Sans", FontLicense::Apache2),
    ("Lato", FontLicense::OFL),
    ("Montserrat", FontLicense::OFL),
    ("Poppins", FontLicense::OFL),
    ("Inter", FontLicense::OFL),
    ("Raleway", FontLicense::OFL),
    ("Nunito", FontLicense::OFL),
    ("Ubuntu", FontLicense::UFL),
    ("Playfair Display", FontLicense::OFL),
    ("Source Sans Pro", FontLicense::OFL),
    ("Source Code Pro", FontLicense::OFL),
    ("Fira Code", FontLicense::OFL),
    ("JetBrains Mono", FontLicense::OFL),
    ("DM Sans", FontLicense::OFL),
    ("Space Grotesk", FontLicense::OFL),
    ("Space Mono", FontLicense::OFL),
    ("IBM Plex Sans", FontLicense::OFL),
    ("IBM Plex Mono", FontLicense::OFL),
    ("Inconsolata", FontLicense::OFL),
    ("Outfit", FontLicense::OFL),
    ("Work Sans", FontLicense::OFL),
    ("Manrope", FontLicense::OFL),
    ("Merriweather", FontLicense::OFL),
    ("PT Sans", FontLicense::OFL),
    ("Noto Sans", FontLicense::OFL),
    ("Noto Serif", FontLicense::OFL),
    ("Material Symbols", FontLicense::Apache2),
];

/// Known commercial font families (NOT free for embedding)
const COMMERCIAL_FONTS: &[&str] = &[
    "Helvetica", "Arial", "Times New Roman", "Garamond", "Futura",
    "Avenir", "Proxima Nova", "Gotham", "Freight", "Neue Haas Grotesk",
    "Akzidenz Grotesk", "Univers", "Frutiger", "Gill Sans", "Optima",
    "Palatino", "Baskerville", "Caslon", "Clarendon", "Didot",
    "SF Pro", "SF Mono", "San Francisco", "Segoe UI",
    "Apercu", "Circular", "Graphik", "Suisse", "Neue Montreal",
    "GT Walsheim", "GT America", "Founders Grotesk", "Calibre",
    "Brandon Grotesque", "TT Norms", "Monument Extended",
    "Canela", "Reckless", "Editorial New", "PP Neue Montreal",
];

// ─── Web Asset Scanner ──────────────────────────────────────────────

pub struct WebAssetScanner;

impl WebAssetScanner {
    /// Scan a project directory for all web asset copyright issues
    pub fn scan(root: &Path) -> WebAssetReport {
        let mut report = WebAssetReport {
            root: root.to_path_buf(),
            cdn_references: Vec::new(),
            web_fonts: Vec::new(),
            icon_libraries: Vec::new(),
            css_frameworks: Vec::new(),
            embedded_assets: Vec::new(),
            source_maps: Vec::new(),
            meta_images: Vec::new(),
            robots_findings: Vec::new(),
            tracking_scripts: Vec::new(),
            total_findings: 0,
            files_scanned: 0,
        };

        // Walk all HTML, CSS, JS files
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

            match ext.as_str() {
                "html" | "htm" | "ejs" | "hbs" | "pug" | "svelte" | "vue" | "jsx" | "tsx" => {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        report.files_scanned += 1;
                        Self::scan_html_content(&content, entry.path(), &mut report);
                    }
                }
                "css" | "scss" | "sass" | "less" | "styl" => {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        report.files_scanned += 1;
                        Self::scan_css_content(&content, entry.path(), &mut report);
                    }
                }
                "js" | "ts" | "mjs" | "cjs" => {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        report.files_scanned += 1;
                        Self::scan_js_content(&content, entry.path(), &mut report);
                    }
                }
                "map" => {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        Self::analyze_source_map(&content, entry.path(), &mut report);
                    }
                }
                _ => {}
            }
        }

        // Check for scraping patterns
        Self::check_scraping_patterns(root, &mut report);

        report.total_findings = report.cdn_references.len()
            + report.web_fonts.len()
            + report.icon_libraries.len()
            + report.css_frameworks.len()
            + report.embedded_assets.len()
            + report.source_maps.len()
            + report.meta_images.len()
            + report.robots_findings.len();

        report
    }

    // ── HTML Scanning ───────────────────────────────────────────────

    fn scan_html_content(content: &str, file_path: &Path, report: &mut WebAssetReport) {
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let line_lower = line.to_lowercase();

            // CDN script/link references
            Self::extract_cdn_references(line, &line_lower, i + 1, file_path, report);

            // Google Fonts links
            if line_lower.contains("fonts.googleapis.com") || line_lower.contains("fonts.gstatic.com") {
                Self::extract_google_fonts(line, i + 1, file_path, report);
            }

            // Adobe Fonts (Typekit)
            if line_lower.contains("use.typekit.net") || line_lower.contains("use.typekit.com") {
                report.web_fonts.push(WebFontUsage {
                    font_name: "Adobe Fonts (Typekit)".into(),
                    source: FontSource::AdobeFonts,
                    license: Some(FontLicense::Commercial),
                    file_path: file_path.to_path_buf(),
                    line_number: i + 1,
                });
            }

            // Meta image tags
            Self::extract_meta_images(line, &line_lower, file_path, report);

            // Icon library detection in HTML
            Self::detect_icon_usage_html(line, &line_lower, i + 1, file_path, report);

            // Tracking scripts
            Self::detect_tracking_scripts(line, &line_lower, i + 1, file_path, report);
        }
    }

    fn extract_cdn_references(
        line: &str,
        line_lower: &str,
        line_num: usize,
        file_path: &Path,
        report: &mut WebAssetReport,
    ) {
        let cdn_patterns: &[(&str, CdnProvider)] = &[
            ("cdnjs.cloudflare.com", CdnProvider::Cdnjs),
            ("cdn.jsdelivr.net", CdnProvider::JsDelivr),
            ("unpkg.com", CdnProvider::Unpkg),
            ("ajax.googleapis.com", CdnProvider::GoogleCdn),
            ("cdnjs.com", CdnProvider::CloudflareCdn),
            ("maxcdn.bootstrapcdn.com", CdnProvider::BootstrapCdn),
            ("stackpath.bootstrapcdn.com", CdnProvider::StackPathCdn),
            ("code.jquery.com", CdnProvider::JqueryCdn),
            ("ajax.aspnetcdn.com", CdnProvider::MicrosoftCdn),
            ("use.fontawesome.com", CdnProvider::FontAwesomeCdn),
            ("kit.fontawesome.com", CdnProvider::FontAwesomeCdn),
            ("ka-f.fontawesome.com", CdnProvider::FontAwesomeCdn),
        ];

        for &(pattern, provider) in cdn_patterns {
            if line_lower.contains(pattern) {
                // Extract the URL
                let url = Self::extract_url_from_tag(line).unwrap_or_default();
                let lib_name = Self::extract_library_from_cdn_url(&url);
                let version = Self::extract_version_from_cdn_url(&url);
                let integrity = Self::extract_integrity_hash(line);

                let resource_type = if line_lower.contains(".css") || line_lower.contains("stylesheet") {
                    CdnResourceType::Css
                } else if line_lower.contains(".js") || line_lower.contains("script") {
                    CdnResourceType::JavaScript
                } else if line_lower.contains(".woff") || line_lower.contains(".ttf") || line_lower.contains(".otf") {
                    CdnResourceType::Font
                } else {
                    CdnResourceType::Other
                };

                // Look up license
                let license = lib_name.as_deref()
                    .and_then(|name| {
                        CDN_LIBRARY_LICENSES.iter()
                            .find(|&&(lib, _)| name.to_lowercase().contains(lib))
                            .map(|&(_, lic)| lic.to_string())
                    });

                report.cdn_references.push(CdnReference {
                    url,
                    library_name: lib_name,
                    version,
                    cdn_provider: provider,
                    resource_type,
                    license,
                    file_path: file_path.to_path_buf(),
                    line_number: line_num,
                    integrity_hash: integrity,
                });
            }
        }
    }

    fn extract_google_fonts(line: &str, line_num: usize, file_path: &Path, report: &mut WebAssetReport) {
        // Parse font families from Google Fonts URL
        // Format: fonts.googleapis.com/css2?family=Roboto:wght@400;700&family=Inter
        if let Some(url) = Self::extract_url_from_tag(line) {
            // Extract family parameters
            let parts: Vec<&str> = url.split("family=").collect();
            for part in parts.iter().skip(1) {
                let family_raw = part.split('&').next().unwrap_or("");
                let family = family_raw.split(':').next().unwrap_or("")
                    .replace('+', " ");

                if family.is_empty() {
                    continue;
                }

                let license = GOOGLE_FONT_LICENSES.iter()
                    .find(|&&(name, _)| family.to_lowercase() == name.to_lowercase())
                    .map(|&(_, lic)| lic);

                report.web_fonts.push(WebFontUsage {
                    font_name: family,
                    source: FontSource::GoogleFonts,
                    license: license.or(Some(FontLicense::OFL)), // Most Google Fonts are OFL
                    file_path: file_path.to_path_buf(),
                    line_number: line_num,
                });
            }
        }
    }

    fn extract_meta_images(line: &str, line_lower: &str, file_path: &Path, report: &mut WebAssetReport) {
        let meta_patterns = [
            ("og:image", "Open Graph Image"),
            ("twitter:image", "Twitter Card Image"),
            ("apple-touch-icon", "Apple Touch Icon"),
            ("msapplication-tileimage", "MS Tile Image"),
        ];

        for &(pattern, tag_type) in &meta_patterns {
            if line_lower.contains(pattern) {
                if let Some(url) = Self::extract_content_attr(line) {
                    report.meta_images.push(MetaImage {
                        tag_type: tag_type.to_string(),
                        url,
                        file_path: file_path.to_path_buf(),
                    });
                }
            }
        }
    }

    fn detect_icon_usage_html(
        line: &str,
        line_lower: &str,
        line_num: usize,
        file_path: &Path,
        report: &mut WebAssetReport,
    ) {
        let icon_patterns: &[(&str, IconLibrary, IconTier)] = &[
            ("fa-solid", IconLibrary::FontAwesome, IconTier::Free),
            ("fa-regular", IconLibrary::FontAwesome, IconTier::Free),
            ("fa-brands", IconLibrary::FontAwesome, IconTier::Free),
            ("fa-light", IconLibrary::FontAwesome, IconTier::Pro),
            ("fa-thin", IconLibrary::FontAwesome, IconTier::Pro),
            ("fa-duotone", IconLibrary::FontAwesome, IconTier::Pro),
            ("fa-sharp", IconLibrary::FontAwesome, IconTier::Pro),
            ("fas fa-", IconLibrary::FontAwesome, IconTier::Free),
            ("far fa-", IconLibrary::FontAwesome, IconTier::Free),
            ("fab fa-", IconLibrary::FontAwesome, IconTier::Free),
            ("fal fa-", IconLibrary::FontAwesome, IconTier::Pro),
            ("fad fa-", IconLibrary::FontAwesome, IconTier::Pro),
            ("material-icons", IconLibrary::MaterialIcons, IconTier::Free),
            ("material-symbols", IconLibrary::MaterialIcons, IconTier::Free),
            ("bi bi-", IconLibrary::BootstrapIcons, IconTier::Free),
            ("ion-md-", IconLibrary::Ionicons, IconTier::Free),
            ("ion-ios-", IconLibrary::Ionicons, IconTier::Free),
            ("ri-", IconLibrary::RemixIcon, IconTier::Free),
            ("las la-", IconLibrary::LineAwesome, IconTier::Free),
            ("bx bx-", IconLibrary::BoxIcons, IconTier::Free),
        ];

        for &(pattern, library, tier) in icon_patterns {
            if line_lower.contains(pattern) {
                // Check if we already have this library for this file
                let already_found = report.icon_libraries.iter()
                    .any(|il| il.library == library && il.file_path == file_path);
                if !already_found {
                    report.icon_libraries.push(IconLibraryUsage {
                        library,
                        tier,
                        references: 1,
                        file_path: file_path.to_path_buf(),
                    });
                } else {
                    // Increment count and upgrade tier if needed
                    if let Some(existing) = report.icon_libraries.iter_mut()
                        .find(|il| il.library == library && il.file_path == file_path)
                    {
                        existing.references += 1;
                        if tier == IconTier::Pro {
                            existing.tier = IconTier::Pro;
                        }
                    }
                }
            }
        }
        let _ = line_num; // suppress unused warning
        let _ = line; // suppress unused warning
    }

    fn detect_tracking_scripts(
        _line: &str,
        line_lower: &str,
        _line_num: usize,
        file_path: &Path,
        report: &mut WebAssetReport,
    ) {
        let trackers: &[(&str, &str, &str)] = &[
            ("google-analytics.com", "Google Analytics", "Tracks user behavior, requires privacy notice"),
            ("googletagmanager.com", "Google Tag Manager", "Container for tracking scripts, requires privacy notice"),
            ("facebook.net/en_US/fbevents.js", "Facebook Pixel", "Tracks user behavior for ad targeting"),
            ("connect.facebook.net", "Facebook SDK", "Social integration and tracking"),
            ("snap.licdn.com", "LinkedIn Insight", "Professional tracking and retargeting"),
            ("static.hotjar.com", "Hotjar", "Session recording and heatmaps"),
            ("js.hs-scripts.com", "HubSpot", "Marketing automation tracking"),
            ("cdn.segment.com", "Segment", "Data collection and forwarding"),
            ("cdn.mxpnl.com", "Mixpanel", "Product analytics"),
            ("plausible.io", "Plausible", "Privacy-friendly analytics"),
            ("umami.is", "Umami", "Privacy-friendly analytics"),
        ];

        for &(pattern, provider, concern) in trackers {
            if line_lower.contains(pattern) {
                let already_found = report.tracking_scripts.iter()
                    .any(|t| t.provider == provider && t.file_path == file_path);
                if !already_found {
                    report.tracking_scripts.push(TrackingScript {
                        provider: provider.to_string(),
                        script_url: Some(pattern.to_string()),
                        file_path: file_path.to_path_buf(),
                        privacy_concern: concern.to_string(),
                    });
                }
            }
        }
    }

    // ── CSS Scanning ────────────────────────────────────────────────

    fn scan_css_content(content: &str, file_path: &Path, report: &mut WebAssetReport) {
        let lower = content.to_lowercase();

        // @font-face declarations
        Self::extract_font_face_declarations(content, file_path, report);

        // @import url() for CDN resources
        for (i, line) in content.lines().enumerate() {
            if line.to_lowercase().contains("@import") {
                Self::extract_cdn_references(line, &line.to_lowercase(), i + 1, file_path, report);
            }
        }

        // Detect CSS frameworks by their characteristic patterns
        Self::detect_css_framework(content, &lower, file_path, report);

        // Detect embedded Base64 assets
        Self::detect_base64_assets(content, file_path, report);

        // Detect commercial font usage
        Self::detect_commercial_fonts(content, file_path, report);
    }

    fn extract_font_face_declarations(content: &str, file_path: &Path, report: &mut WebAssetReport) {
        let lower = content.to_lowercase();
        let mut pos = 0;

        while let Some(start) = lower[pos..].find("@font-face") {
            let abs_start = pos + start;
            let line_num = content[..abs_start].lines().count();

            // Find the closing brace
            if let Some(end) = lower[abs_start..].find('}') {
                let block = &content[abs_start..abs_start + end + 1];
                let block_lower = block.to_lowercase();

                // Extract font-family
                let font_name = Self::extract_css_value(&block_lower, "font-family")
                    .unwrap_or_else(|| "Unknown".into())
                    .replace('\'', "")
                    .replace('"', "")
                    .trim()
                    .to_string();

                // Determine source
                let source = if block_lower.contains("fonts.googleapis.com") || block_lower.contains("fonts.gstatic.com") {
                    FontSource::GoogleFonts
                } else if block_lower.contains("use.typekit.") {
                    FontSource::AdobeFonts
                } else if block_lower.contains("url(") {
                    let url = Self::extract_css_url_value(&block_lower);
                    FontSource::FontFaceUrl(url.unwrap_or_default())
                } else if block_lower.contains("local(") {
                    FontSource::FontFaceLocal
                } else {
                    FontSource::Bundled
                };

                // Check license
                let license = if source == FontSource::GoogleFonts {
                    Some(FontLicense::OFL)
                } else if source == FontSource::AdobeFonts {
                    Some(FontLicense::Commercial)
                } else if COMMERCIAL_FONTS.iter().any(|f| font_name.to_lowercase().contains(&f.to_lowercase())) {
                    Some(FontLicense::Commercial)
                } else {
                    None
                };

                report.web_fonts.push(WebFontUsage {
                    font_name,
                    source,
                    license,
                    file_path: file_path.to_path_buf(),
                    line_number: line_num,
                });

                pos = abs_start + end + 1;
            } else {
                break;
            }
        }
    }

    fn detect_css_framework(content: &str, lower: &str, file_path: &Path, report: &mut WebAssetReport) {
        let framework_signatures: &[(&str, CssFramework, &str)] = &[
            ("bootstrap", CssFramework::Bootstrap, "MIT"),
            (".container-fluid", CssFramework::Bootstrap, "MIT"),
            ("tailwindcss", CssFramework::Tailwind, "MIT"),
            ("@tailwind", CssFramework::Tailwind, "MIT"),
            ("foundation-", CssFramework::Foundation, "MIT"),
            (".columns", CssFramework::Foundation, "MIT"),
            ("bulma", CssFramework::Bulma, "MIT"),
            (".is-primary", CssFramework::Bulma, "MIT"),
            ("material-components", CssFramework::MaterialDesign, "MIT"),
            ("mdc-", CssFramework::MaterialDesign, "MIT"),
            ("semantic-ui", CssFramework::SemanticUi, "MIT"),
            ("uikit", CssFramework::UIKit, "MIT"),
            ("primer", CssFramework::Primer, "MIT"),
        ];

        for &(signature, framework, license) in framework_signatures {
            if lower.contains(signature) {
                let already = report.css_frameworks.iter()
                    .any(|f| f.framework == framework);
                if !already {
                    // Try to extract version from comment header
                    let version = Self::extract_version_from_comment(content);

                    report.css_frameworks.push(CssFrameworkUsage {
                        framework,
                        version,
                        license: license.to_string(),
                        file_path: file_path.to_path_buf(),
                    });
                }
            }
        }
    }

    fn detect_base64_assets(content: &str, file_path: &Path, report: &mut WebAssetReport) {
        // Find data: URIs with Base64 content
        let patterns = [
            "data:image/png;base64,",
            "data:image/jpeg;base64,",
            "data:image/gif;base64,",
            "data:image/svg+xml;base64,",
            "data:image/webp;base64,",
            "data:font/woff2;base64,",
            "data:font/woff;base64,",
            "data:font/ttf;base64,",
            "data:application/font-woff;base64,",
            "data:application/font-woff2;base64,",
        ];

        let lower = content.to_lowercase();
        for pattern in &patterns {
            let mut start_pos = 0;
            while let Some(pos) = lower[start_pos..].find(pattern) {
                let abs_pos = start_pos + pos;
                let line_num = content[..abs_pos].lines().count();

                // Find end of base64 data
                let data_start = abs_pos + pattern.len();
                let data_end = content[data_start..].find(|c: char| c == '"' || c == '\'' || c == ')')
                    .unwrap_or(content[data_start..].len());
                let data_size = data_end; // Approximate

                // Check for stock photo indicators in surrounding context
                let context_start = abs_pos.saturating_sub(200);
                let context_end = (data_start + 50).min(content.len());
                let context = &lower[context_start..context_end];
                let mut stock_indicators = Vec::new();

                if context.contains("shutterstock") { stock_indicators.push("Shutterstock".into()); }
                if context.contains("gettyimages") { stock_indicators.push("Getty Images".into()); }
                if context.contains("istockphoto") { stock_indicators.push("iStock".into()); }
                if context.contains("stock") { stock_indicators.push("Contains 'stock' keyword".into()); }

                let mime_type = pattern.split(';').next()
                    .unwrap_or("unknown")
                    .replace("data:", "");

                if data_size > 1000 { // Only report non-trivial embedded assets
                    report.embedded_assets.push(EmbeddedAsset {
                        mime_type,
                        size_bytes: data_size * 3 / 4, // Base64 ≈ 4/3 of original
                        encoding: "base64".into(),
                        file_path: file_path.to_path_buf(),
                        line_number: line_num,
                        stock_indicators,
                    });
                }

                start_pos = data_start + data_end;
            }
        }
    }

    fn detect_commercial_fonts(content: &str, file_path: &Path, report: &mut WebAssetReport) {
        let lower = content.to_lowercase();

        for &font in COMMERCIAL_FONTS {
            let font_lower = font.to_lowercase();
            if lower.contains(&font_lower) {
                // Check if it's in a font-family declaration
                if lower.contains(&format!("font-family")) {
                    // Verify it's not just in a comment
                    let is_in_comment = Self::is_in_css_comment(&lower, &font_lower);
                    if !is_in_comment {
                        let line_num = lower.find(&font_lower)
                            .map(|pos| content[..pos].lines().count())
                            .unwrap_or(0);

                        let already = report.web_fonts.iter()
                            .any(|f| f.font_name == font && f.file_path == file_path);
                        if !already {
                            report.web_fonts.push(WebFontUsage {
                                font_name: font.to_string(),
                                source: FontSource::FontFaceLocal,
                                license: Some(FontLicense::Commercial),
                                file_path: file_path.to_path_buf(),
                                line_number: line_num,
                            });
                        }
                    }
                }
            }
        }
    }

    // ── JS Scanning ─────────────────────────────────────────────────

    fn scan_js_content(content: &str, file_path: &Path, report: &mut WebAssetReport) {
        let lower = content.to_lowercase();

        // Detect scraping/crawling libraries
        let scraping_libs = [
            ("puppeteer", "Puppeteer — headless Chrome automation"),
            ("playwright", "Playwright — cross-browser automation"),
            ("cheerio", "Cheerio — server-side HTML parsing"),
            ("jsdom", "jsdom — DOM implementation for Node.js"),
            ("crawler", "Crawler — HTTP crawling library"),
            ("scrapy", "Scrapy-like pattern"),
            ("selenium", "Selenium — browser automation"),
            ("nightmare", "Nightmare — browser automation"),
        ];

        for &(lib, desc) in &scraping_libs {
            if lower.contains(&format!("require('{}'", lib))
                || lower.contains(&format!("require(\"{}\"", lib))
                || lower.contains(&format!("from '{}'", lib))
                || lower.contains(&format!("from \"{}\"", lib))
                || lower.contains(&format!("import '{}'", lib))
                || lower.contains(&format!("import \"{}\"", lib))
            {
                report.robots_findings.push(RobotsFinding {
                    finding_type: RobotsFindingType::UsesScrapingLibrary,
                    description: format!("Uses scraping library: {}", desc),
                    file_path: file_path.to_path_buf(),
                });
            }
        }

        // Check for robots.txt ignoring
        if lower.contains("robots") && (lower.contains("ignore") || lower.contains("bypass") || lower.contains("skip")) {
            report.robots_findings.push(RobotsFinding {
                finding_type: RobotsFindingType::IgnoresRobots,
                description: "Code appears to bypass robots.txt restrictions".into(),
                file_path: file_path.to_path_buf(),
            });
        }

        // Detect CDN references in JS
        for (i, line) in content.lines().enumerate() {
            Self::extract_cdn_references(line, &line.to_lowercase(), i + 1, file_path, report);
        }
    }

    // ── Source Map Analysis ─────────────────────────────────────────

    fn analyze_source_map(content: &str, file_path: &Path, report: &mut WebAssetReport) {
        let json: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return,
        };

        if let Some(sources) = json["sources"].as_array() {
            let source_files: Vec<String> = sources.iter()
                .filter_map(|s| s.as_str())
                .map(|s| s.to_string())
                .collect();

            let third_party: Vec<String> = source_files.iter()
                .filter(|s| {
                    s.contains("node_modules") || s.contains("vendor")
                        || s.contains("bower_components")
                })
                .cloned()
                .collect();

            let total = source_files.len();

            report.source_maps.push(SourceMapAnalysis {
                map_file: file_path.to_path_buf(),
                source_files,
                third_party_sources: third_party,
                total_sources: total,
            });
        }
    }

    // ── Scraping Compliance ─────────────────────────────────────────

    fn check_scraping_patterns(root: &Path, report: &mut WebAssetReport) {
        // If the project contains scraping code but no robots.txt handler
        if !report.robots_findings.is_empty() {
            let has_robots_handler = report.robots_findings.iter()
                .any(|f| f.finding_type != RobotsFindingType::UsesScrapingLibrary);

            if !has_robots_handler {
                // Check if there's any robots.txt handling code
                let has_robots_code = walkdir::WalkDir::new(root)
                    .max_depth(5)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        let ext = e.path().extension().and_then(|e| e.to_str()).unwrap_or("");
                        matches!(ext, "js" | "ts" | "py" | "rs" | "go" | "java" | "rb")
                    })
                    .any(|e| {
                        std::fs::read_to_string(e.path())
                            .map(|c| {
                                let l = c.to_lowercase();
                                l.contains("robots.txt") || l.contains("robotstxt")
                                    || l.contains("robots_parser") || l.contains("robotparser")
                            })
                            .unwrap_or(false)
                    });

                if !has_robots_code {
                    report.robots_findings.push(RobotsFinding {
                        finding_type: RobotsFindingType::ScraperWithoutRobotsCheck,
                        description: "Project uses scraping libraries but has no robots.txt compliance code".into(),
                        file_path: root.to_path_buf(),
                    });
                }
            }
        }
    }

    // ── Utility Methods ─────────────────────────────────────────────

    fn extract_url_from_tag(line: &str) -> Option<String> {
        // Try src="..." or href="..."
        for attr in &["src=\"", "href=\"", "src='", "href='"] {
            if let Some(pos) = line.to_lowercase().find(attr) {
                let start = pos + attr.len();
                let quote = if attr.ends_with('"') { '"' } else { '\'' };
                if let Some(end) = line[start..].find(quote) {
                    return Some(line[start..start + end].to_string());
                }
            }
        }
        None
    }

    fn extract_content_attr(line: &str) -> Option<String> {
        for attr in &["content=\"", "content='"] {
            if let Some(pos) = line.to_lowercase().find(attr) {
                let start = pos + attr.len();
                let quote = if attr.ends_with('"') { '"' } else { '\'' };
                if let Some(end) = line[start..].find(quote) {
                    return Some(line[start..start + end].to_string());
                }
            }
        }
        None
    }

    fn extract_library_from_cdn_url(url: &str) -> Option<String> {
        // Common CDN URL patterns:
        // cdnjs.cloudflare.com/ajax/libs/LIBRARY/VERSION/...
        // cdn.jsdelivr.net/npm/LIBRARY@VERSION/...
        // unpkg.com/LIBRARY@VERSION/...

        let parts: Vec<&str> = url.split('/').collect();

        // cdnjs pattern
        if url.contains("cdnjs.cloudflare.com") && parts.len() > 5 {
            return Some(parts[5].to_string());
        }

        // jsdelivr pattern
        if url.contains("cdn.jsdelivr.net") {
            if let Some(pkg) = parts.iter().find(|p| p.starts_with("npm/") || p.contains('@')) {
                let name = pkg.replace("npm/", "").split('@').next()?.to_string();
                return Some(name);
            }
        }

        // unpkg pattern
        if url.contains("unpkg.com") && parts.len() > 3 {
            let name = parts[3].split('@').next()?.to_string();
            return Some(name);
        }

        None
    }

    fn extract_version_from_cdn_url(url: &str) -> Option<String> {
        // Look for @version or /version/ patterns
        if let Some(at_pos) = url.rfind('@') {
            let after = &url[at_pos + 1..];
            let version = after.split('/').next()?;
            if version.chars().next()?.is_ascii_digit() {
                return Some(version.to_string());
            }
        }

        // cdnjs pattern: .../library/1.2.3/...
        let parts: Vec<&str> = url.split('/').collect();
        for part in &parts {
            if part.chars().next().map_or(false, |c| c.is_ascii_digit())
                && part.contains('.')
            {
                return Some(part.to_string());
            }
        }

        None
    }

    fn extract_integrity_hash(line: &str) -> Option<String> {
        if let Some(pos) = line.to_lowercase().find("integrity=\"") {
            let start = pos + 11;
            if let Some(end) = line[start..].find('"') {
                return Some(line[start..start + end].to_string());
            }
        }
        None
    }

    fn extract_css_value(css: &str, property: &str) -> Option<String> {
        let pattern = format!("{}:", property);
        if let Some(pos) = css.find(&pattern) {
            let after = &css[pos + pattern.len()..];
            let value = after.split(';').next()?.trim().to_string();
            return Some(value);
        }
        None
    }

    fn extract_css_url_value(css: &str) -> Option<String> {
        if let Some(pos) = css.find("url(") {
            let start = pos + 4;
            let end_chars = &[')', '\'', '"'];
            let trimmed = css[start..].trim_start_matches(|c: char| c == '\'' || c == '"');
            let close = trimmed.find(|c: char| end_chars.contains(&c))?;
            return Some(trimmed[..close].to_string());
        }
        None
    }

    fn extract_version_from_comment(content: &str) -> Option<String> {
        // Look for version in CSS header comments: /* ... v5.3.0 ... */
        let header = if content.len() > 500 { &content[..500] } else { content };
        let lower = header.to_lowercase();

        // Pattern: v1.2.3 or version 1.2.3
        for pattern in &["v", "version "] {
            if let Some(pos) = lower.find(pattern) {
                let after = &header[pos + pattern.len()..];
                let version: String = after.chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !version.is_empty() && version.contains('.') {
                    return Some(version);
                }
            }
        }

        None
    }

    fn is_in_css_comment(content: &str, target: &str) -> bool {
        if let Some(pos) = content.find(target) {
            // Check if we're between /* and */
            let before = &content[..pos];
            let last_open = before.rfind("/*");
            let last_close = before.rfind("*/");

            match (last_open, last_close) {
                (Some(open), Some(close)) => open > close,
                (Some(_), None) => true,
                _ => false,
            }
        } else {
            false
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_url_from_tag() {
        assert_eq!(
            WebAssetScanner::extract_url_from_tag(
                r#"<script src="https://cdn.jsdelivr.net/npm/vue@3"></script>"#
            ),
            Some("https://cdn.jsdelivr.net/npm/vue@3".into())
        );
    }

    #[test]
    fn test_extract_library_from_cdn() {
        assert_eq!(
            WebAssetScanner::extract_library_from_cdn_url(
                "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"
            ),
            Some("lodash.js".into())
        );
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(
            WebAssetScanner::extract_version_from_cdn_url(
                "https://cdn.jsdelivr.net/npm/vue@3.3.4/dist/vue.global.js"
            ),
            Some("3.3.4".into())
        );
    }

    #[test]
    fn test_version_pinned() {
        assert!(WebAssetScanner::extract_version_from_cdn_url(
            "https://unpkg.com/react@18.2.0/umd/react.production.min.js"
        ).is_some());
    }

    #[test]
    fn test_css_comment_detection() {
        assert!(WebAssetScanner::is_in_css_comment(
            "/* using helvetica */ .body { font: sans-serif; }",
            "helvetica"
        ));
        assert!(!WebAssetScanner::is_in_css_comment(
            "/* comment */ .body { font-family: helvetica; }",
            "helvetica"
        ));
    }
}
