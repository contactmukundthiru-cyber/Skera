//! Web crawler — downloads all assets from a live website for scanning
//!
//! Points Skera at any URL and it crawls the page, downloading:
//! - All JavaScript files (inline + external)
//! - All CSS files (inline + external)
//! - All fonts referenced in CSS
//! - All images
//! - WASM modules
//! - Source maps (.map files)

use std::path::PathBuf;

/// Result from crawling a website
pub struct CrawlResult {
    /// Directory containing downloaded files
    pub output_dir: PathBuf,
    /// Number of files downloaded
    pub files_downloaded: usize,
    /// Total bytes downloaded
    pub total_bytes: u64,
    /// Content types found
    pub content_types: Vec<String>,
    /// Temp directory handle
    pub _temp_dir: tempfile::TempDir,
}

/// Crawl a website and download all assets
pub async fn crawl(url: &str) -> Result<CrawlResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let output_dir = temp_dir.path().join("site");
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create output dir: {}", e))?;

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    // Download the main page
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {} for {}", response.status(), url));
    }

    let html = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Save the HTML
    let html_path = output_dir.join("index.html");
    std::fs::write(&html_path, &html)
        .map_err(|e| format!("Failed to write HTML: {}", e))?;

    let mut files_downloaded = 1u64;
    let mut total_bytes = html.len() as u64;
    let mut content_types = vec!["text/html".to_string()];

    // Extract and download all linked resources
    let base_url = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    // Extract script src and link href attributes
    let src_regex = regex::Regex::new(r#"(?:src|href)\s*=\s*["']([^"']+)["']"#).unwrap();
    let css_url_regex = regex::Regex::new(r#"url\s*\(\s*["']?([^"')]+)["']?\s*\)"#).unwrap();

    let mut urls_to_download: Vec<(String, String)> = Vec::new(); // (url, category)

    for cap in src_regex.captures_iter(&html) {
        let resource_url = cap.get(1).unwrap().as_str();
        let full_url = base_url.join(resource_url)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| resource_url.to_string());

        let category = if resource_url.ends_with(".js") || resource_url.ends_with(".mjs") {
            "js"
        } else if resource_url.ends_with(".css") {
            "css"
        } else if resource_url.ends_with(".wasm") {
            "wasm"
        } else if resource_url.ends_with(".map") {
            "sourcemap"
        } else if resource_url.ends_with(".woff2") || resource_url.ends_with(".woff")
            || resource_url.ends_with(".ttf") || resource_url.ends_with(".otf") {
            "font"
        } else if resource_url.ends_with(".png") || resource_url.ends_with(".jpg")
            || resource_url.ends_with(".gif") || resource_url.ends_with(".svg")
            || resource_url.ends_with(".webp") || resource_url.ends_with(".ico") {
            "image"
        } else {
            "other"
        };

        urls_to_download.push((full_url, category.to_string()));
    }

    // Download each resource
    for (resource_url, category) in &urls_to_download {
        if let Ok(resp) = client.get(resource_url).send().await {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes().await {
                    // Derive filename from URL
                    let filename = resource_url
                        .split('/')
                        .last()
                        .unwrap_or("resource")
                        .split('?')
                        .next()
                        .unwrap_or("resource");

                    let category_dir = output_dir.join(category);
                    let _ = std::fs::create_dir_all(&category_dir);

                    let file_path = category_dir.join(filename);
                    if std::fs::write(&file_path, &bytes).is_ok() {
                        files_downloaded += 1;
                        total_bytes += bytes.len() as u64;

                        if !content_types.contains(category) {
                            content_types.push(category.clone());
                        }

                        // If it's CSS, also extract font/image URLs from it
                        if category == "css" {
                            if let Ok(css_text) = String::from_utf8(bytes.to_vec()) {
                                for cap in css_url_regex.captures_iter(&css_text) {
                                    let css_resource = cap.get(1).unwrap().as_str();
                                    if let Ok(full) = base_url.join(css_resource) {
                                        let cat = if css_resource.contains(".woff")
                                            || css_resource.contains(".ttf")
                                            || css_resource.contains(".otf")
                                        {
                                            "font"
                                        } else {
                                            "image"
                                        };

                                        if let Ok(r) = client.get(full.as_str()).send().await {
                                            if let Ok(b) = r.bytes().await {
                                                let fname = css_resource
                                                    .split('/')
                                                    .last()
                                                    .unwrap_or("asset")
                                                    .split('?')
                                                    .next()
                                                    .unwrap_or("asset");
                                                let cat_dir = output_dir.join(cat);
                                                let _ = std::fs::create_dir_all(&cat_dir);
                                                if std::fs::write(cat_dir.join(fname), &b).is_ok() {
                                                    files_downloaded += 1;
                                                    total_bytes += b.len() as u64;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(CrawlResult {
        output_dir,
        files_downloaded: files_downloaded as usize,
        total_bytes,
        content_types,
        _temp_dir: temp_dir,
    })
}
