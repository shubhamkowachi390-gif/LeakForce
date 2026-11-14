use crate::models::{HistoryEntry, Settings};
use std::fs;
use std::path::{Path, PathBuf};

pub fn load_settings(data_dir: &Path) -> Settings {
    let path = data_dir.join("settings.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Settings>(&text).ok())
        .unwrap_or_default()
        .sanitized()
}

pub fn save_settings(data_dir: &Path, settings: &Settings) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|error| error.to_string())?;
    let text = serde_json::to_string_pretty(settings).map_err(|error| error.to_string())?;
    fs::write(data_dir.join("settings.json"), text).map_err(|error| error.to_string())
}

pub fn load_history(data_dir: &Path) -> Vec<HistoryEntry> {
    let path = data_dir.join("history.json");
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<HistoryEntry>>(&text).ok())
        .unwrap_or_default()
}

pub fn save_history(data_dir: &Path, history: &[HistoryEntry]) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|error| error.to_string())?;
    let text = serde_json::to_string_pretty(history).map_err(|error| error.to_string())?;
    fs::write(data_dir.join("history.json"), text).map_err(|error| error.to_string())
}

pub fn push_history(data_dir: &Path, history: &mut Vec<HistoryEntry>, entry: HistoryEntry) {
    history.insert(0, entry);
    history.truncate(20);
    if let Err(error) = save_history(data_dir, history) {
        eprintln!("Could not save history: {error}");
    }
}

pub fn downloads_dir() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let candidate = PathBuf::from(profile).join("Downloads");
        if candidate.exists() {
            return candidate;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let candidate = PathBuf::from(home).join("Downloads");
        if candidate.exists() {
            return candidate;
        }
    }
    std::env::temp_dir()
}

pub fn exports_dir() -> PathBuf {
    downloads_dir().join("LeakForce")
}

pub fn slugify(target: &str) -> String {
    let host = url::Url::parse(target)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?.to_string();
            let port = url.port().map(|port| format!("-{port}")).unwrap_or_default();
            Some(format!("{host}{port}"))
        })
        .unwrap_or_else(|| target.to_string());

    let mut slug = String::new();
    for character in host.chars() {
        if character.is_ascii_alphanumeric() || character == '-' || character == '.' {
            slug.push(character);
        } else if character == ':' || character == '/' || character == ' ' {
            slug.push('-');
        }
        if slug.len() >= 60 {
            break;
        }
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "target".to_string()
    } else {
        slug
    }
}

pub fn timestamp_for_file() -> String {
    chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()
}

pub fn now_rfc3339() -> String {
    chrono::Local::now().to_rfc3339()
}
