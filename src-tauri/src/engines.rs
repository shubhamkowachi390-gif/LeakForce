use crate::models::Settings;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct EnginePaths {
    pub python: String,
    pub engine_script: PathBuf,
    pub java: String,
    pub jar: PathBuf,
    pub wordlist: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub python_ok: bool,
    pub python_version: String,
    pub java_ok: bool,
    pub java_version: String,
    pub engine_ok: bool,
    pub engine_path: String,
    pub jar_ok: bool,
    pub jar_path: String,
    pub wordlist_ok: bool,
    pub wordlist_path: String,
    pub ready: bool,
}

fn first_existing(candidates: Vec<PathBuf>) -> PathBuf {
    if let Some(found) = candidates.iter().find(|path| path.exists()) {
        return found.clone();
    }
    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Tauri's resource directory is canonicalized and can start with the Windows
/// extended-length prefix `\\?\`. Python accepts it, but `java -jar` does not,
/// so strip it before the path is used by any external engine.
fn simplify_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

/// True when the configured value is a bare command name (resolved via PATH)
/// rather than an explicit file path.
fn is_bare_command(value: &str) -> bool {
    !value.contains('\\') && !value.contains('/')
}

/// Find a bare executable name on PATH, trying Windows executable extensions.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let extensions: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        if dir
            .to_string_lossy()
            .to_lowercase()
            .contains("windowsapps")
        {
            // Microsoft Store app-execution aliases are not real interpreters.
            continue;
        }
        for extension in extensions {
            let candidate = dir.join(format!("{name}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Find a java.exe in JAVA_HOME, on PATH, or in common JDK install folders.
fn find_java() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("JAVA_HOME") {
        let candidate = PathBuf::from(home).join("bin").join("java.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Some(found) = find_on_path("java") {
        return Some(found);
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    for key in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(value) = std::env::var_os(key) {
            roots.push(PathBuf::from(value));
        }
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local).join("Programs"));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        roots.push(PathBuf::from(profile).join(".jdks"));
    }

    let vendors = [
        "Eclipse Adoptium",
        "Java",
        "Microsoft",
        "Amazon Corretto",
        "Zulu",
        "BellSoft",
        "Semeru",
    ];
    let mut found: Vec<PathBuf> = Vec::new();
    for root in &roots {
        for vendor in vendors {
            let base = root.join(vendor);
            let Ok(entries) = std::fs::read_dir(&base) else {
                continue;
            };
            for entry in entries.flatten() {
                let candidate = entry.path().join("bin").join("java.exe");
                if candidate.is_file() {
                    found.push(candidate);
                }
            }
        }
    }
    // A few portable tool folders used by developers.
    for base in [PathBuf::from("C:\\tools")] {
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                if name.starts_with("jdk") || name.starts_with("java") {
                    let candidate = entry.path().join("bin").join("java.exe");
                    if candidate.is_file() {
                        found.push(candidate);
                    }
                }
            }
        }
    }
    found.sort();
    found.pop()
}

/// Find python.exe on PATH or in common Python install folders.
fn find_python() -> Option<PathBuf> {
    if let Some(found) = find_on_path("python") {
        return Some(found);
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local).join("Programs").join("Python"));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        roots.push(PathBuf::from(program_files));
    }
    roots.push(PathBuf::from("C:\\"));

    let mut found: Vec<PathBuf> = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if !name.starts_with("python") {
                continue;
            }
            let candidate = entry.path().join("python.exe");
            if candidate.is_file() {
                found.push(candidate);
            }
        }
    }
    found.sort();
    found.pop()
}

fn resolve_executable(
    configured: &str,
    default_name: &str,
    fallback: fn() -> Option<PathBuf>,
) -> String {
    let configured = configured.trim();
    if !configured.is_empty() {
        if !is_bare_command(configured) {
            return configured.to_string();
        }
        if let Some(found) = find_on_path(configured) {
            return found.display().to_string();
        }
    }
    if let Some(found) = fallback() {
        return found.display().to_string();
    }
    if configured.is_empty() {
        default_name.to_string()
    } else {
        configured.to_string()
    }
}

pub fn resolve_paths(settings: &Settings, resource_dir: &Path, exe_dir: &Path) -> EnginePaths {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let project_dir = manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_dir.to_path_buf());

    let engine_script = if settings.python_engine_override.trim().is_empty() {
        first_existing(vec![
            resource_dir.join("python-engine").join("leakforce_engine.py"),
            exe_dir.join("python-engine").join("leakforce_engine.py"),
            project_dir
                .join("python-engine")
                .join("leakforce_engine.py"),
        ])
    } else {
        PathBuf::from(settings.python_engine_override.trim())
    };

    let jar = if settings.java_worker_override.trim().is_empty() {
        first_existing(vec![
            resource_dir
                .join("java-worker")
                .join("LeakForceWorker.jar"),
            exe_dir.join("java-worker").join("LeakForceWorker.jar"),
            project_dir
                .join("java-worker")
                .join("build")
                .join("LeakForceWorker.jar"),
        ])
    } else {
        PathBuf::from(settings.java_worker_override.trim())
    };

    let wordlist = if settings.wordlist_path.trim().is_empty() {
        first_existing(vec![
            resource_dir
                .join("wordlists")
                .join("top1000-passwords.txt"),
            exe_dir
                .join("wordlists")
                .join("top1000-passwords.txt"),
            project_dir
                .join("wordlists")
                .join("top1000-passwords.txt"),
        ])
    } else {
        PathBuf::from(settings.wordlist_path.trim())
    };

    EnginePaths {
        python: resolve_executable(&settings.python_executable, "python", find_python),
        engine_script: simplify_path(engine_script),
        java: resolve_executable(&settings.java_executable, "java", find_java),
        jar: simplify_path(jar),
        wordlist: simplify_path(wordlist),
    }
}

async fn version_of(program: &str, flag: &str) -> (bool, String) {
    let mut command = tokio::process::Command::new(program);
    command
        .arg(flag)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    match tokio::time::timeout(Duration::from_secs(8), command.output()).await {
        Ok(Ok(output)) => {
            let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stderr.is_empty() {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(&stderr);
            }
            let first_line = text.lines().next().unwrap_or("").trim().to_string();
            let version = if first_line.len() > 160 {
                first_line[..160].to_string()
            } else {
                first_line
            };
            if output.status.success() {
                (true, version)
            } else {
                (
                    false,
                    if version.is_empty() {
                        format!("Exited with {}", output.status)
                    } else {
                        version
                    },
                )
            }
        }
        Ok(Err(error)) => (false, format!("Not found / could not run: {error}")),
        Err(_) => (false, "Timed out while checking version".to_string()),
    }
}

pub async fn check_engines(paths: &EnginePaths) -> EngineStatus {
    let (python_ok, python_version) = version_of(&paths.python, "--version").await;
    let (java_ok, java_version) = version_of(&paths.java, "-version").await;
    let engine_ok = paths.engine_script.is_file();
    let jar_ok = paths.jar.is_file();
    let wordlist_ok = paths.wordlist.is_file();

    EngineStatus {
        python_ok,
        python_version,
        java_ok,
        java_version,
        engine_ok,
        engine_path: paths.engine_script.display().to_string(),
        jar_ok,
        jar_path: paths.jar.display().to_string(),
        wordlist_ok,
        wordlist_path: paths.wordlist.display().to_string(),
        ready: python_ok && java_ok && engine_ok && jar_ok && wordlist_ok,
    }
}
