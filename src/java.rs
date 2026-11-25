//! Busca los `cacerts` de los Java instalados (JAVA_HOME, carpetas habituales
//! de cada sistema, SDKMAN, IntelliJ, Gradle…).

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    /// Nombre para el menú: carpeta del JDK y versión.
    pub label: String,
    pub path: PathBuf,
    /// Otros JDK que usan el mismo archivo (enlaces, p. ej. Debian/Ubuntu).
    pub shared: Vec<String>,
}

/// `cacerts` dentro de un JDK/JRE (Java 9+: lib/security; Java 8: jre/lib/security).
fn in_home(home: &Path) -> Option<PathBuf> {
    ["lib/security/cacerts", "jre/lib/security/cacerts"].iter().map(|r| home.join(r)).find(|p| p.is_file())
}

/// Versión del archivo `release` del JDK (`JAVA_VERSION="21.0.5"`).
fn version(home: &Path) -> Option<String> {
    let s = std::fs::read_to_string(home.join("release")).ok()?;
    let l = s.lines().find(|l| l.starts_with("JAVA_VERSION="))?;
    Some(l["JAVA_VERSION=".len()..].trim_matches('"').to_string())
}

fn children(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect()).unwrap_or_default();
    v.sort();
    v
}

/// Carpetas donde buscar JDKs (cada hija puede ser un JDK).
fn roots() -> Vec<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap_or_default();
    let mut r = vec![
        home.join(".sdkman/candidates/java"),
        home.join(".jdks"),
        home.join(".gradle/jdks"),
        home.join(".asdf/installs/java"),
        home.join(".local/share/mise/installs/java"),
    ];
    if cfg!(target_os = "macos") {
        for base in [PathBuf::from("/Library/Java/JavaVirtualMachines"), home.join("Library/Java/JavaVirtualMachines")] {
            for c in children(&base) {
                r.push(c.join("Contents")); // …/X.jdk/Contents/Home
            }
        }
        r.push("/opt/homebrew/opt".into());
        r.push("/usr/local/opt".into());
    } else if cfg!(windows) {
        for pf in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(p) = std::env::var_os(pf).map(PathBuf::from) {
                for v in ["Java", "Eclipse Adoptium", "Eclipse Foundation", "Microsoft", "Zulu", "Amazon Corretto", "BellSoft", "Semeru", "AdoptOpenJDK", "RedHat"] {
                    r.push(p.join(v));
                }
            }
        }
    } else {
        r.extend(["/usr/lib/jvm", "/usr/java", "/opt", "/opt/java", "/usr/local"].map(PathBuf::from));
    }
    r
}

/// Todos los cacerts encontrados, sin repetir (por ruta real).
pub fn find() -> Vec<Found> {
    let mut homes: Vec<PathBuf> = Vec::new();
    for var in ["JAVA_HOME", "JDK_HOME"] {
        if let Some(h) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            homes.push(h.into());
        }
    }
    for root in roots() {
        for c in children(&root) {
            homes.push(c.join("Home")); // macOS (…/Contents/Home) y Homebrew (openjdk/libexec/…)
            homes.push(c.join("libexec/openjdk.jdk/Contents/Home"));
            homes.push(c);
        }
    }
    let mut out: Vec<Found> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut links: Vec<bool> = Vec::new();
    for h in homes {
        let Some(file) = in_home(&h) else { continue };
        let real = std::fs::canonicalize(&file).unwrap_or(file.clone());
        let name = h.components().rev().map(|c| c.as_os_str().to_string_lossy().into_owned()).find(|n| !["Home", "Contents", "jre"].contains(&n.as_str())).unwrap_or_default();
        let label = match version(&h) {
            Some(v) if !name.contains(&v) => format!("{name} ({v})"),
            _ => name,
        };
        let is_link = real != file;
        if let Some(i) = seen.iter().position(|s| *s == real) {
            let mut label = label;
            // El nombre principal es el del JDK que tiene el archivo de verdad (no un enlace).
            if !is_link && links[i] {
                std::mem::swap(&mut out[i].label, &mut label);
                links[i] = false;
            }
            if out[i].label != label && !out[i].shared.contains(&label) {
                out[i].shared.push(label);
            }
            continue;
        }
        links.push(is_link);
        seen.push(real.clone());
        // Si es un enlace (Debian: /etc/ssl/certs/java/cacerts), se muestra el archivo real.
        out.push(Found { label, path: real, shared: vec![] });
    }
    // Linux: el cacerts del sistema aunque ningún JDK lo enlace.
    let system = PathBuf::from("/etc/ssl/certs/java/cacerts");
    if cfg!(target_os = "linux") && system.is_file() && !seen.iter().any(|s| *s == system) {
        out.push(Found { label: t!("Sistema (ca-certificates-java)").into(), path: system, shared: vec![] });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_jdks_in_folder_and_dedupes_links() {
        let d = std::env::temp_dir().join(format!("keyutil-test-java-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let a = d.join(".jdks/temurin-21");
        std::fs::create_dir_all(a.join("lib/security")).unwrap();
        std::fs::write(a.join("lib/security/cacerts"), b"x").unwrap();
        std::fs::write(a.join("release"), "JAVA_VERSION=\"21.0.5\"\n").unwrap();
        let b = d.join(".jdks/jdk8");
        std::fs::create_dir_all(b.join("jre/lib/security")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(a.join("lib/security/cacerts"), b.join("jre/lib/security/cacerts")).unwrap();
        // SAFETY: prueba de un solo hilo para esta variable; ninguna otra prueba usa HOME.
        let old = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &d) };
        let found = find();
        match old {
            Some(o) => unsafe { std::env::set_var("HOME", o) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        let mine: Vec<_> = found.iter().filter(|f| f.path.starts_with(&d)).collect();
        assert_eq!(mine.len(), 1, "{found:?}");
        assert_eq!(mine[0].label, "temurin-21 (21.0.5)");
        #[cfg(unix)]
        assert_eq!(mine[0].shared, vec!["jdk8".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
