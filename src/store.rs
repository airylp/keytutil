//! Configuración de keyutil: sesión (idioma, tema, almacenes recientes) y
//! copias de seguridad de los almacenes antes de sobrescribirlos.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// Carpeta de configuración: `~/Library/Application Support/keyutil`
/// (macOS), `%APPDATA%\keyutil` (Windows) o `~/.config/keyutil`.
pub fn config_dir() -> Option<PathBuf> {
    let env = |k| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Application Support"))
    } else if cfg!(windows) {
        env("APPDATA")
    } else {
        env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")))
    };
    let base = base?;
    let dir = base.join("keyutil");
    // Hasta la 0.1.3 la app se llamaba «keytutil»: se conserva su configuración.
    let vieja = base.join("keytutil");
    if !dir.exists() && vieja.is_dir() {
        let _ = std::fs::rename(&vieja, &dir);
    }
    Some(dir)
}

/// Copias de los almacenes tal como estaban antes de guardarlos.
pub fn backups_dir() -> Option<PathBuf> {
    Some(config_dir()?.join("respaldos"))
}

/// Cuántas copias se conservan (las más viejas se borran).
const MAX_BACKUPS: usize = 30;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "idioma", default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(rename = "tema", default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
    /// Avisar de versiones nuevas (mira GitHub al abrir y cada 6 horas); `None` = sí.
    #[serde(rename = "buscar_actualizaciones", default, skip_serializing_if = "Option::is_none")]
    pub check_updates: Option<bool>,
    /// Copia del original antes de cada guardado; `None` = sí.
    #[serde(rename = "respaldar", default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<bool>,
    /// Almacenes abiertos hace poco (el primero, el último).
    #[serde(rename = "recientes", default, skip_serializing_if = "Vec::is_empty")]
    pub recent: Vec<PathBuf>,
    /// Último servidor consultado (para no volver a escribirlo).
    #[serde(rename = "ultimo_servidor", default, skip_serializing_if = "Option::is_none")]
    pub last_server: Option<String>,
    /// Colores de la lista de certificados («#rrggbb»); `None` = los del tema.
    #[serde(rename = "lista_fondo", default, skip_serializing_if = "Option::is_none")]
    pub list_bg: Option<String>,
    #[serde(rename = "lista_letra", default, skip_serializing_if = "Option::is_none")]
    pub list_fg: Option<String>,
}

/// «#rrggbb» → RGB.
pub fn parse_hex(s: &str) -> Option<[u8; 3]> {
    let h = s.trim().trim_start_matches('#');
    if h.len() != 6 {
        return None;
    }
    let v = u32::from_str_radix(h, 16).ok()?;
    Some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

pub fn to_hex(c: [u8; 3]) -> String {
    format!("#{:02x}{:02x}{:02x}", c[0], c[1], c[2])
}

impl Session {
    pub fn add_recent(&mut self, p: &Path) {
        self.recent.retain(|r| r != p);
        self.recent.insert(0, p.to_path_buf());
        self.recent.truncate(8);
    }
}

fn bad(e: impl ToString) -> io::Error {
    io::Error::other(e.to_string())
}

fn session_path() -> Option<PathBuf> {
    Some(config_dir()?.join("sesion.toml"))
}

pub fn load_session() -> Session {
    session_path().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| toml::from_str(&s).ok()).unwrap_or_default()
}

pub fn save_session(s: &Session) -> io::Result<()> {
    let p = session_path().ok_or_else(|| bad("sin carpeta de configuración"))?;
    write_atomic(&p, toml::to_string_pretty(s).map_err(bad)?.as_bytes())
}

/// Escribe en un temporal junto al destino y lo renombra: nunca queda un
/// archivo a medias.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    // Conservar los permisos del original (p. ej. un cacerts de solo lectura para otros).
    if let Ok(m) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, m.permissions());
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Guarda el almacén: escritura atómica si se puede crear un temporal en su
/// carpeta; si no (carpeta ajena pero archivo con permiso), directamente.
pub fn save_file(path: &Path, data: &[u8]) -> io::Result<()> {
    match write_atomic(path, data) {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && path.is_file() => std::fs::write(path, data),
        r => r,
    }
}

/// Guarda una copia de `bytes` (el original de `path`) en la carpeta de
/// respaldos y devuelve su ruta.
pub fn backup(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    let dir = backups_dir().ok_or_else(|| bad("sin carpeta de configuración"))?;
    std::fs::create_dir_all(&dir)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "almacen".into());
    let dest = dir.join(format!("{}-{name}", crate::cert::stamp_now()));
    std::fs::write(&dest, bytes)?;
    // Solo las más recientes (el nombre empieza por la fecha: orden alfabético = cronológico).
    let mut all: Vec<PathBuf> = std::fs::read_dir(&dir)?.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
    all.sort();
    if all.len() > MAX_BACKUPS {
        for old in &all[..all.len() - MAX_BACKUPS] {
            let _ = std::fs::remove_file(old);
        }
    }
    Ok(dest)
}

/// Escribe `data` en `dest` con permisos de administrador (el cacerts de un
/// JDK instalado en el sistema suele ser de root): pkexec en Linux, la
/// ventana de contraseña de macOS o el aviso de UAC en Windows. Bloquea hasta
/// que termina (llamar desde un hilo aparte). Comprueba el resultado leyendo
/// el destino.
pub fn write_elevated(dest: &Path, data: &[u8]) -> Result<(), String> {
    use std::process::Command;
    let tmp = std::env::temp_dir().join(format!("keyutil-{}-{}", std::process::id(), crate::cert::stamp_now()));
    std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
    let status = if cfg!(target_os = "macos") {
        let q = |p: &Path| p.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "do shell script \"cat \" & quoted form of \"{}\" & \" > \" & quoted form of \"{}\" with administrator privileges",
            q(&tmp),
            q(dest)
        );
        Command::new("osascript").args(["-e", &script]).status()
    } else if cfg!(windows) {
        let e = |p: &Path| p.display().to_string().replace('\'', "''");
        let ps = format!(
            "Start-Process -Verb RunAs -Wait -WindowStyle Hidden -FilePath cmd.exe -ArgumentList '/c','copy','/y','\"{}\"','\"{}\"'",
            e(&tmp),
            e(dest)
        );
        let mut c = Command::new("powershell");
        c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        c.status()
    } else {
        // `cat >` en vez de `cp`: conserva dueño y permisos del archivo de destino.
        Command::new("pkexec").args(["/bin/sh", "-c", "cat \"$1\" > \"$2\"", "sh"]).arg(&tmp).arg(dest).status()
    };
    let _ = std::fs::remove_file(&tmp);
    match status {
        Err(e) => Err(tf!("no se pudo pedir permisos de administrador: {e}", e = e)),
        Ok(_) if std::fs::read(dest).is_ok_and(|b| b == data) => Ok(()),
        Ok(_) => Err(t!("no se guardó (¿se canceló la contraseña de administrador?)").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_colors() {
        assert_eq!(parse_hex("#0f172a"), Some([0x0f, 0x17, 0x2a]));
        assert_eq!(parse_hex("FFFBEB"), Some([0xff, 0xfb, 0xeb]));
        assert_eq!(parse_hex("#fff"), None);
        assert_eq!(parse_hex("#zzzzzz"), None);
        assert_eq!(to_hex([0x1e, 0x3a, 0x8a]), "#1e3a8a");
    }

    #[test]
    fn recent_list_moves_to_front() {
        let mut s = Session::default();
        for p in ["/a", "/b", "/a"] {
            s.add_recent(Path::new(p));
        }
        assert_eq!(s.recent, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
        let t = toml::to_string_pretty(&s).unwrap();
        assert_eq!(toml::from_str::<Session>(&t).unwrap(), s);
    }

    #[test]
    fn atomic_write_keeps_permissions() {
        let d = std::env::temp_dir().join(format!("keyutil-test-escribir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let f = d.join("cacerts");
        write_atomic(&f, b"uno").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
            write_atomic(&f, b"dos").unwrap();
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o640);
        }
        assert_eq!(std::fs::read(&f).unwrap(), b"dos");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1, "quedó un temporal");
        let _ = std::fs::remove_dir_all(&d);
    }
}
