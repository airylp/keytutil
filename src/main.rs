// En Windows, sin ventana de consola junto a la app.
#![cfg_attr(windows, windows_subsystem = "windows")]
// Primero: sus macros t!/tf! se usan en todos los demás módulos.
#[macro_use]
mod i18n;
mod app;
mod cert;
mod diag;
mod estilo;
mod fetch;
mod icon;
mod icons;
mod java;
mod keystore;
mod store;
mod update;

/// Identidad de keyutil para los módulos comunes (logotipo, «Acerca de»…).
pub const APP: icon::Marca = icon::Marca {
    nombre: "keyutil",
    descripcion: || t!("Certificados de confianza de Java (cacerts)"),
    letra: icon::LETRA_K,
    color: icon::MORADO,
    hecho_con: "Rust · egui / eframe · rustls · x509-parser",
};

fn main() -> eframe::Result {
    let args: Vec<std::path::PathBuf> = std::env::args_os().skip(1).map(Into::into).collect();
    // Empaquetado: `keyutil --iconset carpeta` (macOS) y `keyutil --ico archivo.ico` (Windows).
    match args.first().and_then(|a| a.to_str()) {
        Some("--iconset") => {
            let dir = args.get(1).cloned().unwrap_or_else(|| "keyutil.iconset".into());
            icon::write_iconset(&dir).expect("no se pudo escribir el iconset");
            return Ok(());
        }
        Some("--ico") => {
            let path = args.get(1).cloned().unwrap_or_else(|| "keyutil.ico".into());
            std::fs::write(&path, icon::ico()).expect("no se pudo escribir el .ico");
            return Ok(());
        }
        _ => {}
    }
    // `keyutil archivo`: abre ese almacén (o certificado, para agregarlo).
    let open = args.first().filter(|p| p.is_file()).cloned();
    // En modo captura (pruebas) la ventana no se activa: no roba el teclado.
    let testing = std::env::var_os("KEYUTIL_SCREENSHOT").is_some();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_active(!testing)
            .with_title("keyutil")
            .with_app_id("keyutil")
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([760.0, 460.0])
            .with_drag_and_drop(true)
            .with_icon(std::sync::Arc::new(icon::app_icon())),
        persist_window: !testing,
        ..Default::default()
    };
    estilo::arrancar("keyutil", options, Box::new(move |cc| Ok(Box::new(app::App::new(cc, open)))))
}
