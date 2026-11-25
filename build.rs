//! En Windows mete en el `.exe` el ícono (`windows/keyutil.ico`) y los datos
//! de versión que muestra el Explorador. En macOS y Linux no hace nada.

fn main() {
    println!("cargo:rerun-if-changed=windows/keyutil.ico");
    println!("cargo:rerun-if-env-changed=KEYUTIL_COMMIT");
    println!("cargo:rerun-if-env-changed=KEYUTIL_VERSION");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("windows/keyutil.ico")
            .set("ProductName", "keyutil")
            .set("FileDescription", "keyutil")
            .set("CompanyName", "airylp")
            .set("LegalCopyright", "MIT");
        if let Err(e) = res.compile() {
            println!("cargo:warning=no se pudo añadir el ícono al .exe: {e}");
        }
    }
}
