//! En Windows mete en el `.exe` el ícono (`windows/keytutil.ico`) y los datos
//! de versión que muestra el Explorador. En macOS y Linux no hace nada.

fn main() {
    println!("cargo:rerun-if-changed=windows/keytutil.ico");
    println!("cargo:rerun-if-env-changed=KEYTUTIL_COMMIT");
    println!("cargo:rerun-if-env-changed=KEYTUTIL_VERSION");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("windows/keytutil.ico")
            .set("ProductName", "keytutil")
            .set("FileDescription", "keytutil")
            .set("CompanyName", "airylp")
            .set("LegalCopyright", "MIT");
        if let Err(e) = res.compile() {
            println!("cargo:warning=no se pudo añadir el ícono al .exe: {e}");
        }
    }
}
