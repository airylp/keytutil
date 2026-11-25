//! Interfaz: lista de certificados del almacén abierto (con buscador y
//! casillas para actuar sobre varios), detalle del elegido a la derecha y la
//! ventana «Agregar certificados» (de un servidor o de un archivo/texto).

use crate::cert::{self, CertInfo};
use crate::diag::{self, Chain, Origin};
use crate::fetch::{self, Protocol};
use crate::icons::{Icon, IconButton, Tone};
use crate::keystore::{Format, Keystore, Kind, OpenError};
use crate::estilo::Paleta;
use crate::store::{self, Session};
use eframe::egui::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Avisar de que un certificado vence pronto (días).
const SOON_DAYS: i64 = 30;
const ROW_H: f32 = 26.0;

/// El almacén abierto.
struct Doc {
    /// `None`: nuevo, aún sin archivo.
    path: Option<PathBuf>,
    ks: Keystore,
    password: String,
    /// Contenido del archivo al abrirlo o guardarlo (para la copia de seguridad).
    original: Option<Vec<u8>>,
    dirty: bool,
    /// Cambia con cada modificación (para recalcular lo que dependa del contenido).
    rev: u64,
    /// Texto de búsqueda de cada entrada (en minúsculas), por índice.
    hay: Vec<String>,
    /// Alias (en minúsculas) agregados desde que se abrió: se pintan de otro color.
    added: BTreeSet<String>,
}

impl Doc {
    fn new(path: Option<PathBuf>, ks: Keystore, password: String, original: Option<Vec<u8>>) -> Doc {
        let mut d = Doc { path, ks, password, original, dirty: false, rev: 0, hay: vec![], added: BTreeSet::new() };
        d.changed(false);
        d
    }

    fn changed(&mut self, dirty: bool) {
        self.dirty |= dirty;
        self.rev += 1;
        self.hay = self.ks.entries.iter().map(|e| format!("{}\n{}", e.alias.to_lowercase(), e.info.as_ref().map(CertInfo::haystack).unwrap_or_default())).collect();
    }

    fn name(&self) -> String {
        self.path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| t!("(nuevo almacén)").into())
    }
}

/// Un certificado que se puede agregar (de un servidor, archivo o texto).
struct Candidate {
    der: Vec<u8>,
    info: CertInfo,
    alias: String,
    checked: bool,
    /// De dónde salió (consulta a un servidor).
    origin: Option<Origin>,
}

#[derive(PartialEq, Clone, Copy)]
enum AddMode {
    Server,
    File,
}

struct AddDialog {
    mode: AddMode,
    input: String,
    protocol: Protocol,
    pending: Option<Receiver<Result<Chain, String>>>,
    /// Cadena del servidor, completada hasta la raíz si se pudo.
    chain: Option<Chain>,
    /// Texto pegado (modo archivo/texto) y de dónde vinieron los certificados.
    text: String,
    source: Option<String>,
    error: Option<String>,
    candidates: Vec<Candidate>,
    /// ¿Java confiaría en el servidor con el almacén?, qué certificado lo
    /// arreglaría y con qué revisión del almacén se calculó.
    verdict: Option<(u64, Result<(), String>, Option<usize>)>,
    focus_input: bool,
}

impl AddDialog {
    fn new(mode: AddMode, input: String) -> AddDialog {
        AddDialog { mode, input, protocol: Protocol::Auto, pending: None, chain: None, text: String::new(), source: None, error: None, candidates: vec![], verdict: None, focus_input: true }
    }

    /// Prepara los candidatos: alias libres y marcados los que convenga agregar.
    fn set_candidates(&mut self, ders: Vec<Vec<u8>>, ks: &Keystore) {
        let mut taken: Vec<String> = ks.entries.iter().map(|e| e.alias.to_lowercase()).collect();
        self.candidates.clear();
        for der in ders {
            let Ok(info) = CertInfo::parse(&der) else { continue };
            let alias = cert::alias_for(&info.cn, &|a| taken.iter().any(|t| t == a));
            taken.push(alias.clone());
            self.candidates.push(Candidate { der, info, alias, checked: false, origin: None });
        }
        // Servidor: la CA más alta que mandó (sigue valiendo cuando renueve su
        // certificado); si solo mandó el suyo, ese. Archivo: todos.
        let n = self.candidates.len();
        if self.mode == AddMode::Server && n > 0 {
            let i = (0..n).rev().find(|&i| self.candidates[i].info.is_ca).unwrap_or(0);
            self.candidates[i].checked = true;
        } else {
            for c in &mut self.candidates {
                c.checked = true;
            }
        }
        for c in &mut self.candidates {
            if ks.contains(&c.info.sha256).is_some() {
                c.checked = false;
            }
        }
        self.verdict = None;
    }
}

/// «Comparar almacenes»: el abierto contra otro.
#[derive(Default)]
struct Compare {
    path: Option<PathBuf>,
    /// Contenido del otro almacén mientras se pide su contraseña.
    data: Option<Vec<u8>>,
    password: String,
    error: Option<String>,
    other: Option<Keystore>,
    /// Huellas SHA-256 marcadas para copiar (de los que solo están en el otro).
    checked: BTreeSet<String>,
}

impl Compare {
    fn load(&mut self, path: PathBuf) {
        *self = Compare::default();
        match std::fs::read(&path) {
            Err(e) => self.error = Some(tf!("No se pudo leer {f}: {e}", f = path.display(), e = e)),
            Ok(data) => match Keystore::open(&data, "") {
                Ok((ks, _)) => self.other = Some(ks),
                Err(OpenError::Password) => self.data = Some(data),
                Err(OpenError::Invalid(e)) => self.error = Some(tf!("No se pudo abrir {f}: {e}", f = path.display(), e = e)),
            },
        }
        self.path = Some(path);
    }
}

/// Huella SHA-256 → índice, de las entradas con certificado.
fn prints(ks: &Keystore) -> std::collections::BTreeMap<&str, usize> {
    ks.entries.iter().enumerate().filter_map(|(i, e)| e.info.as_ref().map(|inf| (inf.sha256.as_str(), i))).collect()
}

enum Next {
    Close,
    Open(PathBuf),
    New,
}

enum Dialog {
    Settings,
    Password { path: PathBuf, data: Vec<u8>, input: String, error: Option<String>, show: bool, focus: bool },
    Add(Box<AddDialog>),
    Compare(Box<Compare>),
    SaveAs { format: Format, password: String },
    NewStore { format: Format, password: String },
    ChangePassword { input: String, show: bool },
    ConfirmRemove { aliases: Vec<String> },
    Elevate { path: PathBuf, data: Vec<u8> },
    Unsaved(Next),
    Error(String),
}

/// Diálogo nativo en curso (rfd), esperado en otro hilo.
struct PendingPick {
    result: Arc<Mutex<Option<Option<PathBuf>>>>,
    purpose: Pick,
}

#[derive(Clone)]
enum Pick {
    Open,
    AddFile,
    SaveAs { format: Format, password: String },
    Export(Vec<String>),
    Compare,
}

pub struct App {
    session: Session,
    session_dirty: bool,
    last_session_save: Instant,
    doc: Option<Doc>,
    filter: String,
    focus_filter: bool,
    /// Alias de la entrada que se ve en el detalle.
    focus: Option<String>,
    /// Alias marcados con la casilla.
    checked: BTreeSet<String>,
    rename: Option<(String, String)>,
    dialog: Option<Dialog>,
    pick: Option<PendingPick>,
    java: Vec<crate::java::Found>,
    /// Guardado con permisos de administrador en curso.
    elevated: Option<(PathBuf, Vec<u8>, Receiver<Result<(), String>>)>,
    /// Ya se confirmó cerrar con cambios sin guardar.
    close_ok: bool,
    screenshot: Option<String>,
    frames: u32,
    show_about: bool,
    logo: Option<TextureHandle>,
    show_keys: bool,
    updater: Option<crate::update::Updater>,
    show_updater: bool,
    vigia: crate::estilo::Vigia,
    avisos: crate::estilo::Avisos,
}

/// «C=US, O=Org, CN=Nombre» → pares (atributo, valor), sin el CN (ya se muestra aparte).
fn split_dn(dn: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for part in dn.split(", ") {
        let attr = part.split_once('=').filter(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '.'));
        match (attr, out.last_mut()) {
            (Some((k, v)), _) => out.push((k.to_string(), v.to_string())),
            (None, Some(last)) => {
                last.1.push_str(", ");
                last.1.push_str(part);
            }
            (None, None) => out.push((String::new(), part.to_string())),
        }
    }
    out.retain(|(k, _)| k != "CN");
    out
}

/// Nombre legible de un atributo de un nombre X.500.
fn dn_label(k: &str) -> String {
    match k {
        "O" => t!("Organización").into(),
        "OU" => t!("Unidad").into(),
        "C" => t!("País").into(),
        "L" => t!("Localidad").into(),
        "ST" => t!("Estado o provincia").into(),
        "emailAddress" | "E" => t!("Correo").into(),
        "serialNumber" => t!("N.º de serie").into(),
        "2.5.4.97" | "organizationIdentifier" => t!("Identificador").into(),
        k => k.to_string(),
    }
}

fn dn_grid(ui: &mut Ui, tw: &Paleta, id: &str, dn: &str) {
    let parts = split_dn(dn);
    if parts.is_empty() {
        return;
    }
    ui.add_space(6.0);
    Grid::new(id).num_columns(2).spacing([14.0, 5.0]).show(ui, |ui| {
        for (k, v) in parts {
            ui.label(RichText::new(dn_label(&k)).small().color(tw.apagado));
            ui.add(Label::new(RichText::new(v).color(tw.texto)).wrap().selectable(true));
            ui.end_row();
        }
    });
}

fn colors(ui: &Ui) -> (Color32, Color32, Color32) {
    colors_for(ui.visuals().dark_mode)
}

/// (vencido, vence pronto, bien)
fn colors_for(dark: bool) -> (Color32, Color32, Color32) {
    if dark {
        (Color32::from_rgb(240, 110, 100), Color32::from_rgb(235, 170, 80), Color32::from_rgb(110, 205, 125))
    } else {
        (Color32::from_rgb(190, 40, 35), Color32::from_rgb(180, 105, 0), Color32::from_rgb(30, 135, 60))
    }
}

/// Colores de muestra para la lista (paleta de Tailwind): fondo y letra.
const SWATCHES_BG: [[u8; 3]; 8] = [
    [0xff, 0xff, 0xff], // white
    [0xf8, 0xfa, 0xfc], // slate-50
    [0xff, 0xfb, 0xeb], // amber-50
    [0xec, 0xfd, 0xf5], // emerald-50
    [0xf0, 0xf9, 0xff], // sky-50
    [0xf5, 0xf3, 0xff], // violet-50
    [0x1e, 0x29, 0x3b], // slate-800
    [0x0f, 0x17, 0x2a], // slate-900
];
const SWATCHES_FG: [[u8; 3]; 8] = [
    [0x0f, 0x17, 0x2a], // slate-900
    [0x37, 0x41, 0x51], // gray-700
    [0x1e, 0x3a, 0x8a], // blue-900
    [0x06, 0x4e, 0x3b], // emerald-900
    [0x4c, 0x1d, 0x95], // violet-900
    [0x7c, 0x2d, 0x12], // orange-900
    [0xe2, 0xe8, 0xf0], // slate-200
    [0xff, 0xff, 0xff], // white
];

fn rgb(c: [u8; 3]) -> Color32 {
    Color32::from_rgb(c[0], c[1], c[2])
}

/// Letra legible sobre `bg` (oscura sobre claro y al revés).
fn contrast(bg: Color32) -> Color32 {
    let l = 0.2126 * bg.r() as f32 + 0.7152 * bg.g() as f32 + 0.0722 * bg.b() as f32;
    if l > 150.0 { rgb([0x0f, 0x17, 0x2a]) } else { rgb([0xe2, 0xe8, 0xf0]) }
}

/// Fila de ajustes con un color: muestras, selector libre y «Del tema».
fn color_row(ui: &mut Ui, label: &str, value: &mut Option<String>, swatches: &[[u8; 3]]) -> bool {
    let mut changed = false;
    crate::estilo::fila(ui, label, None, |ui| {
        let cur = value.as_deref().and_then(store::parse_hex);
        for &c in swatches {
            let (rect, r) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::click());
            let sel = cur == Some(c);
            let stroke = if sel { Stroke::new(2.0, crate::estilo::acento()) } else { Stroke::new(1.0, Paleta::de(ui).borde_fuerte) };
            ui.painter().rect(rect.shrink(1.0), 5.0, rgb(c), stroke, StrokeKind::Inside);
            if r.on_hover_text(store::to_hex(c)).clicked() {
                *value = Some(store::to_hex(c));
                changed = true;
            }
        }
        let mut c = cur.unwrap_or([0x80, 0x80, 0x80]);
        if ui.color_edit_button_srgb(&mut c).on_hover_text(t!("Otro color")).changed() {
            *value = Some(store::to_hex(c));
            changed = true;
        }
        if ui.add_enabled(value.is_some(), Button::new(t!("Del tema"))).clicked() {
            *value = None;
            changed = true;
        }
    });
    changed
}

/// «vence en 12 días», «venció hace 3 días»…
fn expiry_text(info: &CertInfo, now: i64) -> String {
    let d = info.days_left(now);
    if d < 0 {
        tf!("venció hace {n} días", n = -d)
    } else if d < SOON_DAYS {
        tf!("vence en {n} días", n = d)
    } else if d < 365 {
        tf!("{n} días", n = d)
    } else {
        tf!("{n} años", n = format!("{:.1}", d as f64 / 365.25))
    }
}

impl App {
    pub fn new(cc: &eframe::CreationContext, open: Option<PathBuf>) -> App {
        let screenshot = std::env::var("KEYUTIL_SCREENSHOT").ok();
        let session = store::load_session();
        if let Some(l) = session.lang.as_deref().and_then(crate::i18n::Lang::from_code).or_else(crate::i18n::system) {
            crate::i18n::set(l);
        }
        crate::estilo::aplicar_tema(&cc.egui_ctx, crate::estilo::Tema::de_clave(session.theme.as_deref().unwrap_or("")));
        crate::estilo::aplicar(&cc.egui_ctx);
        if let Ok(t) = std::env::var("KEYUTIL_TEMA") {
            crate::estilo::aplicar_tema(&cc.egui_ctx, crate::estilo::Tema::de_clave(&t));
        }
        let mut app = App {
            session,
            session_dirty: false,
            last_session_save: Instant::now(),
            doc: None,
            filter: String::new(),
            focus_filter: false,
            focus: None,
            checked: BTreeSet::new(),
            rename: None,
            dialog: None,
            pick: None,
            java: crate::java::find(),
            elevated: None,
            close_ok: false,
            screenshot,
            frames: 0,
            show_about: false,
            logo: None,
            show_keys: false,
            updater: None,
            show_updater: false,
            vigia: Default::default(),
            avisos: Default::default(),
        };
        if let Some(p) = open {
            app.open_path(p);
        }
        app
    }

    // ------------------------------------------------------------ abrir y guardar

    /// Abre un almacén o, si es un certificado y hay almacén abierto, ofrece agregarlo.
    fn open_path(&mut self, path: PathBuf) {
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => return self.avisos.error(tf!("No se pudo leer {f}: {e}", f = path.display(), e = e)),
        };
        if !crate::keystore::looks_like_keystore(&data) {
            if let Ok(ders) = cert::parse_many(&data) {
                return self.offer_certs(ders, path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
            }
        }
        if self.doc.as_ref().is_some_and(|d| d.dirty) {
            self.dialog = Some(Dialog::Unsaved(Next::Open(path)));
            return;
        }
        match Keystore::open(&data, "") {
            Ok((ks, pw)) => self.set_doc(Doc::new(Some(path), ks, pw, Some(data))),
            Err(OpenError::Password) => self.dialog = Some(Dialog::Password { path, data, input: String::new(), error: None, show: false, focus: true }),
            Err(OpenError::Invalid(e)) => self.dialog = Some(Dialog::Error(tf!("No se pudo abrir {f}: {e}", f = path.display(), e = e))),
        }
    }

    fn set_doc(&mut self, doc: Doc) {
        if let Some(p) = &doc.path {
            self.session.add_recent(p);
            self.session_dirty = true;
        }
        let n = doc.ks.entries.len();
        let unverified = !doc.ks.verified;
        self.focus = doc.ks.entries.first().map(|e| e.alias.clone());
        self.checked.clear();
        self.rename = None;
        self.doc = Some(doc);
        if unverified {
            self.avisos.push(crate::estilo::Tipo::Aviso, t!("Abierto sin comprobar la contraseña: se pedirá al guardar."));
        } else {
            self.avisos.info(tf!("{n} certificados", n = n));
        }
    }

    /// Certificados sueltos (archivo, texto o arrastrados): ventana para agregarlos.
    fn offer_certs(&mut self, ders: Vec<Vec<u8>>, source: String) {
        let Some(doc) = &self.doc else {
            self.avisos.error(t!("Abre primero un almacén (o crea uno nuevo) para agregar certificados."));
            return;
        };
        let mut d = AddDialog::new(AddMode::File, String::new());
        d.source = Some(source);
        d.set_candidates(ders, &doc.ks);
        self.dialog = Some(Dialog::Add(Box::new(d)));
    }

    fn save(&mut self, ctx: &Context) {
        let Some(doc) = &self.doc else { return };
        let Some(path) = doc.path.clone() else {
            self.dialog = Some(Dialog::SaveAs { format: doc.ks.format, password: doc.password.clone() });
            return;
        };
        if doc.password.is_empty() {
            self.dialog = Some(Dialog::ChangePassword { input: String::new(), show: false });
            self.avisos.push(crate::estilo::Tipo::Aviso, t!("Escribe la contraseña del almacén para guardarlo."));
            return;
        }
        let format = doc.ks.format;
        self.write_to(path, format, None, ctx);
    }

    /// Escribe el almacén en `path` (con copia del original antes) y lo deja
    /// como archivo abierto. Sin permiso, ofrece hacerlo como administrador.
    fn write_to(&mut self, path: PathBuf, format: Format, password: Option<String>, _ctx: &Context) {
        let Some(doc) = &mut self.doc else { return };
        let pw = password.clone().unwrap_or_else(|| doc.password.clone());
        let data = match doc.ks.write(format, &pw) {
            Ok(d) => d,
            Err(e) => return self.avisos.error(e),
        };
        // Copia de lo que había en el archivo (el original abierto u otro que se reemplaza).
        if self.session.backup.unwrap_or(true) {
            if let Ok(old) = std::fs::read(&path) {
                if let Err(e) = store::backup(&path, &old) {
                    return self.avisos.error(tf!("No se pudo hacer la copia de seguridad: {e}", e = e));
                }
            }
        }
        match store::save_file(&path, &data) {
            Ok(()) => self.saved(path, format, pw, data),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                doc.password = pw;
                doc.ks.format = format;
                self.dialog = Some(Dialog::Elevate { path, data });
            }
            Err(e) => self.avisos.error(tf!("No se pudo guardar: {e}", e = e)),
        }
    }

    fn saved(&mut self, path: PathBuf, format: Format, password: String, data: Vec<u8>) {
        if let Some(doc) = &mut self.doc {
            doc.ks.format = format;
            doc.password = password;
            doc.original = Some(data);
            doc.path = Some(path.clone());
            doc.dirty = false;
            doc.ks.verified = true;
        }
        self.session.add_recent(&path);
        self.session_dirty = true;
        self.avisos.exito(tf!("Guardado: {f}", f = path.display()));
    }

    fn pick(&mut self, purpose: Pick, ctx: &Context) {
        if self.pick.is_some() {
            return;
        }
        type Fut = std::pin::Pin<Box<dyn std::future::Future<Output = Option<rfd::FileHandle>> + Send>>;
        let d = rfd::AsyncFileDialog::new();
        let dir = self.doc.as_ref().and_then(|d| d.path.as_ref()).and_then(|p| p.parent()).map(Path::to_path_buf);
        let d = match &dir {
            Some(x) => d.set_directory(x),
            None => d,
        };
        let fut: Fut = match &purpose {
            Pick::Open => Box::pin(d.set_title(t!("Abrir almacén")).add_filter(t!("Almacenes y certificados"), &["jks", "p12", "pfx", "keystore", "truststore", "ks", "pem", "crt", "cer", "der"]).add_filter(t!("Todos"), &["*"]).pick_file()),
            Pick::AddFile => Box::pin(d.set_title(t!("Agregar certificados")).add_filter(t!("Certificados"), &["pem", "crt", "cer", "der", "cert", "txt"]).add_filter(t!("Todos"), &["*"]).pick_file()),
            Pick::SaveAs { format, .. } => {
                let ext = if *format == Format::Jks { "jks" } else { "p12" };
                let name = self.doc.as_ref().and_then(|d| d.path.as_ref()).and_then(|p| p.file_stem()).map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "cacerts".into());
                Box::pin(d.set_title(t!("Guardar almacén como")).set_file_name(format!("{name}.{ext}")).save_file())
            }
            Pick::Compare => Box::pin(d.set_title(t!("Comparar con")).add_filter(t!("Almacenes"), &["jks", "p12", "pfx", "keystore", "truststore", "ks"]).add_filter(t!("Todos"), &["*"]).pick_file()),
            Pick::Export(aliases) => {
                let name = if aliases.len() == 1 { format!("{}.pem", aliases[0]) } else { "certificados.pem".into() };
                Box::pin(d.set_title(t!("Exportar certificados")).set_file_name(name).add_filter("PEM", &["pem", "crt"]).add_filter(t!("DER (binario, uno solo)"), &["der", "cer"]).save_file())
            }
        };
        let result = Arc::new(Mutex::new(None));
        let r = result.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            *r.lock().unwrap() = Some(block_on(fut).map(|h| h.path().to_path_buf()));
            ctx.request_repaint();
        });
        self.pick = Some(PendingPick { result, purpose });
    }

    fn poll(&mut self, ctx: &Context) {
        // Diálogo de archivos.
        if let Some(done) = self.pick.as_ref().and_then(|p| p.result.lock().unwrap().take()) {
            let purpose = self.pick.take().unwrap().purpose;
            if let Some(path) = done {
                match purpose {
                    Pick::Open => self.open_path(path),
                    Pick::AddFile => match std::fs::read(&path).map_err(|e| e.to_string()).and_then(|b| cert::parse_many(&b)) {
                        Ok(ders) => self.offer_certs(ders, path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
                        Err(e) => self.avisos.error(e),
                    },
                    Pick::SaveAs { format, password } => self.write_to(path, format, Some(password), ctx),
                    Pick::Export(aliases) => self.export(&aliases, &path),
                    Pick::Compare => {
                        if let Some(Dialog::Compare(c)) = &mut self.dialog {
                            c.load(path);
                        }
                    }
                }
            }
        }
        // Consulta a un servidor.
        if let Some(Dialog::Add(d)) = &mut self.dialog {
            if let Some(r) = d.pending.as_ref().and_then(|rx| rx.try_recv().ok()) {
                d.pending = None;
                match r {
                    Ok(c) => {
                        self.session.last_server = Some(d.input.trim().to_string());
                        self.session_dirty = true;
                        d.error = None;
                        if let Some(doc) = &self.doc {
                            d.set_candidates(c.links.iter().map(|l| l.der.clone()).collect(), &doc.ks);
                            for (cand, l) in d.candidates.iter_mut().zip(&c.links) {
                                cand.origin = Some(l.origin.clone());
                            }
                        }
                        d.chain = Some(c);
                    }
                    Err(e) => {
                        d.error = Some(e);
                        d.chain = None;
                        d.candidates.clear();
                    }
                }
            }
        }
        // Guardado como administrador.
        if let Some(r) = self.elevated.as_ref().and_then(|(_, _, rx)| rx.try_recv().ok()) {
            let (path, data, _) = self.elevated.take().unwrap();
            match r {
                Ok(()) => {
                    let (format, pw) = self.doc.as_ref().map(|d| (d.ks.format, d.password.clone())).unwrap_or((Format::Pkcs12, String::new()));
                    self.saved(path, format, pw, data);
                    if self.close_ok {
                        ctx.send_viewport_cmd(ViewportCommand::Close);
                    }
                }
                Err(e) => {
                    self.close_ok = false;
                    self.avisos.error(e);
                }
            }
        }
    }

    fn export(&mut self, aliases: &[String], path: &Path) {
        let Some(doc) = &self.doc else { return };
        let ders: Vec<&[u8]> = aliases.iter().filter_map(|a| doc.ks.find(a)).flat_map(|i| doc.ks.entries[i].certs.iter().map(Vec::as_slice)).collect();
        let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        let data = if (ext == "der" || ext == "cer") && ders.len() == 1 { ders[0].to_vec() } else { ders.iter().map(|d| cert::to_pem(d)).collect::<String>().into_bytes() };
        match std::fs::write(path, data) {
            Ok(()) => self.avisos.exito(tf!("Exportados {n} certificados a {f}", n = ders.len(), f = path.display())),
            Err(e) => self.avisos.error(tf!("No se pudo exportar: {e}", e = e)),
        }
    }

    /// Dónde buscar los emisores que el servidor no manda: el almacén abierto
    /// y los cacerts de los otros Java instalados.
    fn pool(&self) -> diag::Pool {
        let current = self.doc.as_ref().and_then(|d| d.path.as_ref()).and_then(|p| p.canonicalize().ok());
        diag::Pool {
            store: self.doc.as_ref().map(|d| d.ks.anchors().map(<[u8]>::to_vec).collect()).unwrap_or_default(),
            java: self.java.iter().filter(|j| j.path.canonicalize().ok() != current).map(|j| (j.label.clone(), j.path.clone())).collect(),
        }
    }

    fn start_fetch(d: &mut AddDialog, ctx: &Context, pool: diag::Pool) {
        let (tx, rx) = channel();
        let (input, protocol, ctx) = (d.input.clone(), d.protocol, ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(diag::run(&input, protocol, pool));
            ctx.request_repaint();
        });
        d.pending = Some(rx);
        d.error = None;
    }

    fn open_add_server(&mut self, ctx: &Context) {
        if self.doc.is_none() {
            return self.avisos.error(t!("Abre primero un almacén (o crea uno nuevo) para agregar certificados."));
        }
        let last = self.session.last_server.clone().unwrap_or_default();
        let mut d = AddDialog::new(AddMode::Server, last);
        if let Ok(h) = std::env::var("KEYUTIL_SERVIDOR") {
            if self.screenshot.is_some() {
                d.input = h;
                Self::start_fetch(&mut d, ctx, self.pool());
            }
        }
        self.dialog = Some(Dialog::Add(Box::new(d)));
    }

    fn open_updater(&mut self, ctx: &Context) {
        let running = self.updater.as_ref().is_some_and(|u| u.stage() == crate::update::Stage::Running);
        if !running {
            self.updater = Some(crate::update::Updater::check(ctx.clone()));
        }
        self.show_updater = true;
    }

    fn updater_window(&mut self, ctx: &Context) {
        let Some(u) = &self.updater else { return };
        if !self.show_updater {
            return;
        }
        let mut open = true;
        let nota = self.doc.as_ref().is_some_and(|d| d.dirty).then(|| t!("Hay cambios sin guardar en el almacén: guárdalos antes de reiniciar."));
        match crate::estilo::ventana_actualizar(ctx, u, &mut open, nota) {
            crate::estilo::AccionActualizar::Ejecutar => u.run(ctx.clone()),
            crate::estilo::AccionActualizar::Reiniciar(p) => match crate::update::relaunch_after_exit(&p) {
                Ok(()) => ctx.send_viewport_cmd(ViewportCommand::Close),
                Err(e) => self.avisos.error(tf!("No se pudo abrir la versión nueva: {e}", e = e)),
            },
            crate::estilo::AccionActualizar::Nada => {}
        }
        if !open {
            self.show_updater = false;
        }
    }

    /// Alias visibles con el filtro actual (en orden).
    fn visible(&self) -> Vec<usize> {
        let Some(doc) = &self.doc else { return vec![] };
        let f = self.filter.trim().to_lowercase();
        let words: Vec<&str> = f.split_whitespace().collect();
        (0..doc.ks.entries.len()).filter(|&i| words.iter().all(|w| doc.hay[i].contains(w))).collect()
    }

    fn remove(&mut self, aliases: &[String]) {
        let Some(doc) = &mut self.doc else { return };
        let mut n = 0;
        for a in aliases {
            doc.added.remove(&a.to_lowercase());
            if doc.ks.remove(a).is_some() {
                n += 1;
            }
            self.checked.remove(a);
        }
        doc.changed(true);
        if self.focus.as_ref().is_some_and(|f| doc.ks.find(f).is_none()) {
            self.focus = None;
        }
        self.avisos.info(tf!("Quitados {n} certificados (falta guardar)", n = n));
    }

    // ------------------------------------------------------------ barras

    fn toolbar(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let has_doc = self.doc.is_some();
        ui.horizontal(|ui| {
            if ui.add(IconButton::new(Icon::Open, Tone::File).label(t!("Abrir…"))).on_hover_text(t!("Abrir un almacén JKS o PKCS12 (Ctrl+O)")).clicked() {
                self.pick(Pick::Open, &ctx);
            }
            let mut open = None;
            // La flecha se pinta: «▾»/«⏷» no están en todas las fuentes (cuadro en Windows).
            let java = ui.menu_button(RichText::new(format!("{}    ", t!("Java"))), |ui| {
                if self.java.is_empty() {
                    ui.weak(t!("No se encontró ningún Java instalado"));
                }
                for j in &self.java {
                    let mut r = ui.add(IconButton::new(Icon::Cup, Tone::Tool).label(&j.label));
                    let mut tip = j.path.display().to_string();
                    if !j.shared.is_empty() {
                        tip.push_str(&tf!("\nTambién lo usan: {l}", l = j.shared.join(", ")));
                    }
                    r = r.on_hover_text(tip);
                    if r.clicked() {
                        open = Some(j.path.clone());
                        ui.close();
                    }
                }
                let recent: Vec<PathBuf> = self.session.recent.iter().filter(|p| p.is_file()).cloned().collect();
                if !recent.is_empty() {
                    ui.separator();
                    ui.weak(t!("Recientes"));
                    for p in recent {
                        if ui.add(IconButton::new(Icon::Database, Tone::File).label(p.display().to_string())).clicked() {
                            open = Some(p);
                            ui.close();
                        }
                    }
                }
                ui.separator();
                if ui.button(t!("Buscar otra vez")).clicked() {
                    self.java = crate::java::find();
                }
            })
            .response
            .on_hover_text(t!("Los cacerts de los Java instalados y los almacenes recientes"));
            let (c, h) = (pos2(java.rect.right() - 11.0, java.rect.center().y), 3.0);
            let color = ui.style().interact(&java).text_color();
            ui.painter().add(eframe::egui::Shape::convex_polygon(vec![pos2(c.x - h * 1.3, c.y - h * 0.6), pos2(c.x + h * 1.3, c.y - h * 0.6), pos2(c.x, c.y + h * 0.9)], color, Stroke::NONE));
            if let Some(p) = open {
                self.open_path(p);
            }
            if ui.add(IconButton::new(Icon::New, Tone::File).label(t!("Nuevo"))).on_hover_text(t!("Crear un almacén vacío")).clicked() {
                if self.doc.as_ref().is_some_and(|d| d.dirty) {
                    self.dialog = Some(Dialog::Unsaved(Next::New));
                } else {
                    self.dialog = Some(Dialog::NewStore { format: Format::Pkcs12, password: crate::keystore::DEFAULT_PASSWORD.into() });
                }
            }
            ui.separator();
            let dirty = self.doc.as_ref().is_some_and(|d| d.dirty);
            if ui.add_enabled(dirty, IconButton::new(Icon::Save, Tone::File).label(t!("Guardar")).primary()).on_hover_text(t!("Guardar los cambios en el archivo (Ctrl+S)")).clicked() {
                self.save(&ctx);
            }
            if ui.add_enabled(has_doc, IconButton::new(Icon::Convert, Tone::File).label(t!("Guardar como…"))).on_hover_text(t!("Guardar en otro archivo, otro formato (JKS/PKCS12) u otra contraseña (Ctrl+Shift+S)")).clicked() {
                let d = self.doc.as_ref().unwrap();
                self.dialog = Some(Dialog::SaveAs { format: d.ks.format, password: d.password.clone() });
            }
            ui.separator();
            if ui.add_enabled(has_doc, IconButton::new(Icon::Globe, Tone::Live).label(t!("De un servidor…"))).on_hover_text(t!("Traer los certificados de un servidor (HTTPS, correo, LDAPS, base de datos…) y agregarlos (Ctrl+L)")).clicked() {
                self.open_add_server(&ctx);
            }
            if ui.add_enabled(has_doc, IconButton::new(Icon::Plus, Tone::Live).label(t!("De un archivo…"))).on_hover_text(t!("Agregar certificados de un archivo .pem, .crt, .cer o .der (también se pueden arrastrar o pegar con Ctrl+V)")).clicked() {
                self.pick(Pick::AddFile, &ctx);
            }
            if ui.add_enabled(has_doc, IconButton::new(Icon::Results, Tone::Tool).label(t!("Comparar…"))).on_hover_text(t!("Comparar este almacén con otro (p. ej. el cacerts de otro Java o de otro servidor) y copiar los certificados que le falten")).clicked() {
                self.dialog = Some(Dialog::Compare(Box::default()));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(IconButton::new(Icon::Gear, Tone::Neutral).selected(matches!(self.dialog, Some(Dialog::Settings)))).on_hover_text(t!("Ajustes")).clicked() {
                    self.dialog = if matches!(self.dialog, Some(Dialog::Settings)) { None } else { Some(Dialog::Settings) };
                }
                if crate::update::SUPPORTED {
                    let nueva = self.vigia.nueva(self.updater.as_ref());
                    if crate::estilo::boton_actualizar(ui, self.show_updater, nueva.as_deref()) {
                        if nueva.is_some() && self.updater.is_some() {
                            self.show_updater = true;
                        } else if nueva.is_some() {
                            self.updater = self.vigia.comprobacion.take();
                            self.show_updater = true;
                        } else {
                            self.open_updater(&ctx);
                        }
                    }
                }
                if has_doc {
                    let r = ui.add(TextEdit::singleline(&mut self.filter).hint_text(t!("Buscar (alias, nombre, emisor, huella)…")).desired_width(200.0));
                    if self.focus_filter {
                        r.request_focus();
                        self.focus_filter = false;
                    }
                    let (rect, _) = ui.allocate_exact_size(vec2(16.0, 16.0), Sense::hover());
                    crate::icons::paint(ui.painter(), rect, Icon::Search);
                }
            });
        });
    }

    fn status_bar(&mut self, ui: &mut Ui) {
        let info = self.doc.as_ref().map(|d| (d.name(), d.ks.format, d.ks.entries.len(), d.dirty, d.ks.verified, d.path.is_some()));
        let now = cert::now();
        let expired = self.doc.as_ref().map(|d| d.ks.entries.iter().filter(|e| e.info.as_ref().is_some_and(|i| i.expired(now))).count()).unwrap_or(0);
        let mut copied = false;
        let mut change_pw = false;
        crate::estilo::barra_estado(ui, &mut self.show_keys, &mut self.show_about, |ui| {
            let Some((name, format, n, dirty, verified, has_path)) = info else {
                ui.small(t!("Ningún almacén abierto"));
                return;
            };
            ui.small(RichText::new(format.name()).strong());
            ui.separator();
            ui.small(tf!("{n} certificados", n = n));
            if expired > 0 {
                ui.separator();
                ui.small(RichText::new(tf!("{n} vencidos", n = expired)).color(colors(ui).0));
            }
            ui.separator();
            let (lock, tip) = if verified { (t!("Contraseña comprobada"), t!("Clic: cambiar la contraseña del almacén")) } else { (t!("Contraseña sin comprobar"), t!("Se abrió sin contraseña: clic para escribirla (hace falta para guardar)")) };
            if crate::estilo::etiqueta(ui, Icon::Lock, RichText::new(lock).small()).on_hover_text(tip).clicked() {
                change_pw = true;
            }
            if dirty {
                ui.separator();
                ui.small(RichText::new(t!("● sin guardar")).color(colors(ui).1));
            }
            ui.separator();
            let r = ui.add(Label::new(RichText::new(&name).small().weak()).sense(Sense::click()).truncate());
            if has_path && r.on_hover_text(t!("Clic: copiar la ruta")).clicked() {
                ui.ctx().copy_text(name.clone());
                copied = true;
            }
        });
        if copied {
            self.avisos.info(t!("Ruta copiada"));
        }
        if change_pw {
            self.dialog = Some(Dialog::ChangePassword { input: String::new(), show: false });
        }
    }

    // ------------------------------------------------------------ lista y detalle

    fn list(&mut self, ui: &mut Ui) {
        let vis = self.visible();
        let now = cert::now();
        let (red, orange, _) = colors(ui);
        // Colores elegidos en Ajustes (o los del tema).
        let bg = self.session.list_bg.as_deref().and_then(store::parse_hex).map(rgb);
        let fg = self.session.list_fg.as_deref().and_then(store::parse_hex).map(rgb).or(bg.map(contrast));
        let Some(doc) = &self.doc else { return };
        let all_checked = !vis.is_empty() && vis.iter().all(|&i| self.checked.contains(&doc.ks.entries[i].alias));
        // Encabezado.
        let w = ui.available_width();
        let cols = |x0: f32| {
            let rest = (w - 28.0 - 110.0).max(200.0);
            [x0 + 28.0, x0 + 28.0 + rest * 0.30, x0 + 28.0 + rest * 0.66, x0 + 28.0 + rest]
        };
        let mut toggle_all = false;
        let mut sel_expired = false;
        ui.horizontal(|ui| {
            // Fondo de la cabecera: se reserva antes para quedar debajo de la casilla.
            let head_bg = ui.painter().add(Shape::Noop);
            let mut c = all_checked;
            if ui.checkbox(&mut c, "").on_hover_text(t!("Marcar o desmarcar los visibles (Ctrl+A)")).changed() {
                toggle_all = true;
            }
            let x = ui.min_rect().left() - 4.0;
            let c = cols(x);
            let y = ui.min_rect().center().y;
            let p = ui.painter();
            let pal = Paleta::de(ui);
            // Cabecera como `thead`: fondo gris, títulos pequeños en mayúsculas.
            let head = Rect::from_min_max(pos2(x, ui.min_rect().top() - 4.0), pos2(x + w + 4.0, ui.min_rect().bottom() + 4.0));
            p.set(head_bg, Shape::rect_filled(head, 6.0, pal.codigo));
            let font = FontId::proportional(10.5);
            for (i, s) in [t!("Alias"), t!("Emitido para"), t!("Emitido por"), t!("Vence")].iter().enumerate() {
                p.text(pos2(c[i], y), Align2::LEFT_CENTER, s.to_uppercase(), font.clone(), pal.apagado);
            }
        });
        ui.separator();
        let mut clicked = None;
        let mut toggled = None;
        let mut menu_act: Option<(String, u8)> = None;
        ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, vis.len(), |ui, range| {
            if let Some(bg) = bg {
                ui.painter().rect_filled(ui.clip_rect(), 0.0, bg);
            }
            for &i in &vis[range] {
                let e = &doc.ks.entries[i];
                let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::click());
                let focused = self.focus.as_deref() == Some(e.alias.as_str());
                let checked = self.checked.contains(&e.alias);
                let v = ui.visuals();
                // Agregados en esta sesión: fondo verde y una barra a la izquierda.
                let new = doc.added.contains(&e.alias.to_lowercase());
                if new {
                    let g = colors(ui).2;
                    ui.painter().rect_filled(rect, 4.0, g.gamma_multiply(if v.dark_mode { 0.22 } else { 0.16 }));
                    ui.painter().rect_filled(Rect::from_min_size(rect.min, vec2(3.0, rect.height())), 1.5, g);
                }
                // Filas separadas por una línea fina (como `divide-y`).
                ui.painter().line_segment([pos2(rect.left(), rect.bottom() - 0.5), pos2(rect.right(), rect.bottom() - 0.5)], Stroke::new(1.0, Paleta::de(ui).borde.gamma_multiply(0.7)));
                if focused {
                    ui.painter().rect_filled(rect, 4.0, v.selection.bg_fill.gamma_multiply(if new { 0.35 } else { 0.55 }));
                } else if resp.hovered() {
                    ui.painter().rect_filled(rect, 4.0, v.widgets.hovered.weak_bg_fill.gamma_multiply(if new { 0.5 } else { 1.0 }));
                }
                // Casilla.
                let cb = Rect::from_center_size(pos2(rect.left() + 12.0, rect.center().y), vec2(16.0, 16.0));
                let cr = ui.interact(cb, ui.scope_id().with(("cb", i)), Sense::click());
                let stroke = if cr.hovered() { v.widgets.hovered.fg_stroke } else { v.widgets.inactive.fg_stroke };
                ui.painter().rect(cb.shrink(1.0), 3.0, if checked { v.selection.bg_fill } else { v.extreme_bg_color }, Stroke::new(1.0, stroke.color), StrokeKind::Inside);
                if checked {
                    ui.painter().line(vec![pos2(cb.left() + 4.0, cb.center().y), pos2(cb.center().x - 1.0, cb.bottom() - 4.5), pos2(cb.right() - 3.5, cb.top() + 4.0)], Stroke::new(2.0, v.selection.stroke.color));
                }
                if cr.clicked() {
                    toggled = Some(e.alias.clone());
                }
                let c = cols(rect.left());
                let font = TextStyle::Body.resolve(ui.style());
                let small = TextStyle::Small.resolve(ui.style());
                let text = fg.unwrap_or(v.text_color());
                let weak = fg.map(|c| c.gamma_multiply(0.72)).unwrap_or(v.weak_text_color());
                let cell = |x0: f32, x1: f32, s: &str, f: &FontId, color: Color32, icon: Option<Icon>| {
                    let mut x = x0;
                    if let Some(ic) = icon {
                        crate::icons::paint(ui.painter(), Rect::from_min_size(pos2(x, rect.center().y - 8.0), vec2(16.0, 16.0)), ic);
                        x += 20.0;
                    }
                    let clip = Rect::from_x_y_ranges(x..=x1 - 8.0, rect.y_range());
                    let g = ui.painter().layout_no_wrap(s.to_string(), f.clone(), color);
                    ui.painter().with_clip_rect(clip).galley(pos2(x, rect.center().y - g.size().y / 2.0), g, color);
                };
                let kind_icon = match e.kind {
                    Kind::KeyPair => Some(Icon::Lock),
                    Kind::Secret => Some(Icon::Lock),
                    Kind::Trusted => None,
                };
                cell(c[0], c[1], &e.alias, &font, text, kind_icon);
                match &e.info {
                    Some(info) => {
                        cell(c[1], c[2], &info.cn, &font, text, None);
                        cell(c[2], c[3], &info.issuer_cn, &small, weak, None);
                        let d = info.days_left(now);
                        let (col, ic) = if d < 0 { (red, Some(Icon::Error)) } else if d < SOON_DAYS { (orange, Some(Icon::Warning)) } else { (weak, None) };
                        cell(c[3], rect.right(), &cert::date(info.not_after), &small, col, ic);
                    }
                    None => cell(c[1], c[2], if e.kind == Kind::Secret { t!("(clave secreta)") } else { t!("(certificado ilegible)") }, &small, weak, None),
                }
                let mut tip = e.info.as_ref().map(|i| format!("{}\n{}", i.subject, expiry_text(i, now))).unwrap_or_default();
                if new {
                    tip.push_str(&format!("\n{}", t!("Agregado en esta sesión")));
                }
                let resp = resp.on_hover_text_at_pointer(tip);
                if resp.clicked() {
                    clicked = Some(e.alias.clone());
                }
                resp.context_menu(|ui| {
                    if ui.button(t!("Exportar…")).clicked() {
                        menu_act = Some((e.alias.clone(), 0));
                        ui.close();
                    }
                    if ui.button(t!("Copiar PEM")).clicked() {
                        menu_act = Some((e.alias.clone(), 1));
                        ui.close();
                    }
                    if ui.button(t!("Copiar huella SHA-256")).clicked() {
                        menu_act = Some((e.alias.clone(), 2));
                        ui.close();
                    }
                    ui.separator();
                    if ui.button(t!("Quitar…")).clicked() {
                        menu_act = Some((e.alias.clone(), 3));
                        ui.close();
                    }
                });
            }
            if vis.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.weak(if doc.ks.entries.is_empty() { t!("El almacén está vacío: agrega certificados de un servidor o de un archivo.") } else { t!("Ningún certificado coincide con la búsqueda.") });
                });
            }
        });
        let expired: Vec<String> = doc.ks.entries.iter().filter(|e| e.info.as_ref().is_some_and(|i| i.expired(now))).map(|e| e.alias.clone()).collect();
        let vis_aliases: Vec<String> = vis.iter().map(|&i| doc.ks.entries[i].alias.clone()).collect();
        // Barra de selección.
        let mut act = None;
        ui.separator();
        ui.horizontal(|ui| {
            let n = self.checked.len();
            if n == 0 {
                ui.weak(t!("Marca casillas para exportar o quitar varios a la vez."));
            } else {
                ui.label(RichText::new(tf!("{n} marcados", n = n)).strong());
                if ui.add(IconButton::new(Icon::Upload, Tone::File).label(t!("Exportar…"))).on_hover_text(t!("Guardar los marcados en un archivo PEM (Ctrl+E)")).clicked() {
                    act = Some(0);
                }
                if ui.add(IconButton::new(Icon::Trash, Tone::Edit).label(t!("Quitar…"))).on_hover_text(t!("Quitar los marcados del almacén (Supr)")).clicked() {
                    act = Some(1);
                }
                if ui.button(t!("Desmarcar")).clicked() {
                    act = Some(2);
                }
            }
            if !expired.is_empty() {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(IconButton::new(Icon::Error, Tone::Edit).label(tf!("Marcar los {n} vencidos", n = expired.len()))).clicked() {
                        sel_expired = true;
                    }
                });
            }
        });
        if toggle_all {
            if all_checked {
                for a in &vis_aliases {
                    self.checked.remove(a);
                }
            } else {
                self.checked.extend(vis_aliases);
            }
        }
        if sel_expired {
            self.checked = expired.into_iter().collect();
        }
        if let Some(a) = toggled {
            if !self.checked.remove(&a) {
                self.checked.insert(a);
            }
        }
        if let Some(a) = clicked {
            self.focus = Some(a);
            self.rename = None;
        }
        let ctx = ui.ctx().clone();
        match act {
            Some(0) => self.pick(Pick::Export(self.checked.iter().cloned().collect()), &ctx),
            Some(1) => self.dialog = Some(Dialog::ConfirmRemove { aliases: self.checked.iter().cloned().collect() }),
            Some(2) => self.checked.clear(),
            _ => {}
        }
        if let Some((a, what)) = menu_act {
            self.entry_action(&a, what, &ctx);
        }
    }

    /// 0 exportar, 1 copiar PEM, 2 copiar huella, 3 quitar.
    fn entry_action(&mut self, alias: &str, what: u8, ctx: &Context) {
        let Some(doc) = &self.doc else { return };
        let Some(i) = doc.ks.find(alias) else { return };
        let e = &doc.ks.entries[i];
        match what {
            0 => self.pick(Pick::Export(vec![alias.to_string()]), ctx),
            1 => {
                ctx.copy_text(e.certs.iter().map(|d| cert::to_pem(d)).collect());
                self.avisos.info(t!("PEM copiado"));
            }
            2 => {
                ctx.copy_text(e.info.as_ref().map(|i| i.sha256.clone()).unwrap_or_default());
                self.avisos.info(t!("Huella copiada"));
            }
            _ => self.dialog = Some(Dialog::ConfirmRemove { aliases: vec![alias.to_string()] }),
        }
    }

    fn detail(&mut self, ui: &mut Ui) {
        let now = cert::now();
        let (red, orange, green) = colors(ui);
        let Some(doc) = &self.doc else { return };
        let Some(i) = self.focus.as_deref().and_then(|a| doc.ks.find(a)) else {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.weak(t!("Elige un certificado para ver su detalle.")));
            return;
        };
        let e = &doc.ks.entries[i];
        let mut act = None;
        let mut rename_ok = None;
        ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let tw = Paleta::de(ui);
            ui.add_space(6.0);
            // Alias (renombrable).
            match &mut self.rename {
                Some((old, buf)) if *old == e.alias => {
                    ui.horizontal(|ui| {
                        let r = ui.add(TextEdit::singleline(buf).desired_width(ui.available_width() - 90.0));
                        if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) || ui.button(t!("Aceptar")).clicked() {
                            rename_ok = Some((old.clone(), buf.clone()));
                        }
                        r.request_focus();
                    });
                }
                _ => {
                    ui.horizontal_top(|ui| {
                        ui.add(Label::new(RichText::new(&e.alias).size(19.0).strong().color(tw.texto)).wrap_mode(TextWrapMode::Wrap).selectable(true));
                    });
                }
            }
            ui.add_space(6.0);
            // Insignias: tipo de entrada, CA/raíz y estado.
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let accent = crate::estilo::acento();
                crate::estilo::insignia(ui, match e.kind {
                    Kind::Trusted => t!("De confianza"),
                    Kind::KeyPair => t!("Clave privada"),
                    Kind::Secret => t!("Clave secreta"),
                }, accent);
                if let Some(info) = &e.info {
                    if info.is_ca {
                        crate::estilo::insignia(ui, t!("Autoridad (CA)"), tw.apagado);
                    }
                    if info.self_signed {
                        crate::estilo::insignia(ui, t!("Raíz"), tw.apagado);
                    }
                }
                if doc.added.contains(&e.alias.to_lowercase()) {
                    crate::estilo::insignia(ui, t!("Agregado en esta sesión"), green);
                }
                if ui.add(IconButton::new(Icon::Edit, Tone::Edit).small()).on_hover_text(t!("Cambiar el alias")).clicked() {
                    act = Some(9);
                }
            });
            if e.kind != Kind::Trusted {
                ui.add_space(2.0);
                ui.label(RichText::new(t!("Se conserva tal cual al guardar.")).small().color(tw.apagado));
            }
            ui.add_space(10.0);
            if let Some(info) = &e.info {
                let d = info.days_left(now);
                let (col, ic, txt) = if d < 0 { (red, Icon::Error, tf!("Vencido: {t}", t = expiry_text(info, now))) } else if d < SOON_DAYS { (orange, Icon::Warning, tf!("Vigente, {t}", t = expiry_text(info, now))) } else { (green, Icon::Check, tf!("Vigente · {t}", t = expiry_text(info, now))) };
                // Vigencia: estado, fechas y barra del tiempo transcurrido.
                crate::estilo::tarjeta(ui, t!("Vigencia"), |ui| {
                    crate::estilo::etiqueta(ui, ic, RichText::new(txt).color(col).strong());
                    ui.add_space(8.0);
                    let total = (info.not_after - info.not_before).max(1) as f32;
                    let frac = ((now - info.not_before) as f32 / total).clamp(0.0, 1.0);
                    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 6.0), Sense::hover());
                    ui.painter().rect_filled(rect, 3.0, tw.borde);
                    ui.painter().rect_filled(Rect::from_min_size(rect.min, vec2(rect.width() * frac, rect.height())), 3.0, col);
                    ui.add_space(8.0);
                    ui.columns(2, |c| {
                        crate::estilo::campo(&mut c[0], t!("Desde"), &cert::date_time(info.not_before));
                        crate::estilo::campo(&mut c[1], t!("Hasta"), &cert::date_time(info.not_after));
                    });
                    if let Some(ms) = e.added_ms {
                        crate::estilo::campo(ui, t!("Agregado al almacén"), &cert::date_time(ms / 1000));
                    }
                });
                crate::estilo::tarjeta(ui, t!("Emitido para"), |ui| {
                    ui.add(Label::new(RichText::new(&info.cn).strong().size(15.0).color(tw.texto)).wrap().selectable(true));
                    dn_grid(ui, &tw, "dn_titular", &info.subject);
                });
                crate::estilo::tarjeta(ui, t!("Emitido por"), |ui| {
                    if info.self_signed {
                        ui.label(RichText::new(t!("Por sí mismo (autofirmado)")).color(tw.texto));
                    } else {
                        ui.add(Label::new(RichText::new(&info.issuer_cn).strong().size(15.0).color(tw.texto)).wrap().selectable(true));
                        dn_grid(ui, &tw, "dn_emisor", &info.issuer);
                    }
                });
                if !info.sans.is_empty() {
                    crate::estilo::tarjeta(ui, &tf!("Nombres alternativos ({n})", n = info.sans.len()), |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
                            for n in info.sans.iter().take(60) {
                                crate::estilo::chip(ui, n);
                            }
                            if info.sans.len() > 60 {
                                ui.label(RichText::new(tf!("… y {n} más", n = info.sans.len() - 60)).small().color(tw.apagado));
                            }
                        });
                    });
                }
                crate::estilo::tarjeta(ui, t!("Clave y firma"), |ui| {
                    ui.columns(2, |c| {
                        crate::estilo::campo(&mut c[0], t!("Clave"), &info.key);
                        crate::estilo::campo(&mut c[1], t!("Firma"), &info.signature);
                    });
                    ui.label(RichText::new(t!("N.º de serie")).small().color(tw.apagado));
                    crate::estilo::codigo(ui, &info.serial);
                });
                crate::estilo::tarjeta(ui, t!("Huellas"), |ui| {
                    for (k, v) in [("SHA-256", &info.sha256), ("SHA-1", &info.sha1)] {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(k).small().strong().color(tw.apagado));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add(IconButton::new(Icon::Copy, Tone::Neutral).small()).on_hover_text(t!("Copiar")).clicked() {
                                    ui.ctx().copy_text(v.clone());
                                    act = Some(if k == "SHA-1" { 7 } else { 2 });
                                }
                            });
                        });
                        // En dos líneas (sin espacios no se partiría y ensancharía el panel).
                        let mid = v.len() / 2;
                        let cut = v[mid..].find(':').map(|i| mid + i + 1).unwrap_or(v.len());
                        crate::estilo::codigo(ui, &format!("{}\n{}", &v[..cut], &v[cut..]));
                        ui.add_space(4.0);
                    }
                });
                if e.certs.len() > 1 {
                    crate::estilo::tarjeta(ui, &tf!("Cadena ({n} certificados)", n = e.certs.len()), |ui| {
                        for (k, der) in e.certs.iter().enumerate() {
                            if let Ok(ci) = CertInfo::parse(der) {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("{}", k + 1)).small().strong().color(crate::estilo::acento()));
                                    ui.vertical(|ui| {
                                        ui.add(Label::new(RichText::new(&ci.cn).color(tw.texto)).wrap());
                                        ui.label(RichText::new(tf!("vence {f}", f = cert::date(ci.not_after))).small().color(tw.apagado));
                                    });
                                });
                                ui.add_space(2.0);
                            }
                        }
                    });
                }
            }
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                if ui.add(IconButton::new(Icon::Upload, Tone::File).label(t!("Exportar…"))).clicked() {
                    act = Some(0);
                }
                if ui.add(IconButton::new(Icon::Copy, Tone::File).label(t!("Copiar PEM"))).clicked() {
                    act = Some(1);
                }
                if ui.add(IconButton::new(Icon::Trash, Tone::Edit).label(t!("Quitar…"))).clicked() {
                    act = Some(3);
                }
            });
        });
        let alias = e.alias.clone();
        let ctx = ui.ctx().clone();
        match act {
            Some(9) => self.rename = Some((alias.clone(), alias)),
            Some(7) => self.avisos.info(t!("Huella copiada")),
            Some(2) => self.avisos.info(t!("Huella copiada")),
            Some(w) => self.entry_action(&alias, w, &ctx),
            None => {}
        }
        if let Some((old, new)) = rename_ok {
            self.rename = None;
            if old != new {
                let doc = self.doc.as_mut().unwrap();
                match doc.ks.rename(&old, &new) {
                    Ok(()) => {
                        let a = doc.ks.entries[doc.ks.find(&new).unwrap()].alias.clone();
                        if doc.added.remove(&old.to_lowercase()) {
                            doc.added.insert(a.to_lowercase());
                        }
                        doc.changed(true);
                        if self.checked.remove(&old) {
                            self.checked.insert(a.clone());
                        }
                        self.focus = Some(a);
                    }
                    Err(e) => self.avisos.error(e),
                }
            }
        }
    }

    fn welcome(&mut self, ui: &mut Ui) {
        let logo = crate::estilo::logo(ui.ctx(), &mut self.logo);
        let mut acciones: Vec<(Icon, String, String)> = vec![
            (Icon::Open, t!("Abrir almacén…").into(), t!("JKS o PKCS12 (cacerts, truststore, keystore)").into()),
            (Icon::New, t!("Nuevo almacén").into(), t!("Un almacén vacío al que agregar certificados").into()),
        ];
        for j in self.java.iter().take(5) {
            acciones.push((Icon::Cup, tf!("cacerts de {j}", j = j.label), j.path.display().to_string()));
        }
        let refs: Vec<(Icon, &str, &str)> = acciones.iter().map(|(i, a, b)| (*i, a.as_str(), b.as_str())).collect();
        let pie = if self.java.is_empty() { t!("No se encontró ningún Java instalado: abre el cacerts a mano o arrastra aquí un archivo.") } else { t!("También puedes arrastrar aquí un almacén o un certificado.") };
        let ctx = ui.ctx().clone();
        match crate::estilo::bienvenida(ui, &logo, &refs, Some(pie)) {
            Some(0) => self.pick(Pick::Open, &ctx),
            Some(1) => self.dialog = Some(Dialog::NewStore { format: Format::Pkcs12, password: crate::keystore::DEFAULT_PASSWORD.into() }),
            Some(i) => {
                let p = self.java[i - 2].path.clone();
                self.open_path(p);
            }
            None => {}
        }
    }

    // ------------------------------------------------------------ diálogos

    fn dialogs(&mut self, ctx: &Context) {
        let Some(mut d) = self.dialog.take() else { return };
        let mut keep = true;
        let modal = |title: &str| Window::new(title).collapsible(false).resizable(false).pivot(Align2::CENTER_CENTER).default_pos(ctx.content_rect().center());
        match &mut d {
            Dialog::Settings => {
                let mut open = true;
                let label = crate::update::version_label();
                let version = crate::estilo::Version { etiqueta: &label, actualizable: crate::update::SUPPORTED };
                let mut theme = crate::estilo::Tema::de_clave(self.session.theme.as_deref().unwrap_or(""));
                let accion = crate::estilo::ventana_ajustes(ctx, &mut open, &version, |ui| {
                    use crate::estilo::{fila, rejilla, seccion};
                    seccion(ui, t!("General"));
                    rejilla(ui, "ajustes_general", |ui| {
                        if let Some(l) = crate::estilo::fila_idioma(ui) {
                            crate::i18n::set(l);
                            self.session.lang = Some(l.code().into());
                            self.session_dirty = true;
                        }
                        if crate::estilo::fila_tema(ui, &mut theme) {
                            self.session.theme = theme.clave().map(Into::into);
                            self.session_dirty = true;
                        }
                        if crate::update::SUPPORTED {
                            fila(ui, t!("Actualizaciones"), None, |ui| {
                                let mut on = self.session.check_updates.unwrap_or(true);
                                if ui.checkbox(&mut on, t!("Avisar de versiones nuevas (punto verde en ⬇; mira GitHub al abrir y cada 6 horas)")).changed() {
                                    self.session.check_updates = (!on).then_some(false);
                                    self.session_dirty = true;
                                }
                            });
                        }
                    });
                    seccion(ui, t!("Lista de certificados"));
                    rejilla(ui, "ajustes_lista", |ui| {
                        self.session_dirty |= color_row(ui, t!("Fondo"), &mut self.session.list_bg, &SWATCHES_BG);
                        self.session_dirty |= color_row(ui, t!("Letra"), &mut self.session.list_fg, &SWATCHES_FG);
                    });
                    ui.weak(t!("Si eliges solo el fondo, la letra se ajusta sola para que se lea bien."));
                    seccion(ui, t!("Guardado"));
                    rejilla(ui, "ajustes_guardado", |ui| {
                        fila(ui, t!("Copia de seguridad"), None, |ui| {
                            let mut on = self.session.backup.unwrap_or(true);
                            if ui.checkbox(&mut on, t!("Antes de guardar, copiar el archivo original a la carpeta de respaldos")).changed() {
                                self.session.backup = (!on).then_some(false);
                                self.session_dirty = true;
                            }
                        });
                        let dir = store::backups_dir().map(|d| d.display().to_string()).unwrap_or_default();
                        crate::estilo::fila_carpeta(ui, t!("Respaldos"), &dir);
                    });
                });
                if accion == crate::estilo::Accion::BuscarActualizaciones {
                    self.open_updater(ctx);
                }
                if accion == crate::estilo::Accion::Restablecer {
                    self.session.theme = None;
                    self.session.lang = None;
                    self.session.check_updates = None;
                    self.session.backup = None;
                    self.session.list_bg = None;
                    self.session.list_fg = None;
                    crate::estilo::aplicar_tema(ctx, crate::estilo::Tema::Sistema);
                    crate::i18n::set(crate::i18n::system().unwrap_or(crate::i18n::Lang::Es));
                    self.session_dirty = true;
                }
                keep = open;
            }
            Dialog::Password { path, data, input, error, show, focus } => {
                let mut open = true;
                let mut ok = false;
                modal(t!("Contraseña del almacén")).open(&mut open).show(ctx, |ui| {
                    ui.set_width(380.0);
                    ui.label(tf!("{f} está protegido con contraseña (la de fábrica de Java, «changeit», no sirvió).", f = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let r = ui.add(TextEdit::singleline(input).password(!*show).desired_width(300.0));
                        if *focus {
                            r.request_focus();
                            *focus = false;
                        }
                        if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                            ok = true;
                        }
                        if ui.add(IconButton::new(Icon::Eye, Tone::Neutral).small().selected(*show)).on_hover_text(t!("Mostrar u ocultar")).clicked() {
                            *show = !*show;
                        }
                    });
                    if let Some(e) = error {
                        ui.colored_label(colors(ui).0, e.as_str());
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ok |= ui.add(IconButton::new(Icon::Lock, Tone::File).label(t!("Abrir")).framed().primary()).clicked();
                        if ui.button(t!("Abrir sin contraseña")).on_hover_text(t!("Solo JKS: se ven los certificados, pero hará falta la contraseña para guardar")).clicked() {
                            match Keystore::open(data, "") {
                                Ok((mut ks, _)) if crate::keystore::is_jks(data) => {
                                    ks.verified = false;
                                    let doc = Doc::new(Some(path.clone()), ks, String::new(), Some(data.clone()));
                                    keep = false;
                                    self.set_doc(doc);
                                }
                                _ => *error = Some(t!("Un PKCS12 no se puede leer sin su contraseña.").into()),
                            }
                        }
                    });
                });
                if ok {
                    match Keystore::open(data, input) {
                        Ok((ks, pw)) => {
                            let doc = Doc::new(Some(path.clone()), ks, pw, Some(data.clone()));
                            keep = false;
                            self.set_doc(doc);
                        }
                        Err(e) => *error = Some(e.to_string()),
                    }
                }
                keep &= open;
            }
            Dialog::Add(a) => keep = self.add_dialog(ctx, a),
            Dialog::Compare(c) => keep = self.compare_dialog(ctx, c),
            Dialog::SaveAs { .. } | Dialog::NewStore { .. } => {
                let new = matches!(d, Dialog::NewStore { .. });
                let (Dialog::SaveAs { format, password } | Dialog::NewStore { format, password }) = &mut d else { unreachable!() };
                let mut open = true;
                let mut ok = false;
                let has_keys = self.doc.as_ref().is_some_and(|d| d.ks.entries.iter().any(|e| e.kind != Kind::Trusted));
                // Formato con el que se abrió (o guardó) el almacén: se señala en las opciones.
                let current = (!new).then(|| self.doc.as_ref().map(|d| d.ks.format)).flatten();
                let label = |f: Format| if current == Some(f) { tf!("{f} (el actual)", f = f.name()) } else { f.name().to_string() };
                modal(if new { t!("Nuevo almacén") } else { t!("Guardar almacén como") }).open(&mut open).show(ctx, |ui| {
                    ui.set_width(420.0);
                    Grid::new("guardar_como").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
                        ui.strong(t!("Formato"));
                        ui.horizontal(|ui| {
                            ui.radio_value(format, Format::Pkcs12, label(Format::Pkcs12)).on_hover_text(t!("El de Java 9 en adelante (recomendado)"));
                            ui.radio_value(format, Format::Jks, label(Format::Jks)).on_hover_text(t!("Para Java 8 y anteriores"));
                        });
                        ui.end_row();
                        if let Some(c) = current {
                            ui.label("");
                            if *format == c {
                                ui.weak(tf!("El almacén ya es {f}: se guarda en el mismo formato.", f = c.name()));
                            } else {
                                ui.colored_label(colors(ui).1, tf!("Se convertirá de {a} a {b}.", a = c.name(), b = format.name()));
                            }
                            ui.end_row();
                        }
                        ui.strong(t!("Contraseña"));
                        ui.add(TextEdit::singleline(password).desired_width(220.0));
                        ui.end_row();
                    });
                    ui.weak(t!("La de fábrica del cacerts de Java es «changeit»."));
                    if has_keys && !new {
                        ui.weak(t!("Las claves privadas solo se pueden guardar en su formato original."));
                    }
                    ui.add_space(6.0);
                    ok = ui.add_enabled(!password.is_empty(), IconButton::new(if new { Icon::New } else { Icon::Save }, Tone::File).label(if new { t!("Crear") } else { t!("Elegir archivo…") }).framed().primary()).clicked();
                });
                if ok {
                    keep = false;
                    if new {
                        self.set_doc(Doc::new(None, Keystore::new(*format), password.clone(), None));
                    } else {
                        self.pick(Pick::SaveAs { format: *format, password: password.clone() }, ctx);
                    }
                }
                keep &= open;
            }
            Dialog::ChangePassword { input, show } => {
                let mut open = true;
                let mut ok = false;
                let verified = self.doc.as_ref().is_some_and(|d| d.ks.verified);
                modal(t!("Contraseña del almacén")).open(&mut open).show(ctx, |ui| {
                    ui.set_width(380.0);
                    ui.label(if verified { t!("Nueva contraseña (se aplica al guardar):") } else { t!("Contraseña con la que guardar el almacén:") });
                    ui.horizontal(|ui| {
                        let r = ui.add(TextEdit::singleline(input).password(!*show).desired_width(300.0));
                        if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                            ok = true;
                        }
                        if ui.add(IconButton::new(Icon::Eye, Tone::Neutral).small().selected(*show)).clicked() {
                            *show = !*show;
                        }
                    });
                    ui.weak(t!("Las aplicaciones Java que usan este almacén deben conocer la contraseña (javax.net.ssl.trustStorePassword)."));
                    ok |= ui.add_enabled(!input.is_empty(), IconButton::new(Icon::Check, Tone::File).label(t!("Aceptar")).framed().primary()).clicked();
                });
                if ok && !input.is_empty() {
                    if let Some(doc) = &mut self.doc {
                        doc.password = input.clone();
                        doc.ks.verified = true;
                        doc.changed(true);
                    }
                    keep = false;
                }
                keep &= open;
            }
            Dialog::ConfirmRemove { aliases } => {
                let mut open = true;
                let mut ok = false;
                modal(t!("Quitar certificados")).open(&mut open).show(ctx, |ui| {
                    ui.set_width(400.0);
                    ui.label(tf!("¿Quitar {n} certificados del almacén?", n = aliases.len()));
                    ui.add_space(4.0);
                    for a in aliases.iter().take(8) {
                        ui.weak(format!("• {a}"));
                    }
                    if aliases.len() > 8 {
                        ui.weak(tf!("… y {n} más", n = aliases.len() - 8));
                    }
                    ui.add_space(4.0);
                    ui.weak(t!("Las aplicaciones Java dejarán de confiar en los servidores que dependan de ellos. El archivo no cambia hasta guardar."));
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ok = ui.add(IconButton::new(Icon::Trash, Tone::Edit).label(t!("Quitar")).framed().primary()).clicked();
                        if ui.button(t!("Cancelar")).clicked() {
                            keep = false;
                        }
                    });
                });
                if ok {
                    let a = aliases.clone();
                    self.remove(&a);
                    keep = false;
                }
                keep &= open;
            }
            Dialog::Elevate { path, data } => {
                let mut open = true;
                modal(t!("Hacen falta permisos")).open(&mut open).show(ctx, |ui| {
                    ui.set_width(440.0);
                    ui.label(tf!("No tienes permiso para escribir en {f}.", f = path.display()));
                    ui.add_space(4.0);
                    ui.weak(t!("El cacerts de un Java instalado en el sistema suele ser del administrador."));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add(IconButton::new(Icon::Lock, Tone::File).label(t!("Guardar como administrador")).framed().primary()).clicked() {
                            let (tx, rx) = channel();
                            let (p, b, c) = (path.clone(), data.clone(), ctx.clone());
                            std::thread::spawn(move || {
                                let _ = tx.send(store::write_elevated(&p, &b));
                                c.request_repaint();
                            });
                            self.elevated = Some((path.clone(), data.clone(), rx));
                            keep = false;
                        }
                        if ui.button(t!("Guardar en otro archivo…")).clicked() {
                            if let Some(doc) = &self.doc {
                                self.pick(Pick::SaveAs { format: doc.ks.format, password: doc.password.clone() }, ctx);
                            }
                            keep = false;
                        }
                        if ui.button(t!("Cancelar")).clicked() {
                            self.close_ok = false;
                            keep = false;
                        }
                    });
                });
                keep &= open;
            }
            Dialog::Unsaved(next) => {
                let mut open = true;
                let mut choice = None;
                modal(t!("Cambios sin guardar")).open(&mut open).show(ctx, |ui| {
                    ui.set_width(380.0);
                    ui.label(t!("El almacén tiene cambios sin guardar."));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add(IconButton::new(Icon::Save, Tone::File).label(t!("Guardar")).framed().primary()).clicked() {
                            choice = Some(0);
                        }
                        if ui.button(t!("Descartar")).clicked() {
                            choice = Some(1);
                        }
                        if ui.button(t!("Cancelar")).clicked() {
                            choice = Some(2);
                        }
                    });
                });
                if let Some(c) = choice {
                    keep = false;
                    let next = std::mem::replace(next, Next::New);
                    if c == 0 {
                        self.save(ctx);
                    }
                    let saved = c == 1 || self.doc.as_ref().is_some_and(|d| !d.dirty);
                    if c != 2 {
                        match next {
                            Next::Close if saved => {
                                self.close_ok = true;
                                ctx.send_viewport_cmd(ViewportCommand::Close);
                            }
                            // Guardando como administrador: se cierra al terminar.
                            Next::Close => self.close_ok = self.elevated.is_some() || matches!(self.dialog, Some(Dialog::Elevate { .. })),
                            Next::Open(p) if saved => {
                                self.doc = None;
                                self.open_path(p);
                            }
                            Next::New if saved => self.dialog = Some(Dialog::NewStore { format: Format::Pkcs12, password: crate::keystore::DEFAULT_PASSWORD.into() }),
                            _ => {}
                        }
                    }
                }
                keep &= open;
            }
            Dialog::Error(msg) => {
                let mut open = true;
                modal(t!("Error")).open(&mut open).show(ctx, |ui| {
                    ui.set_width(420.0);
                    crate::estilo::alerta(ui, crate::estilo::Tipo::Error, msg.as_str());
                    ui.add_space(6.0);
                    if ui.button(t!("Aceptar")).clicked() {
                        keep = false;
                    }
                });
                keep &= open;
            }
        }
        if keep && self.dialog.is_none() {
            self.dialog = Some(d);
        }
    }

    /// Ventana «Agregar certificados». Devuelve si sigue abierta.
    fn add_dialog(&mut self, ctx: &Context, d: &mut AddDialog) -> bool {
        let mut open = true;
        let now = cert::now();
        let Some(doc) = &mut self.doc else { return false };
        // Veredicto de confianza (se recalcula si cambió el almacén).
        if let Some(c) = &d.chain {
            if d.verdict.as_ref().is_none_or(|(rev, _, _)| *rev != doc.rev) {
                let first = d.verdict.is_none();
                let anchors: Vec<&[u8]> = doc.ks.anchors().collect();
                let v = fetch::trusted(&c.fetched.chain, anchors.iter().copied(), &c.fetched.host);
                let rec = if v.is_err() { c.recommended(&anchors) } else { None };
                // Se marca solo lo que lo arregla (nada si Java ya confía o si
                // agregar no sirve de nada).
                if first {
                    for (k, cand) in d.candidates.iter_mut().enumerate() {
                        cand.checked = rec == Some(k);
                    }
                }
                d.verdict = Some((doc.rev, v, rec));
            }
        }
        let mut start = false;
        let mut add = false;
        let mut pick_file = false;
        let (red, orange, green) = colors_for(ctx.global_style().visuals.dark_mode);
        Window::new(t!("Agregar certificados"))
            .id(Id::NULL.with("agregar"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(720.0)
            .pivot(Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut d.mode, AddMode::Server, t!("De un servidor"));
                    ui.selectable_value(&mut d.mode, AddMode::File, t!("De un archivo o texto"));
                });
                ui.separator();
                match d.mode {
                    AddMode::Server => {
                        ui.horizontal(|ui| {
                            let busy = d.pending.is_some();
                            let r = ui.add(TextEdit::singleline(&mut d.input).hint_text(t!("servidor.ejemplo.com, https://…, smtp://…:587, jdbc:…")).desired_width(ui.available_width() - 330.0));
                            if d.focus_input {
                                r.request_focus();
                                d.focus_input = false;
                            }
                            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                            ComboBox::from_id_salt("protocolo").selected_text(d.protocol.label()).width(170.0).show_ui(ui, |ui| {
                                for p in Protocol::ALL {
                                    ui.selectable_value(&mut d.protocol, p, p.label());
                                }
                            });
                            let go = ui.add_enabled(!busy && !d.input.trim().is_empty(), IconButton::new(Icon::Download, Tone::Live).label(t!("Consultar")).framed().primary()).clicked();
                            if (go || enter) && !busy && !d.input.trim().is_empty() {
                                start = true;
                            }
                            if busy {
                                ui.spinner();
                            }
                        });
                        if let (Some(c), Some((_, v, rec))) = (&d.chain, &d.verdict) {
                            let f = &c.fetched;
                            ui.add_space(4.0);
                            ui.weak(tf!("{h}:{p} · {pr} · el servidor mandó {n} certificados", h = f.host, p = f.port, pr = f.protocol.label(), n = f.chain.len()));
                            ui.add_space(4.0);
                            let pal = Paleta::de(ui);
                            Frame::new().fill(pal.codigo).stroke(Stroke::new(1.0, pal.borde)).corner_radius(8.0).inner_margin(Margin::symmetric(12, 10)).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.spacing_mut().item_spacing.y = 6.0;
                            for (level, text) in diag::checks(c, v, *rec, now) {
                                let (icon, color) = match level {
                                    diag::Level::Ok => (Icon::Check, green),
                                    diag::Level::Warn => (Icon::Warning, orange),
                                    diag::Level::Bad => (Icon::Error, red),
                                };
                                let strong = level != diag::Level::Ok || text == t!("Java confía en este servidor con este almacén");
                                let mut rt = RichText::new(text).color(color);
                                if strong {
                                    rt = rt.strong();
                                }
                                crate::estilo::etiqueta(ui, icon, rt);
                            }
                            });
                        }
                    }
                    AddMode::File => {
                        ui.horizontal(|ui| {
                            if ui.add(IconButton::new(Icon::Open, Tone::File).label(t!("Elegir archivo…")).framed()).clicked() {
                                pick_file = true;
                            }
                            ui.weak(t!("o pega uno o varios certificados PEM:"));
                        });
                        let r = ui.add(TextEdit::multiline(&mut d.text).hint_text("-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----").font(TextStyle::Monospace).desired_rows(4).desired_width(f32::INFINITY));
                        if r.changed() {
                            match cert::parse_many(d.text.as_bytes()) {
                                Ok(ders) => {
                                    d.source = Some(t!("texto pegado").into());
                                    d.error = None;
                                    d.set_candidates(ders, &doc.ks);
                                }
                                Err(e) => {
                                    d.error = (!d.text.trim().is_empty()).then_some(e);
                                    d.candidates.clear();
                                }
                            }
                        }
                        if let Some(s) = &d.source {
                            ui.weak(tf!("{n} certificados de {s}", n = d.candidates.len(), s = s));
                        }
                    }
                }
                if let Some(e) = &d.error {
                    ui.add_space(4.0);
                    crate::estilo::alerta(ui, crate::estilo::Tipo::Error, e);
                }
                if !d.candidates.is_empty() {
                    ui.add_space(6.0);
                    let n = d.candidates.len();
                    ScrollArea::vertical().max_height(ctx.content_rect().height() * 0.5).auto_shrink([false, true]).show(ui, |ui| {
                        for (k, c) in d.candidates.iter_mut().enumerate() {
                            let existing = doc.ks.contains(&c.info.sha256).map(str::to_string);
                            // Tarjeta; la marcada, con borde del color de la app.
                            let pal = Paleta::de(ui);
                            let stroke = if c.checked { Stroke::new(1.5, crate::estilo::acento()) } else { Stroke::new(1.0, pal.borde) };
                            Frame::new().fill(pal.tarjeta).stroke(stroke).corner_radius(8.0).inner_margin(Margin::same(10)).outer_margin(Margin { bottom: 6, ..Default::default() }).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.add_enabled(existing.is_none(), Checkbox::without_text(&mut c.checked));
                                    let role = if d.mode == AddMode::File {
                                        String::new()
                                    } else if k == 0 {
                                        t!("Servidor").to_string()
                                    } else if c.info.self_signed {
                                        t!("Raíz").to_string()
                                    } else {
                                        t!("Intermedio").to_string()
                                    };
                                    if !role.is_empty() {
                                        ui.label(RichText::new(role).small().strong().color(crate::estilo::acento()));
                                    }
                                    ui.add(Label::new(RichText::new(&c.info.cn).strong()).truncate());
                                    let from = match &c.origin {
                                        Some(Origin::Java(j)) => Some((tf!("no lo manda el servidor; está en el cacerts de {j}", j = j), None)),
                                        Some(Origin::Aia(u)) => Some((t!("no lo manda el servidor; descargado de la dirección que indica su certificado hijo").to_string(), Some(u.clone()))),
                                        _ => None,
                                    };
                                    if let Some((text, tip)) = from {
                                        let r = ui.label(RichText::new(text).small().color(orange));
                                        if let Some(u) = tip {
                                            r.on_hover_text(u);
                                        }
                                    }
                                });
                                ui.horizontal_wrapped(|ui| {
                                    ui.add_space(24.0);
                                    let d_left = c.info.days_left(now);
                                    let col = if d_left < 0 { red } else if d_left < SOON_DAYS { orange } else { ui.visuals().weak_text_color() };
                                    ui.weak(tf!("emitido por {i}", i = c.info.issuer_cn));
                                    ui.label(RichText::new(tf!("· vence {f} ({t})", f = cert::date(c.info.not_after), t = expiry_text(&c.info, now))).small().color(col));
                                });
                                ui.horizontal(|ui| {
                                    ui.add_space(24.0);
                                    match &existing {
                                        Some(a) => {
                                            crate::estilo::etiqueta(ui, Icon::Check, RichText::new(tf!("Ya está en el almacén como «{a}»", a = a)).color(green));
                                        }
                                        None => {
                                            ui.label(t!("Alias:"));
                                            let taken = doc.ks.find(&c.alias).is_some();
                                            ui.add(TextEdit::singleline(&mut c.alias).desired_width(240.0).text_color_opt(taken.then_some(red)));
                                            if taken {
                                                ui.colored_label(red, t!("ya existe"));
                                            }
                                        }
                                    }
                                });
                            });
                        }
                    });
                    let todo: Vec<usize> = (0..n).filter(|&k| d.candidates[k].checked && doc.ks.contains(&d.candidates[k].info.sha256).is_none()).collect();
                    ui.add_space(6.0);
                    if d.mode == AddMode::Server && n > 1 {
                        ui.weak(t!("Consejo: agrega la autoridad (intermedio o raíz) en vez del certificado del servidor; así sigue valiendo cuando el servidor lo renueve."));
                    }
                    ui.horizontal(|ui| {
                        let ok = !todo.is_empty() && todo.iter().all(|&k| doc.ks.find(&d.candidates[k].alias).is_none() && !d.candidates[k].alias.trim().is_empty());
                        add = ui.add_enabled(ok, IconButton::new(Icon::Plus, Tone::Live).label(tf!("Agregar {n} al almacén", n = todo.len())).framed().primary()).clicked();
                    });
                }
            });
        if add {
            let mut n = 0;
            let mut last = None;
            for c in d.candidates.iter_mut().filter(|c| c.checked) {
                if doc.ks.contains(&c.info.sha256).is_some() {
                    continue;
                }
                match doc.ks.add(&c.alias, c.der.clone()) {
                    Ok(()) => {
                        n += 1;
                        doc.added.insert(c.alias.trim().to_lowercase());
                        last = Some(c.alias.to_lowercase());
                        c.checked = false;
                    }
                    Err(e) => self.avisos.error(e),
                }
            }
            if n > 0 {
                doc.changed(true);
                self.focus = last.and_then(|a| doc.ks.find(&a)).map(|i| doc.ks.entries[i].alias.clone());
                self.avisos.exito(tf!("Agregados {n} certificados. Guarda (Ctrl+S) para escribirlos en el archivo.", n = n));
            }
        }
        if pick_file {
            self.pick(Pick::AddFile, ctx);
            return false;
        }
        if start {
            let pool = self.pool();
            Self::start_fetch(d, ctx, pool);
        }
        open
    }

    /// Ventana «Comparar almacenes». Devuelve si sigue abierta.
    fn compare_dialog(&mut self, ctx: &Context, c: &mut Compare) -> bool {
        let mut open = true;
        let now = cert::now();
        let (mut pick_file, mut load, mut copy) = (false, None, false);
        let current = self.doc.as_ref().and_then(|d| d.path.as_ref()).and_then(|p| p.canonicalize().ok());
        // Opciones: los cacerts de los Java instalados y los almacenes recientes.
        let mut choices: Vec<(String, PathBuf)> = self.java.iter().map(|j| (format!("Java · {}", j.label), j.path.clone())).collect();
        for p in self.session.recent.iter().filter(|p| p.is_file()) {
            choices.push((p.display().to_string(), p.clone()));
        }
        let mut seen = BTreeSet::new();
        choices.retain(|(_, p)| {
            let real = p.canonicalize().unwrap_or_else(|_| p.clone());
            Some(&real) != current.as_ref() && seen.insert(real)
        });
        let Some(doc) = &mut self.doc else { return false };
        let (red, orange, green) = colors_for(ctx.global_style().visuals.dark_mode);
        Window::new(t!("Comparar almacenes"))
            .id(Id::NULL.with("comparar"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(780.0)
            .pivot(Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(t!("Comparar con:"));
                    let sel = c.path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| t!("(elige un almacén)").into());
                    ComboBox::from_id_salt("comparar_con").selected_text(sel).width((ui.available_width() - 170.0).max(200.0)).show_ui(ui, |ui| {
                        if choices.is_empty() {
                            ui.weak(t!("No se encontró ningún Java instalado"));
                        }
                        for (label, p) in &choices {
                            if ui.selectable_label(c.path.as_ref() == Some(p), label).on_hover_text(p.display().to_string()).clicked() {
                                load = Some(p.clone());
                            }
                        }
                    });
                    if ui.add(IconButton::new(Icon::Open, Tone::File).label(t!("Elegir archivo…")).framed()).clicked() {
                        pick_file = true;
                    }
                });
                if let Some(data) = &c.data {
                    let mut try_open = false;
                    ui.horizontal(|ui| {
                        ui.label(t!("Contraseña del otro almacén:"));
                        let r = ui.add(TextEdit::singleline(&mut c.password).password(true).desired_width(220.0));
                        try_open = (r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))) | ui.button(t!("Abrir")).clicked();
                    });
                    if try_open {
                        match Keystore::open(data, &c.password) {
                            Ok((ks, _)) => {
                                c.other = Some(ks);
                                c.error = None;
                            }
                            Err(e) => c.error = Some(e.to_string()),
                        }
                    }
                    if c.other.is_some() {
                        c.data = None;
                    }
                }
                if let Some(e) = &c.error {
                    crate::estilo::etiqueta(ui, Icon::Error, RichText::new(e.as_str()).color(red));
                }
                let Some(other) = &c.other else {
                    if c.path.is_none() {
                        ui.add_space(4.0);
                        ui.weak(t!("Elige otro almacén para ver qué certificados tiene uno y no el otro."));
                    }
                    return;
                };
                let (mine, theirs) = (prints(&doc.ks), prints(other));
                let only_theirs: Vec<usize> = theirs.iter().filter(|(k, _)| !mine.contains_key(*k)).map(|(_, &i)| i).collect();
                let only_mine: Vec<usize> = mine.iter().filter(|(k, _)| !theirs.contains_key(*k)).map(|(_, &i)| i).collect();
                let both = mine.len() - only_mine.len();
                let by_cn = |v: &mut Vec<usize>, ks: &Keystore| v.sort_by_key(|&i| ks.entries[i].info.as_ref().map(|x| x.cn.to_lowercase()).unwrap_or_default());
                let (mut only_theirs, mut only_mine) = (only_theirs, only_mine);
                by_cn(&mut only_theirs, other);
                by_cn(&mut only_mine, &doc.ks);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    crate::estilo::insignia(ui, &tf!("En los dos: {n}", n = both), green);
                    crate::estilo::insignia(ui, &tf!("Solo en el otro: {n}", n = only_theirs.len()), if only_theirs.is_empty() { Paleta::de(ui).apagado } else { orange });
                    crate::estilo::insignia(ui, &tf!("Solo en este: {n}", n = only_mine.len()), Paleta::de(ui).apagado);
                });
                ui.add_space(4.0);
                let h = (ctx.content_rect().height() * 0.5).max(160.0);
                let row = |ui: &mut Ui, e: &crate::keystore::Entry| {
                    let Some(info) = &e.info else { return };
                    ui.vertical(|ui| {
                        ui.add(Label::new(RichText::new(&info.cn).strong()).truncate());
                        let d = info.days_left(now);
                        let col = if d < 0 { red } else if d < SOON_DAYS { orange } else { ui.visuals().weak_text_color() };
                        ui.label(RichText::new(format!("{} · {}", e.alias, expiry_text(info, now))).small().color(col));
                    });
                };
                ui.columns(2, |cols| {
                    let ui = &mut cols[0];
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(t!("Solo en el otro").to_uppercase()).size(11.0).strong().color(Paleta::de(ui).apagado));
                        if !only_theirs.is_empty() {
                            if ui.small_button(t!("Todos")).clicked() {
                                c.checked = only_theirs.iter().filter_map(|&i| other.entries[i].info.as_ref().map(|x| x.sha256.clone())).collect();
                            }
                            if ui.small_button(t!("Ninguno")).clicked() {
                                c.checked.clear();
                            }
                        }
                    });
                    ScrollArea::vertical().id_salt("solo_otro").max_height(h).auto_shrink([false, true]).show(ui, |ui| {
                        if only_theirs.is_empty() {
                            ui.weak(t!("(ninguno)"));
                        }
                        for &i in &only_theirs {
                            let e = &other.entries[i];
                            let Some(sha) = e.info.as_ref().map(|x| x.sha256.clone()) else { continue };
                            ui.horizontal(|ui| {
                                let mut on = c.checked.contains(&sha);
                                if ui.add(Checkbox::without_text(&mut on)).changed() {
                                    if on {
                                        c.checked.insert(sha.clone());
                                    } else {
                                        c.checked.remove(&sha);
                                    }
                                }
                                row(ui, e);
                            });
                        }
                    });
                    let ui = &mut cols[1];
                    ui.label(RichText::new(t!("Solo en este").to_uppercase()).size(11.0).strong().color(Paleta::de(ui).apagado));
                    ScrollArea::vertical().id_salt("solo_este").max_height(h).auto_shrink([false, true]).show(ui, |ui| {
                        if only_mine.is_empty() {
                            ui.weak(t!("(ninguno)"));
                        }
                        for &i in &only_mine {
                            ui.horizontal(|ui| {
                                ui.add_space(24.0);
                                row(ui, &doc.ks.entries[i]);
                            });
                        }
                    });
                });
                ui.add_space(6.0);
                let n = c.checked.iter().filter(|s| !mine.contains_key(s.as_str())).count();
                copy = ui.add_enabled(n > 0, IconButton::new(Icon::Plus, Tone::Live).label(tf!("Copiar {n} a este almacén", n = n)).framed().primary()).clicked();
            });
        if copy {
            if let Some(other) = &c.other {
                let mut n = 0;
                let mut last = None;
                for sha in std::mem::take(&mut c.checked) {
                    let Some(e) = other.entries.iter().find(|e| e.info.as_ref().is_some_and(|x| x.sha256 == sha)) else { continue };
                    let (Some(der), Some(info)) = (e.der(), &e.info) else { continue };
                    if doc.ks.contains(&sha).is_some() {
                        continue;
                    }
                    let alias = if doc.ks.find(&e.alias).is_none() { e.alias.clone() } else { cert::alias_for(&info.cn, &|a| doc.ks.find(a).is_some()) };
                    match doc.ks.add(&alias, der.to_vec()) {
                        Ok(()) => {
                            n += 1;
                            doc.added.insert(alias.trim().to_lowercase());
                            last = Some(alias.to_lowercase());
                        }
                        Err(e) => self.avisos.error(e),
                    }
                }
                if n > 0 {
                    doc.changed(true);
                    self.focus = last.and_then(|a| doc.ks.find(&a)).map(|i| doc.ks.entries[i].alias.clone());
                    self.avisos.exito(tf!("Agregados {n} certificados. Guarda (Ctrl+S) para escribirlos en el archivo.", n = n));
                }
            }
        }
        if let Some(p) = load {
            c.load(p);
        }
        if pick_file {
            self.pick(Pick::Compare, ctx);
        }
        open
    }

    fn about_window(&mut self, ctx: &Context) {
        if !self.show_about {
            return;
        }
        let logo = crate::estilo::logo(ctx, &mut self.logo);
        let config = store::config_dir().map(|d| d.display().to_string()).unwrap_or_default();
        let backups = store::backups_dir().map(|d| d.display().to_string()).unwrap_or_default();
        let label = crate::update::version_label();
        let version = crate::estilo::Version { etiqueta: &label, actualizable: crate::update::SUPPORTED };
        if crate::estilo::acerca(ctx, &mut self.show_about, &logo, &version, |ui| {
            crate::estilo::fila_carpeta(ui, t!("Configuración"), &config);
            crate::estilo::fila_carpeta(ui, t!("Respaldos"), &backups);
        }) == crate::estilo::Accion::BuscarActualizaciones
        {
            self.open_updater(ctx);
        }
    }

    fn keys(&mut self, ctx: &Context) {
        let text_focus = ctx.memory(|m| m.focused().is_some());
        let no_dialog = self.dialog.is_none();
        let (o, s, ss, l, f, e, a, del) = ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::COMMAND, Key::O),
                i.consume_key(Modifiers::COMMAND, Key::S),
                i.consume_key(Modifiers::COMMAND | Modifiers::SHIFT, Key::S),
                i.consume_key(Modifiers::COMMAND, Key::L),
                i.consume_key(Modifiers::COMMAND, Key::F),
                i.consume_key(Modifiers::COMMAND, Key::E),
                !text_focus && i.consume_key(Modifiers::COMMAND, Key::A),
                !text_focus && i.consume_key(Modifiers::NONE, Key::Delete),
            )
        });
        if o {
            self.pick(Pick::Open, ctx);
        }
        if ss && self.doc.is_some() {
            let d = self.doc.as_ref().unwrap();
            self.dialog = Some(Dialog::SaveAs { format: d.ks.format, password: d.password.clone() });
        } else if s && self.doc.as_ref().is_some_and(|d| d.dirty) {
            self.save(ctx);
        }
        if l && self.doc.is_some() {
            self.open_add_server(ctx);
        }
        if f && self.doc.is_some() {
            self.focus_filter = true;
        }
        if no_dialog && self.doc.is_some() {
            if e && !self.checked.is_empty() {
                self.pick(Pick::Export(self.checked.iter().cloned().collect()), ctx);
            }
            if a {
                let vis = self.visible();
                let d = self.doc.as_ref().unwrap();
                self.checked = vis.iter().map(|&i| d.ks.entries[i].alias.clone()).collect();
            }
            if del {
                let list: Vec<String> = if self.checked.is_empty() { self.focus.iter().cloned().collect() } else { self.checked.iter().cloned().collect() };
                if !list.is_empty() {
                    self.dialog = Some(Dialog::ConfirmRemove { aliases: list });
                }
            }
            // Pegar un certificado (sin un campo de texto activo).
            if !text_focus {
                let pasted = ctx.input(|i| i.events.iter().find_map(|e| if let Event::Paste(s) = e { Some(s.clone()) } else { None }));
                if let Some(text) = pasted {
                    match cert::parse_many(text.as_bytes()) {
                        Ok(ders) => self.offer_certs(ders, t!("texto pegado").into()),
                        Err(e) => self.avisos.error(e),
                    }
                }
            }
        }
        // Arrastrar y soltar.
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        if let Some(p) = dropped.into_iter().next() {
            self.open_path(p);
        }
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            if self.dialog.is_some() {
                self.dialog = None;
            } else if self.rename.is_some() {
                self.rename = None;
            } else if self.show_keys {
                self.show_keys = false;
            } else if self.show_updater && !self.updater.as_ref().is_some_and(|u| u.stage() == crate::update::Stage::Running) {
                self.show_updater = false;
            }
        }
    }

    fn screenshot_step(&mut self, ctx: &Context) {
        let Some(path) = self.screenshot.clone() else { return };
        self.frames += 1;
        if self.frames == 3 {
            self.show_about = std::env::var_os("KEYUTIL_ACERCA").is_some();
            self.show_keys = std::env::var_os("KEYUTIL_ATAJOS").is_some();
            if let Ok(m) = std::env::var("KEYUTIL_AVISO") {
                self.avisos.auto(m);
            }
            if std::env::var_os("KEYUTIL_AJUSTES").is_some() {
                self.dialog = Some(Dialog::Settings);
            }
            if std::env::var_os("KEYUTIL_GUARDAR_COMO").is_some() {
                if let Some(d) = &self.doc {
                    self.dialog = Some(Dialog::SaveAs { format: d.ks.format, password: d.password.clone() });
                }
            }
            if let Ok(f) = std::env::var("KEYUTIL_BUSCAR") {
                self.filter = f;
            }
            if let Ok(a) = std::env::var("KEYUTIL_FOCO") {
                self.focus = self.doc.as_ref().and_then(|d| d.ks.find(&a)).map(|i| self.doc.as_ref().unwrap().ks.entries[i].alias.clone());
            }
            if std::env::var_os("KEYUTIL_MARCAR_VENCIDOS").is_some() {
                let now = cert::now();
                if let Some(d) = &self.doc {
                    self.checked = d.ks.entries.iter().filter(|e| e.info.as_ref().is_some_and(|i| i.expired(now))).map(|e| e.alias.clone()).collect();
                }
            }
            if std::env::var_os("KEYUTIL_SERVIDOR").is_some() {
                self.open_add_server(ctx);
            }
            if let Ok(f) = std::env::var("KEYUTIL_COMPARAR") {
                let mut c = Compare::default();
                c.load(f.into());
                if let Some(o) = &c.other {
                    c.checked = o.entries.iter().filter_map(|e| e.info.as_ref().map(|x| x.sha256.clone())).take(2).collect();
                }
                self.dialog = Some(Dialog::Compare(Box::new(c)));
            }
            if let Ok(f) = std::env::var("KEYUTIL_PEGAR") {
                if let Ok(ders) = std::fs::read(&f).map_err(|e| e.to_string()).and_then(|b| cert::parse_many(&b)) {
                    self.offer_certs(ders, f);
                }
            }
        }
        // KEYUTIL_AGREGAR=1: pulsa «Agregar» en cuanto llega la cadena del servidor.
        if std::env::var_os("KEYUTIL_AGREGAR").is_some() {
            if let (Some(Dialog::Add(a)), Some(doc)) = (&mut self.dialog, &mut self.doc) {
                if a.pending.is_none() && a.candidates.iter().any(|c| c.checked) {
                    for c in a.candidates.iter_mut().filter(|c| c.checked) {
                        if doc.ks.add(&c.alias, c.der.clone()).is_ok() {
                            doc.added.insert(c.alias.trim().to_lowercase());
                        }
                        c.checked = false;
                    }
                    doc.changed(true);
                    self.dialog = None;
                }
            }
        }
        let busy = matches!(&self.dialog, Some(Dialog::Add(a)) if a.pending.is_some());
        if self.frames < 40 || busy {
            ctx.request_repaint();
            return;
        }
        if self.frames < 1000 {
            self.frames = 1000;
            ctx.send_viewport_cmd(ViewportCommand::Screenshot(ScreenshotCallback::new(move |img| {
                let mut out = Vec::with_capacity(8 + img.pixels.len() * 4);
                out.extend_from_slice(&(img.size[0] as u32).to_le_bytes());
                out.extend_from_slice(&(img.size[1] as u32).to_le_bytes());
                out.extend_from_slice(img.as_raw());
                std::fs::write(&path, out).unwrap();
                std::process::exit(0);
            })));
        }
    }
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

impl eframe::App for App {
    fn persist_egui_memory(&self) -> bool {
        false
    }

    /// En macOS, Ctrl hace de Cmd (atajos y copiar/cortar/pegar).
    fn raw_input_hook(&mut self, ctx: &Context, raw: &mut RawInput) {
        crate::estilo::ctrl_mac(ctx, raw);
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        self.keys(&ctx);
        let (settings_key, keys_key) = crate::estilo::atajos_comunes(&ctx);
        if settings_key {
            self.dialog = if matches!(self.dialog, Some(Dialog::Settings)) { None } else { Some(Dialog::Settings) };
        }
        if keys_key {
            self.show_keys = !self.show_keys;
        }
        self.vigia.tick(&ctx, self.session.check_updates.unwrap_or(true) && self.screenshot.is_none());
        Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(2.0);
            self.toolbar(ui);
            ui.add_space(2.0);
        });
        self.status_bar(ui);
        if self.doc.is_some() {
            Panel::right("detalle").resizable(true).default_size(340.0).min_size(260.0).show(ui, |ui| self.detail(ui));
            CentralPanel::default().frame(crate::estilo::marco_central(ui.style())).show(ui, |ui| self.list(ui));
        } else {
            CentralPanel::default().frame(crate::estilo::marco_central(ui.style())).show(ui, |ui| self.welcome(ui));
        }
        self.dialogs(&ctx);
        self.about_window(&ctx);
        self.updater_window(&ctx);
        crate::estilo::ventana_atajos(
            &ctx,
            &mut self.show_keys,
            &[(
                t!("Almacén"),
                vec![
                    (crate::estilo::tecla("Ctrl+O"), t!("Abrir un almacén")),
                    (crate::estilo::tecla("Ctrl+S"), t!("Guardar")),
                    (crate::estilo::tecla("Ctrl+Shift+S"), t!("Guardar como (otro formato o contraseña)")),
                    (crate::estilo::tecla("Ctrl+L"), t!("Agregar de un servidor")),
                    (crate::estilo::tecla("Ctrl+V"), t!("Agregar los certificados PEM copiados")),
                    (crate::estilo::tecla("Ctrl+F"), t!("Buscar")),
                    (crate::estilo::tecla("Ctrl+A"), t!("Marcar los visibles")),
                    (crate::estilo::tecla("Ctrl+E"), t!("Exportar los marcados")),
                    (t!("Supr").to_string(), t!("Quitar los marcados (o el elegido)")),
                    (t!("Arrastrar un archivo").to_string(), t!("Abrir el almacén o agregar el certificado")),
                ],
            )],
        );
        self.avisos.mostrar(&ctx);
        if ctx.input(|i| i.viewport().close_requested()) && !self.close_ok && self.doc.as_ref().is_some_and(|d| d.dirty) {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            self.dialog = Some(Dialog::Unsaved(Next::Close));
        }
        if self.session_dirty && (self.last_session_save.elapsed() > Duration::from_secs(2) || ctx.input(|i| i.viewport().close_requested())) {
            let _ = store::save_session(&self.session);
            self.session_dirty = false;
            self.last_session_save = Instant::now();
        }
        self.screenshot_step(&ctx);
    }
}
