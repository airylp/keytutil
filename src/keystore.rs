//! Almacenes de certificados de Java: JKS (Java 8 y anteriores) y PKCS12
//! (Java 9 en adelante; el `cacerts` actual). Se leen, se modifican en memoria
//! y se vuelven a escribir; las entradas con clave privada se conservan tal
//! cual (en JKS, los bytes cifrados de la clave sin tocar).
//!
//! JKS: formato binario propio de Sun (lector y escritor aquí mismo); la
//! integridad es un SHA-1 de la contraseña en UTF-16BE + «Mighty Aphrodite» +
//! el contenido. Solo JKS guarda la fecha en que se agregó cada entrada.
//! PKCS12: `p12-keystore` (marca los certificados de confianza con el atributo
//! de Oracle que Java necesita para tratarlos como `trustedCertEntry`).

use crate::cert::CertInfo;
use p12_keystore::{Certificate as P12Cert, KeyStore as P12, KeyStoreEntry, Pkcs12ImportPolicy};
use sha1::{Digest, Sha1};

const JKS_MAGIC: u32 = 0xFEED_FEED;
const JCEKS_MAGIC: u32 = 0xCECE_CECE;

/// Contraseña de fábrica del `cacerts` de Java.
pub const DEFAULT_PASSWORD: &str = "changeit";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Jks,
    Pkcs12,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Jks => "JKS",
            Format::Pkcs12 => "PKCS12",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Certificado de confianza (lo que hay en un cacerts).
    Trusted,
    /// Clave privada con su cadena de certificados.
    KeyPair,
    /// Clave secreta (solo PKCS12): se conserva pero no se muestra su contenido.
    Secret,
}

#[derive(Clone, Debug)]
enum Raw {
    None,
    /// JKS: clave privada cifrada, tal como estaba.
    JksKey(Vec<u8>),
    /// PKCS12: la entrada original (clave privada o secreta).
    P12(KeyStoreEntry),
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub alias: String,
    pub kind: Kind,
    /// DER: el certificado (confianza) o la cadena (clave privada, primero el propio).
    pub certs: Vec<Vec<u8>>,
    /// Datos del primer certificado (si se pudo leer).
    pub info: Option<CertInfo>,
    /// Cuándo se agregó, en milisegundos desde 1970 (solo JKS).
    pub added_ms: Option<i64>,
    raw: Raw,
}

impl Entry {
    pub fn trusted(alias: String, der: Vec<u8>) -> Entry {
        let info = CertInfo::parse(&der).ok();
        Entry { alias, kind: Kind::Trusted, certs: vec![der], info, added_ms: Some(now_ms()), raw: Raw::None }
    }

    pub fn der(&self) -> Option<&[u8]> {
        self.certs.first().map(Vec::as_slice)
    }
}

fn now_ms() -> i64 {
    crate::cert::now() * 1000
}

#[derive(Clone, Debug)]
pub struct Keystore {
    pub format: Format,
    pub entries: Vec<Entry>,
    /// Si la contraseña con que se abrió se comprobó contra el archivo (JKS y
    /// PKCS12 con integridad); `false` si se abrió sin contraseña.
    pub verified: bool,
}

#[derive(Debug, PartialEq)]
pub enum OpenError {
    /// Hace falta (otra) contraseña.
    Password,
    Invalid(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Password => f.write_str(t!("contraseña incorrecta")),
            OpenError::Invalid(s) => f.write_str(s),
        }
    }
}

pub fn is_jks(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == JKS_MAGIC
}

/// ¿Parece un almacén (y no un certificado suelto)?
pub fn looks_like_keystore(data: &[u8]) -> bool {
    is_jks(data) || (data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == JCEKS_MAGIC) || {
        // PKCS12: DER que empieza por SEQUENCE con versión 3.
        data.first() == Some(&0x30) && crate::cert::parse_many(data).is_err() && data.windows(3).take(12).any(|w| w == [0x02, 0x01, 0x03])
    }
}

impl Keystore {
    pub fn new(format: Format) -> Keystore {
        Keystore { format, entries: vec![], verified: true }
    }

    /// Abre un almacén. Con contraseña vacía: JKS se lee sin comprobar la
    /// integridad (como `keytool -list` sin contraseña) y PKCS12 prueba
    /// «changeit».
    pub fn open(data: &[u8], password: &str) -> Result<(Keystore, String), OpenError> {
        if data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == JCEKS_MAGIC {
            return Err(OpenError::Invalid(t!("es un almacén JCEKS; conviértelo a PKCS12 con keytool -importkeystore").into()));
        }
        if is_jks(data) {
            let entries = parse_jks(data)?;
            let mut pw = password.to_string();
            let verified = if pw.is_empty() {
                // Sin contraseña: si es la de fábrica, queda comprobada.
                if jks_hash(&data[..data.len() - 20], DEFAULT_PASSWORD) == data[data.len() - 20..] {
                    pw = DEFAULT_PASSWORD.into();
                    true
                } else {
                    false
                }
            } else if jks_hash(&data[..data.len() - 20], password) == data[data.len() - 20..] {
                true
            } else {
                return Err(OpenError::Password);
            };
            return Ok((Keystore { format: Format::Jks, entries, verified }, pw));
        }
        let tries: Vec<&str> = if password.is_empty() { vec![DEFAULT_PASSWORD, ""] } else { vec![password] };
        let mut last = OpenError::Password;
        for pw in tries {
            // «Relaxed» enlaza cada clave con su cadena; «Raw» trae además los
            // certificados sin el atributo de confianza de Java (los de openssl).
            match P12::from_pkcs12(data, pw, Pkcs12ImportPolicy::Relaxed) {
                Ok(ks) => {
                    let raw = P12::from_pkcs12(data, pw, Pkcs12ImportPolicy::Raw).ok();
                    return Ok((from_p12(&ks, raw.as_ref()), pw.to_string()));
                }
                Err(p12_keystore::error::Error::MacError(_) | p12_keystore::error::Error::UnpadError | p12_keystore::error::Error::Pkcs5Error(_)) => last = OpenError::Password,
                Err(e) => last = OpenError::Invalid(tf!("no es un almacén JKS ni PKCS12 válido ({e})", e = e)),
            }
        }
        Err(last)
    }

    /// Bytes del almacén en `format` (puede ser distinto del original: convertir).
    pub fn write(&self, format: Format, password: &str) -> Result<Vec<u8>, String> {
        if password.is_empty() {
            return Err(t!("hace falta una contraseña para guardar el almacén").into());
        }
        match format {
            Format::Jks => {
                if self.entries.iter().any(|e| matches!(e.raw, Raw::P12(_))) {
                    return Err(t!("las claves de un PKCS12 no se pueden pasar a JKS; guárdalo como PKCS12").into());
                }
                Ok(write_jks(&self.entries, password))
            }
            Format::Pkcs12 => {
                let mut ks = P12::new();
                for e in &self.entries {
                    let entry = match (&e.raw, e.kind) {
                        (Raw::P12(x), _) => x.clone(),
                        (Raw::JksKey(_), _) => return Err(t!("las claves privadas de un JKS no se pueden pasar a PKCS12; guárdalo como JKS").into()),
                        (Raw::None, _) => KeyStoreEntry::Certificate(P12Cert::from_der(&e.certs[0]).map_err(|x| x.to_string())?),
                    };
                    ks.add_entry(&e.alias, entry);
                }
                ks.writer(password).write().map_err(|e| tf!("no se pudo generar el PKCS12: {e}", e = e))
            }
        }
    }

    pub fn find(&self, alias: &str) -> Option<usize> {
        // JKS no distingue mayúsculas en los alias (keytool los guarda en minúsculas).
        self.entries.iter().position(|e| e.alias.eq_ignore_ascii_case(alias))
    }

    /// Alias de la entrada de confianza con este certificado, si ya está.
    pub fn contains(&self, sha256: &str) -> Option<&str> {
        self.entries.iter().find(|e| e.info.as_ref().is_some_and(|i| i.sha256 == sha256)).map(|e| e.alias.as_str())
    }

    /// Agrega un certificado de confianza. Error si el alias ya existe.
    pub fn add(&mut self, alias: &str, der: Vec<u8>) -> Result<(), String> {
        let alias = alias.trim();
        if alias.is_empty() {
            return Err(t!("falta el alias").into());
        }
        if self.find(alias).is_some() {
            return Err(tf!("ya hay una entrada «{a}»", a = alias));
        }
        CertInfo::parse(&der)?;
        let alias = if self.format == Format::Jks { alias.to_lowercase() } else { alias.to_string() };
        self.entries.push(Entry::trusted(alias, der));
        self.sort();
        Ok(())
    }

    pub fn remove(&mut self, alias: &str) -> Option<Entry> {
        self.find(alias).map(|i| self.entries.remove(i))
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), String> {
        let new = new.trim();
        if new.is_empty() {
            return Err(t!("falta el alias").into());
        }
        let i = self.find(old).ok_or_else(|| tf!("no existe «{a}»", a = old))?;
        if self.find(new).is_some_and(|j| j != i) {
            return Err(tf!("ya hay una entrada «{a}»", a = new));
        }
        self.entries[i].alias = if self.format == Format::Jks { new.to_lowercase() } else { new.to_string() };
        self.sort();
        Ok(())
    }

    pub fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.alias.to_lowercase());
    }

    /// DER de todos los certificados de confianza (anclas para comprobar un servidor).
    pub fn anchors(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.iter().filter(|e| e.kind == Kind::Trusted).filter_map(Entry::der)
    }
}

fn from_p12(ks: &P12, raw: Option<&P12>) -> Keystore {
    let mut entries: Vec<Entry> = Vec::new();
    for (alias, e) in ks.entries() {
        let (kind, certs): (Kind, Vec<Vec<u8>>) = match e {
            KeyStoreEntry::Certificate(c) => (Kind::Trusted, vec![c.as_der().to_vec()]),
            KeyStoreEntry::PrivateKeyChain(ch) => (Kind::KeyPair, ch.certs().iter().map(|c| c.as_der().to_vec()).collect()),
            KeyStoreEntry::Secret(_) => (Kind::Secret, vec![]),
        };
        let raw = if kind == Kind::Trusted { Raw::None } else { Raw::P12(e.clone()) };
        let info = certs.first().and_then(|d| CertInfo::parse(d).ok());
        entries.push(Entry { alias: alias.clone(), kind, certs, info, added_ms: None, raw });
    }
    // Certificados sueltos que no son de ninguna cadena ni están ya.
    if let Some(raw) = raw {
        for (alias, e) in raw.entries() {
            let KeyStoreEntry::Certificate(c) = e else { continue };
            let der = c.as_der();
            if entries.iter().any(|x| x.certs.iter().any(|d| d == der)) || entries.iter().any(|x| x.alias.eq_ignore_ascii_case(alias)) {
                continue;
            }
            entries.push(Entry { alias: alias.clone(), kind: Kind::Trusted, certs: vec![der.to_vec()], info: CertInfo::parse(der).ok(), added_ms: None, raw: Raw::None });
        }
    }
    let mut k = Keystore { format: Format::Pkcs12, entries, verified: true };
    k.sort();
    k
}

// ------------------------------------------------------------------ JKS

fn jks_hash(body: &[u8], password: &str) -> [u8; 20] {
    let mut h = Sha1::new();
    for u in password.encode_utf16() {
        h.update(u.to_be_bytes());
    }
    h.update(b"Mighty Aphrodite");
    h.update(body);
    h.finalize().into()
}

struct Reader<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], OpenError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.d.len()).ok_or_else(|| OpenError::Invalid(t!("archivo JKS dañado o incompleto").into()))?;
        let s = &self.d[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, OpenError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, OpenError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// Texto «UTF modificado» de Java (para alias normales coincide con UTF-8).
    fn utf(&mut self) -> Result<String, OpenError> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let b = self.take(n)?;
        Ok(String::from_utf8_lossy(b).into_owned())
    }
    fn cert(&mut self) -> Result<Vec<u8>, OpenError> {
        let _type = self.utf()?; // «X.509»
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

fn parse_jks(data: &[u8]) -> Result<Vec<Entry>, OpenError> {
    if data.len() < 32 {
        return Err(OpenError::Invalid(t!("archivo JKS dañado o incompleto").into()));
    }
    let mut r = Reader { d: &data[..data.len() - 20], pos: 0 };
    r.u32()?;
    let version = r.u32()?;
    if version != 2 && version != 1 {
        return Err(OpenError::Invalid(tf!("versión de JKS no admitida ({v})", v = version)));
    }
    let count = r.u32()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let tag = r.u32()?;
        let alias = r.utf()?;
        let added = r.i64()?;
        match tag {
            2 => {
                let der = if version == 2 { r.cert()? } else {
                    let n = r.u32()? as usize;
                    r.take(n)?.to_vec()
                };
                let info = CertInfo::parse(&der).ok();
                out.push(Entry { alias, kind: Kind::Trusted, certs: vec![der], info, added_ms: Some(added), raw: Raw::None });
            }
            1 => {
                let n = r.u32()? as usize;
                let key = r.take(n)?.to_vec();
                let chain = r.u32()?;
                let mut certs = Vec::new();
                for _ in 0..chain {
                    certs.push(r.cert()?);
                }
                let info = certs.first().and_then(|d| CertInfo::parse(d).ok());
                out.push(Entry { alias, kind: Kind::KeyPair, certs, info, added_ms: Some(added), raw: Raw::JksKey(key) });
            }
            t => return Err(OpenError::Invalid(tf!("tipo de entrada JKS desconocido ({t})", t = t))),
        }
    }
    let mut k = Keystore { format: Format::Jks, entries: out, verified: true };
    k.sort();
    Ok(k.entries)
}

fn write_jks(entries: &[Entry], password: &str) -> Vec<u8> {
    fn utf(b: &mut Vec<u8>, s: &str) {
        b.extend_from_slice(&(s.len() as u16).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    fn cert(b: &mut Vec<u8>, der: &[u8]) {
        utf(b, "X.509");
        b.extend_from_slice(&(der.len() as u32).to_be_bytes());
        b.extend_from_slice(der);
    }
    let mut b = Vec::new();
    b.extend_from_slice(&JKS_MAGIC.to_be_bytes());
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        let added = e.added_ms.unwrap_or_else(now_ms);
        match &e.raw {
            Raw::JksKey(key) => {
                b.extend_from_slice(&1u32.to_be_bytes());
                utf(&mut b, &e.alias);
                b.extend_from_slice(&added.to_be_bytes());
                b.extend_from_slice(&(key.len() as u32).to_be_bytes());
                b.extend_from_slice(key);
                b.extend_from_slice(&(e.certs.len() as u32).to_be_bytes());
                for c in &e.certs {
                    cert(&mut b, c);
                }
            }
            _ => {
                b.extend_from_slice(&2u32.to_be_bytes());
                utf(&mut b, &e.alias);
                b.extend_from_slice(&added.to_be_bytes());
                cert(&mut b, &e.certs[0]);
            }
        }
    }
    let h = jks_hash(&b, password);
    b.extend_from_slice(&h);
    b
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // Generados con keytool (JDK 21), contraseña «changeit»: tests/fixtures.
    const JKS: &[u8] = include_bytes!("../tests/fixtures/muestra.jks");
    const P12_FILE: &[u8] = include_bytes!("../tests/fixtures/muestra.p12");
    const CON_CLAVE: &[u8] = include_bytes!("../tests/fixtures/conclave.jks");
    pub const RAIZ_PEM: &str = include_str!("../tests/fixtures/raiz.pem");
    pub const SERVIDOR_PEM: &str = include_str!("../tests/fixtures/servidor.pem");

    pub fn sample_der() -> Vec<u8> {
        crate::cert::parse_many(RAIZ_PEM.as_bytes()).unwrap().remove(0)
    }

    #[test]
    fn opens_jks_and_checks_password() {
        let (ks, pw) = Keystore::open(JKS, "changeit").unwrap();
        assert_eq!(pw, "changeit");
        assert_eq!(ks.format, Format::Jks);
        assert!(ks.verified);
        let aliases: Vec<_> = ks.entries.iter().map(|e| e.alias.as_str()).collect();
        assert_eq!(aliases, ["raiz", "servidor"]);
        assert!(ks.entries.iter().all(|e| e.added_ms.is_some() && e.info.is_some()));
        // El fixture se generó cuando la app se llamaba «keytutil».
        assert_eq!(ks.entries[1].info.as_ref().unwrap().cn, "servidor.keytutil.test");
        assert_eq!(Keystore::open(JKS, "otra").unwrap_err(), OpenError::Password);
        // Sin contraseña: se prueba la de fábrica.
        let (ks, pw) = Keystore::open(JKS, "").unwrap();
        assert!(ks.verified);
        assert_eq!(pw, "changeit");
    }

    #[test]
    fn opens_pkcs12() {
        let (ks, pw) = Keystore::open(P12_FILE, "").unwrap();
        assert_eq!((ks.format, pw.as_str()), (Format::Pkcs12, "changeit"));
        assert_eq!(ks.entries.len(), 2);
        assert!(ks.entries.iter().all(|e| e.kind == Kind::Trusted && e.added_ms.is_none()));
        assert_eq!(Keystore::open(P12_FILE, "otra").unwrap_err(), OpenError::Password);
        assert!(matches!(Keystore::open(b"basura cualquiera", "x"), Err(OpenError::Invalid(_))));
        assert!(looks_like_keystore(P12_FILE) && looks_like_keystore(JKS));
        assert!(!looks_like_keystore(RAIZ_PEM.as_bytes()) && !looks_like_keystore(&sample_der()));
    }

    #[test]
    fn add_remove_rename_round_trip() {
        for (data, format) in [(JKS, Format::Jks), (P12_FILE, Format::Pkcs12)] {
            let (mut ks, pw) = Keystore::open(data, "changeit").unwrap();
            assert!(ks.add("RAIZ", sample_der()).is_err(), "alias repetido");
            ks.add("Otra-Raiz", sample_der()).unwrap();
            ks.remove("servidor").unwrap();
            ks.rename("raiz", "la-raiz").unwrap();
            let bytes = ks.write(format, &pw).unwrap();
            let (again, _) = Keystore::open(&bytes, "changeit").unwrap();
            let aliases: Vec<_> = again.entries.iter().map(|e| e.alias.to_lowercase()).collect();
            assert_eq!(aliases, ["la-raiz", "otra-raiz"], "{format:?}");
            assert_eq!(again.contains(&crate::cert::sha256(&sample_der())).map(str::to_lowercase).as_deref(), Some("la-raiz"));
        }
    }

    #[test]
    fn converts_between_formats() {
        let (ks, _) = Keystore::open(JKS, "changeit").unwrap();
        let p12 = ks.write(Format::Pkcs12, "nueva").unwrap();
        let (b, _) = Keystore::open(&p12, "nueva").unwrap();
        assert_eq!((b.format, b.entries.len()), (Format::Pkcs12, 2));
        let jks = b.write(Format::Jks, "changeit").unwrap();
        assert_eq!(Keystore::open(&jks, "changeit").unwrap().0.entries.len(), 2);
    }

    /// La clave privada de un JKS se conserva byte a byte al reescribirlo.
    #[test]
    fn keeps_private_keys() {
        let (mut ks, pw) = Keystore::open(CON_CLAVE, "changeit").unwrap();
        assert_eq!(ks.entries.iter().map(|e| e.kind).collect::<Vec<_>>(), [Kind::Trusted, Kind::KeyPair]);
        let before = ks.entries[1].clone();
        ks.remove("raiz");
        let bytes = ks.write(Format::Jks, &pw).unwrap();
        let (again, _) = Keystore::open(&bytes, "changeit").unwrap();
        let after = &again.entries[0];
        assert_eq!((after.kind, &after.certs, after.added_ms), (Kind::KeyPair, &before.certs, before.added_ms));
        assert!(matches!((&after.raw, &before.raw), (Raw::JksKey(a), Raw::JksKey(b)) if a == b));
        assert!(ks.write(Format::Pkcs12, "changeit").is_err());
        // Mismo contenido → mismos bytes que keytool (orden aparte).
        let (orig, _) = Keystore::open(CON_CLAVE, "changeit").unwrap();
        assert_eq!(orig.write(Format::Jks, "changeit").unwrap().len(), CON_CLAVE.len());
    }

    /// Un PKCS12 con clave privada conserva la clave enlazada a su cadena.
    #[test]
    fn keeps_pkcs12_key_chain() {
        let data = include_bytes!("../tests/fixtures/servidor.p12");
        let (mut ks, pw) = Keystore::open(data, "changeit").unwrap();
        assert_eq!(ks.entries.iter().map(|e| e.kind).collect::<Vec<_>>(), [Kind::KeyPair], "{:?}", ks.entries.iter().map(|e| &e.alias).collect::<Vec<_>>());
        assert_eq!(ks.entries[0].certs.len(), 2);
        ks.add("raiz", sample_der()).unwrap();
        let (again, _) = Keystore::open(&ks.write(Format::Pkcs12, &pw).unwrap(), "changeit").unwrap();
        let kinds: Vec<_> = again.entries.iter().map(|e| (e.alias.as_str(), e.kind, e.certs.len())).collect();
        assert_eq!(kinds, [("raiz", Kind::Trusted, 1), ("servidor", Kind::KeyPair, 2)]);
    }

    /// Los cacerts reales de Java 8 (JKS) y 21 (PKCS12): KEYUTIL_CACERTS=ruta1:ruta2.
    #[test]
    #[ignore]
    fn real_cacerts() {
        let Ok(list) = std::env::var("KEYUTIL_CACERTS") else { return };
        for p in list.split(':') {
            let data = std::fs::read(p).unwrap();
            let (ks, pw) = Keystore::open(&data, "").unwrap();
            println!("{p}: {} {} entradas, contraseña «{pw}», comprobada: {}", ks.format.name(), ks.entries.len(), ks.verified);
            assert!(ks.entries.len() > 50 && ks.entries.iter().all(|e| e.info.is_some()));
            let out = ks.write(ks.format, "changeit").unwrap();
            assert_eq!(Keystore::open(&out, "changeit").unwrap().0.entries.len(), ks.entries.len());
            if let Ok(dir) = std::env::var("KEYUTIL_SALIDA") {
                std::fs::write(format!("{dir}/{}.salida", std::path::Path::new(p).file_name().unwrap().to_string_lossy()), out).unwrap();
            }
        }
    }
}
