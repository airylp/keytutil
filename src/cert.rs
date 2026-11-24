//! Certificados X.509: datos para mostrar, PEM ⇄ DER, lectura de archivos
//! con uno o varios certificados y alias a partir del nombre.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Lo que se muestra de un certificado.
#[derive(Clone, Debug, PartialEq)]
pub struct CertInfo {
    /// Nombre común del titular (o el titular completo si no tiene CN).
    pub cn: String,
    pub subject: String,
    pub issuer: String,
    pub issuer_cn: String,
    pub serial: String,
    /// Vigencia en segundos desde 1970 (UTC).
    pub not_before: i64,
    pub not_after: i64,
    /// Nombres alternativos (DNS e IP).
    pub sans: Vec<String>,
    pub sha256: String,
    pub sha1: String,
    pub is_ca: bool,
    pub self_signed: bool,
    /// «RSA 2048», «EC 256»…
    pub key: String,
    pub signature: String,
}

impl CertInfo {
    pub fn parse(der: &[u8]) -> Result<CertInfo, String> {
        let (_, c) = X509Certificate::from_der(der).map_err(|e| tf!("certificado no válido: {e}", e = e))?;
        let cn_of = |n: &X509Name| {
            n.iter_common_name().next().and_then(|a| a.as_str().ok()).map(str::to_string).unwrap_or_else(|| {
                // Sin CN: la organización o, si no, el nombre completo.
                n.iter_organization().next().and_then(|a| a.as_str().ok()).map(str::to_string).unwrap_or_else(|| n.to_string())
            })
        };
        let sans = c
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .filter_map(|g| match g {
                        GeneralName::DNSName(d) => Some(d.to_string()),
                        GeneralName::IPAddress(ip) => match ip.len() {
                            4 => Some(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string()),
                            16 => <[u8; 16]>::try_from(*ip).ok().map(|b| std::net::Ipv6Addr::from(b).to_string()),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let reg = x509_parser::objects::oid_registry();
        let pk = c.public_key();
        let alg = x509_parser::objects::oid2sn(&pk.algorithm.algorithm, reg).unwrap_or("?");
        let alg = match alg {
            "rsaEncryption" => "RSA",
            "id-ecPublicKey" => "EC",
            "id-Ed25519" | "ED25519" => "Ed25519",
            "id-Ed448" | "ED448" => "Ed448",
            a => a,
        };
        let key = match pk.parsed() {
            Ok(p) if p.key_size() > 0 && alg != "Ed25519" => format!("{alg} {}", p.key_size()),
            _ => alg.to_string(),
        };
        let signature = x509_parser::objects::oid2sn(&c.signature_algorithm.algorithm, reg).unwrap_or("?").to_string();
        Ok(CertInfo {
            cn: cn_of(c.subject()),
            subject: c.subject().to_string(),
            issuer: c.issuer().to_string(),
            issuer_cn: cn_of(c.issuer()),
            serial: c.raw_serial_as_string().to_uppercase(),
            not_before: c.validity().not_before.timestamp(),
            not_after: c.validity().not_after.timestamp(),
            sans,
            sha256: fingerprint::<Sha256>(der),
            sha1: fingerprint::<Sha1>(der),
            is_ca: c.is_ca(),
            self_signed: c.subject().as_raw() == c.issuer().as_raw(),
            key,
            signature,
        })
    }

    /// Días hasta que vence (negativo si ya venció).
    pub fn days_left(&self, now: i64) -> i64 {
        (self.not_after - now).div_euclid(86_400)
    }

    pub fn expired(&self, now: i64) -> bool {
        now > self.not_after
    }

    /// Texto para buscar: alias aparte, aquí nombre, emisor, huellas y serie.
    pub fn haystack(&self) -> String {
        format!("{}\n{}\n{}\n{}\n{}\n{}", self.subject, self.issuer, self.sha256, self.sha1, self.serial, self.sans.join(" ")).to_lowercase()
    }
}

/// Huella en hexadecimal con dos puntos, como `keytool` y `openssl`.
fn fingerprint<D: Digest>(der: &[u8]) -> String {
    D::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
pub fn sha256(der: &[u8]) -> String {
    fingerprint::<Sha256>(der)
}

/// Segundos actuales desde 1970.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Fecha civil (año, mes, día) de un día contado desde 1970-01-01.
fn civil(days: i64) -> (i64, u32, u32) {
    // Algoritmo de Howard Hinnant (days_from_civil inverso).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// «2026-11-23» (UTC).
pub fn date(ts: i64) -> String {
    let (y, m, d) = civil(ts.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// «2026-11-23 18:05 UTC».
pub fn date_time(ts: i64) -> String {
    let s = ts.rem_euclid(86_400);
    format!("{} {:02}:{:02} UTC", date(ts), s / 3600, s % 3600 / 60)
}

/// «20261123-180512» (para nombres de archivo, hora local no hace falta).
pub fn stamp_now() -> String {
    let t = now();
    let s = t.rem_euclid(86_400);
    format!("{}-{:02}{:02}{:02}", date(t).replace('-', ""), s / 3600, s % 3600 / 60, s % 60)
}

/// PEM (líneas de 64 caracteres).
pub fn to_pem(der: &[u8]) -> String {
    let b = B64.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

/// Todos los certificados de un archivo o texto: uno o varios bloques PEM
/// (`.pem`, `.crt`, cadenas completas), DER (`.cer`, `.der`) o el base64 del
/// DER sin cabeceras. Devuelve los DER en el orden en que aparecen.
pub fn parse_many(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if X509Certificate::from_der(bytes).is_ok() {
        return Ok(vec![bytes.to_vec()]);
    }
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut rest = &*text;
    while let Some(i) = rest.find("-----BEGIN") {
        let after = &rest[i..];
        let Some(head_end) = after[10..].find("-----").map(|j| j + 15) else { break };
        let kind = &after[11..head_end - 5];
        let Some(end) = after.find("-----END") else { break };
        if kind.trim().ends_with("CERTIFICATE") && !kind.contains("REQUEST") {
            let body: String = after[head_end..end].lines().map(str::trim).filter(|l| !l.contains(':')).collect();
            let der = B64.decode(body.as_bytes()).map_err(|_| t!("un bloque PEM tiene base64 inválido").to_string())?;
            X509Certificate::from_der(&der).map_err(|e| tf!("certificado no válido: {e}", e = e))?;
            out.push(der);
        }
        rest = &after[end + 8..];
    }
    if out.is_empty() {
        // Base64 suelto (copiado sin las líneas BEGIN/END).
        let body: String = text.split_whitespace().collect();
        if let Ok(der) = B64.decode(body.as_bytes()) {
            if X509Certificate::from_der(&der).is_ok() {
                return Ok(vec![der]);
            }
        }
        return Err(t!("no se encontró ningún certificado (se esperaba PEM o DER)").into());
    }
    Ok(out)
}

/// Alias para un certificado nuevo: su nombre común en minúsculas, sin
/// caracteres raros, y distinto de los que ya hay (`-2`, `-3`…).
pub fn alias_for(cn: &str, taken: &dyn Fn(&str) -> bool) -> String {
    let mut base = String::new();
    let cn = cn.trim().replace("*.", "comodin.").replace('*', "comodin");
    for c in cn.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
            base.push(c);
        } else if !base.ends_with('-') && !base.is_empty() {
            base.push('-');
        }
    }
    let base = base.trim_matches(['-', '.']);
    let base = if base.is_empty() { "certificado".to_string() } else { base.chars().take(60).collect() };
    if !taken(&base) {
        return base;
    }
    (2..).map(|n| format!("{base}-{n}")).find(|a| !taken(a)).unwrap()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_795_392_000), "2026-11-23");
        assert_eq!(date(-86_400), "1969-12-31");
        assert_eq!(date_time(1_795_392_000 + 3600 + 120), "2026-11-23 01:02 UTC");
    }

    #[test]
    fn aliases() {
        let none = |_: &str| false;
        assert_eq!(alias_for("Mi Servidor (pruebas)", &none), "mi-servidor-pruebas");
        assert_eq!(alias_for("*.ejemplo.com", &none), "comodin.ejemplo.com");
        assert_eq!(alias_for("  ", &none), "certificado");
        let taken = |a: &str| a == "x" || a == "x-2";
        assert_eq!(alias_for("X", &taken), "x-3");
    }

    #[test]
    fn pem_round_trip_and_bundles() {
        let der = crate::keystore::tests::sample_der();
        let pem = to_pem(&der);
        assert_eq!(parse_many(pem.as_bytes()).unwrap(), vec![der.clone()]);
        assert_eq!(parse_many(&der).unwrap(), vec![der.clone()]);
        let bundle = format!("texto\n{pem}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{pem}");
        assert_eq!(parse_many(bundle.as_bytes()).unwrap().len(), 2);
        let loose: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("\n");
        assert_eq!(parse_many(loose.as_bytes()).unwrap(), vec![der.clone()]);
        assert!(parse_many(b"hola").is_err());
        let info = CertInfo::parse(&der).unwrap();
        assert!(!info.cn.is_empty());
        assert_eq!(info.sha256.len(), 32 * 3 - 1);
    }
}
