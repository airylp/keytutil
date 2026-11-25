//! Certificados que presenta un servidor: conexión TLS directa (HTTPS, LDAPS,
//! IMAPS…) o STARTTLS de correo (SMTP, IMAP, POP3), sin validar nada (el
//! objetivo es ver la cadena). Después, `trusted` comprueba si la cadena es de
//! confianza con los certificados de un almacén, como lo haría Java.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(8);

/// Cómo se llega al saludo TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Según el esquema o el puerto.
    Auto,
    Tls,
    Smtp,
    Imap,
    Pop3,
}

impl Protocol {
    pub const ALL: [Protocol; 5] = [Protocol::Auto, Protocol::Tls, Protocol::Smtp, Protocol::Imap, Protocol::Pop3];

    pub fn label(self) -> &'static str {
        match self {
            Protocol::Auto => t!("Automático (por puerto)"),
            Protocol::Tls => t!("TLS directo"),
            Protocol::Smtp => "STARTTLS · SMTP",
            Protocol::Imap => "STARTTLS · IMAP",
            Protocol::Pop3 => "STARTTLS · POP3",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Protocol::Auto | Protocol::Tls => "TLS",
            Protocol::Smtp => "SMTP",
            Protocol::Imap => "IMAP",
            Protocol::Pop3 => "POP3",
        }
    }

    /// Puertos donde el servicio empieza en claro y espera STARTTLS.
    fn for_port(port: u16) -> Protocol {
        match port {
            25 | 587 | 2525 => Protocol::Smtp,
            143 => Protocol::Imap,
            110 => Protocol::Pop3,
            _ => Protocol::Tls,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// Protocolo que implica el esquema (`smtp://`…); `None` sin esquema.
    pub implied: Option<Protocol>,
}

/// `https://host[:puerto]/ruta`, otros esquemas (`smtp`, `submission`, `smtps`,
/// `imap`, `imaps`, `pop3`, `pop3s`, `ldaps`, `ftps`, `jdbc:…//host:puerto`) o
/// solo `host` / `host:puerto` (443 si falta).
pub fn parse_target(input: &str) -> Result<Target, String> {
    let mut s = input.trim();
    if s.is_empty() {
        return Err(t!("escribe una URL o un host").into());
    }
    // jdbc:postgresql://host:5432/db, jdbc:sqlserver://host:1433;… → host y puerto.
    if let Some(rest) = s.strip_prefix("jdbc:") {
        s = rest.find("//").map(|i| &rest[i + 2..]).unwrap_or(rest);
    }
    let (default, implied, rest) = match s.split_once("://") {
        Some((scheme, rest)) => {
            let (port, p) = match scheme.to_ascii_lowercase().as_str() {
                "https" | "wss" => (443, Protocol::Tls),
                "smtps" => (465, Protocol::Tls),
                "smtp" => (25, Protocol::Smtp),
                "submission" => (587, Protocol::Smtp),
                "imaps" => (993, Protocol::Tls),
                "imap" => (143, Protocol::Imap),
                "pop3s" => (995, Protocol::Tls),
                "pop3" => (110, Protocol::Pop3),
                "ldaps" => (636, Protocol::Tls),
                "ftps" => (990, Protocol::Tls),
                "http" => return Err(t!("http:// no usa certificados; ¿querías https://?").into()),
                other => return Err(tf!("esquema no admitido: {s}://", s = other)),
            };
            (port, Some(p), rest)
        }
        None => (443, None, s),
    };
    // Quitar ruta, consulta y usuario.
    let hostport = rest.split(['/', '?', '#', ';']).next().unwrap_or("");
    let hostport = hostport.rsplit('@').next().unwrap_or("");
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| t!("dirección IPv6 mal escrita").to_string())?;
        (h.to_string(), after.strip_prefix(':'))
    } else if hostport.matches(':').count() > 1 {
        (hostport.to_string(), None) // IPv6 sin corchetes ni puerto
    } else {
        match hostport.split_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (hostport.to_string(), None),
        }
    };
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err(t!("falta un host válido").into());
    }
    let port = match port {
        Some(p) => p.parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(|| t!("el puerto no es válido").to_string())?,
        None => default,
    };
    Ok(Target { host: host.to_lowercase(), port, implied })
}

#[derive(Clone, Debug)]
pub struct Fetched {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    /// Como la manda el servidor: el suyo primero.
    pub chain: Vec<Vec<u8>>,
    /// Versión de TLS y cifrado acordados («TLS 1.3 · TLS13_AES_256_GCM_SHA384»).
    pub tls: String,
}

#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Conecta y devuelve la cadena (bloquea: llamar desde un hilo).
pub fn fetch(input: &str, protocol: Protocol) -> Result<Fetched, String> {
    let target = parse_target(input)?;
    let protocol = match protocol {
        Protocol::Auto => target.implied.unwrap_or_else(|| Protocol::for_port(target.port)),
        p => p,
    };
    let Target { host, port, .. } = target;
    let addrs: Vec<_> = (host.as_str(), port).to_socket_addrs().map_err(|e| tf!("no se encontró {h}: {e}", h = host, e = e))?.collect();
    // IPv4 primero (muchas redes no tienen salida IPv6) y el primer error es el que cuenta.
    let mut addrs = addrs;
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut tcp = None;
    let mut last = String::new();
    for a in &addrs {
        match TcpStream::connect_timeout(a, TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) if last.is_empty() => last = e.to_string(),
            Err(_) => {}
        }
    }
    let mut tcp = tcp.ok_or_else(|| tf!("no se pudo conectar a {h}:{p}: {e}", h = host, p = port, e = last))?;
    tcp.set_read_timeout(Some(TIMEOUT)).ok();
    tcp.set_write_timeout(Some(TIMEOUT)).ok();
    if protocol != Protocol::Tls {
        starttls(&mut tcp, protocol)?;
    }
    let p = provider();
    let config = ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(p)))
        .with_no_client_auth();
    let name = ServerName::try_from(host.clone()).map_err(|_| t!("falta un host válido").to_string())?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut tcp) {
            let hint = if protocol == Protocol::Tls { t!(" (si ese puerto empieza en claro, como un servidor de correo, prueba con STARTTLS)") } else { "" };
            return Err(tf!("no se completó el saludo TLS: {e}{h}", e = e, h = hint));
        }
    }
    let chain: Vec<Vec<u8>> = conn.peer_certificates().unwrap_or_default().iter().map(|c| c.to_vec()).collect();
    if chain.is_empty() {
        return Err(t!("el servidor no presentó ningún certificado").into());
    }
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".to_string(),
        Some(v) => format!("{v:?}"),
        None => "TLS".to_string(),
    };
    let tls = match conn.negotiated_cipher_suite() {
        Some(cs) => format!("{version} · {:?}", cs.suite()),
        None => version,
    };
    conn.send_close_notify();
    let _ = conn.complete_io(&mut tcp);
    Ok(Fetched { host, port, protocol, chain, tls })
}

/// Conversa en claro con el servidor de correo hasta que acepta STARTTLS.
fn starttls(tcp: &mut TcpStream, protocol: Protocol) -> Result<(), String> {
    let name = protocol.short();
    let mut w = tcp.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(tcp.try_clone().map_err(|e| e.to_string())?.take(64 << 10));
    let mut line = || -> Result<String, String> {
        let mut s = String::new();
        match r.read_line(&mut s) {
            Ok(0) => Err(t!("el servidor cerró la conexión antes de pasar a TLS").into()),
            Ok(_) => Ok(s.trim_end().to_string()),
            Err(e) => Err(tf!("se cortó la conexión con el servidor: {e}", e = e)),
        }
    };
    let bad = |step: &str, l: &str| tf!("el servidor no aceptó STARTTLS ({p}, {s}): {l}", p = name, s = step, l = l.chars().take(200).collect::<String>());
    let mut send = |s: &str| w.write_all(s.as_bytes()).map_err(|e| tf!("se cortó la conexión con el servidor: {e}", e = e));
    // Respuesta SMTP de una o varias líneas (`250-…` … `250 …`).
    let smtp = |line: &mut dyn FnMut() -> Result<String, String>, code: &str, step: &str| -> Result<(), String> {
        for _ in 0..100 {
            let l = line()?;
            if !l.starts_with(code) {
                return Err(bad(step, &l));
            }
            if l.as_bytes().get(3) != Some(&b'-') {
                return Ok(());
            }
        }
        Err(bad(step, "…"))
    };
    match protocol {
        Protocol::Smtp => {
            smtp(&mut line, "220", t!("saludo"))?;
            send("EHLO keyutil\r\n")?;
            smtp(&mut line, "250", "EHLO")?;
            send("STARTTLS\r\n")?;
            smtp(&mut line, "220", "STARTTLS")?;
        }
        Protocol::Imap => {
            let g = line()?;
            if !g.starts_with("* OK") {
                return Err(bad(t!("saludo"), &g));
            }
            send("a1 STARTTLS\r\n")?;
            for _ in 0..100 {
                let l = line()?;
                if let Some(rest) = l.strip_prefix("a1 ") {
                    if rest.starts_with("OK") {
                        break;
                    }
                    return Err(bad("STARTTLS", &l));
                }
            }
        }
        Protocol::Pop3 => {
            let g = line()?;
            if !g.starts_with("+OK") {
                return Err(bad(t!("saludo"), &g));
            }
            send("STLS\r\n")?;
            let l = line()?;
            if !l.starts_with("+OK") {
                return Err(bad("STLS", &l));
            }
        }
        Protocol::Auto | Protocol::Tls => {}
    }
    if !r.buffer().is_empty() {
        return Err(tf!("el servidor {p} mandó datos inesperados después de aceptar STARTTLS", p = name));
    }
    Ok(())
}

/// Descarga por HTTP (sin TLS) lo que hay en `url`: los certificados de los
/// emisores (AIA «caIssuers») se publican así. Sigue hasta 3 redirecciones.
pub fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let mut url = url.trim().to_string();
    for _ in 0..4 {
        let rest = url.strip_prefix("http://").ok_or_else(|| tf!("dirección no compatible: {u}", u = url))?;
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, p.parse::<u16>().map_err(|_| tf!("dirección no compatible: {u}", u = url))?),
            _ => (hostport, 80),
        };
        let addr = (host.trim_matches(['[', ']']), port).to_socket_addrs().map_err(|e| tf!("no se encontró {h}: {e}", h = host, e = e))?.min_by_key(|a| a.is_ipv6()).ok_or_else(|| tf!("no se encontró {h}: {e}", h = host, e = "-"))?;
        let mut tcp = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| tf!("no se pudo conectar a {h}:{p}: {e}", h = host, p = port, e = e))?;
        tcp.set_read_timeout(Some(TIMEOUT)).ok();
        tcp.set_write_timeout(Some(TIMEOUT)).ok();
        write!(tcp, "GET {path} HTTP/1.0\r\nHost: {hostport}\r\nUser-Agent: keyutil\r\nAccept: */*\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
        let mut resp = Vec::new();
        tcp.take(4 << 20).read_to_end(&mut resp).map_err(|e| e.to_string())?;
        let end = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| t!("respuesta HTTP no válida").to_string())?;
        let head = String::from_utf8_lossy(&resp[..end]).to_string();
        let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        if (300..400).contains(&status) {
            if let Some(loc) = head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("location")).map(|(_, v)| v.trim().to_string())) {
                url = if loc.starts_with('/') { format!("http://{hostport}{loc}") } else { loc };
                continue;
            }
        }
        if status != 200 {
            return Err(tf!("{u} respondió {c}", u = url, c = status));
        }
        return Ok(resp[end + 4..].to_vec());
    }
    Err(t!("demasiadas redirecciones").into())
}

/// ¿Confiaría Java en esta cadena con los certificados del almacén? `Ok(())`
/// o el motivo. Comprueba firmas, vigencia y que el nombre coincida.
pub fn trusted<'a>(chain: &[Vec<u8>], anchors: impl Iterator<Item = &'a [u8]>, host: &str) -> Result<(), String> {
    let mut roots = rustls::RootCertStore::empty();
    let (_ok, _bad) = roots.add_parsable_certificates(anchors.map(|d| CertificateDer::from(d.to_vec())));
    if roots.is_empty() {
        return Err(t!("el almacén no tiene certificados de confianza").into());
    }
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build().map_err(|e| e.to_string())?;
    let end = CertificateDer::from(chain[0].clone());
    let rest: Vec<CertificateDer> = chain[1..].iter().map(|d| CertificateDer::from(d.clone())).collect();
    let name = ServerName::try_from(host.to_string()).map_err(|_| t!("falta un host válido").to_string())?;
    match verifier.verify_server_cert(&end, &rest, &name, &[], UnixTime::now()) {
        Ok(_) => Ok(()),
        Err(rustls::Error::InvalidCertificate(e)) => Err(match e {
            rustls::CertificateError::UnknownIssuer => t!("ningún certificado del almacén respalda esta cadena").to_string(),
            rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. } => t!("el certificado del servidor está vencido").to_string(),
            rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. } => t!("el certificado no es para ese nombre de host").to_string(),
            rustls::CertificateError::NotValidYet | rustls::CertificateError::NotValidYetContext { .. } => t!("el certificado aún no es válido").to_string(),
            other => format!("{other:?}"),
        }),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> (String, u16, Option<Protocol>) {
        let t = parse_target(s).unwrap();
        (t.host, t.port, t.implied)
    }

    #[test]
    fn targets() {
        assert_eq!(t("https://Ejemplo.com/ruta?x=1"), ("ejemplo.com".into(), 443, Some(Protocol::Tls)));
        assert_eq!(t("https://ejemplo.com:8443"), ("ejemplo.com".into(), 8443, Some(Protocol::Tls)));
        assert_eq!(t("smtp://mail.ejemplo.com:587"), ("mail.ejemplo.com".into(), 587, Some(Protocol::Smtp)));
        assert_eq!(t("imaps://usuario@mail.ejemplo.com"), ("mail.ejemplo.com".into(), 993, Some(Protocol::Tls)));
        assert_eq!(t("mail.ejemplo.com:465"), ("mail.ejemplo.com".into(), 465, None));
        assert_eq!(t("  ejemplo.com  "), ("ejemplo.com".into(), 443, None));
        assert_eq!(t("[::1]:993"), ("::1".into(), 993, None));
        assert_eq!(t("jdbc:postgresql://db.ejemplo.com:5432/base"), ("db.ejemplo.com".into(), 5432, None));
        assert_eq!(t("jdbc:sqlserver://sql.ejemplo.com:1433;databaseName=x"), ("sql.ejemplo.com".into(), 1433, None));
        assert!(parse_target("gopher://x").is_err());
        assert!(parse_target("http://x").is_err());
        assert!(parse_target("").is_err());
        assert!(parse_target("host:99999").is_err());
        assert_eq!(Protocol::for_port(587), Protocol::Smtp);
        assert_eq!(Protocol::for_port(8443), Protocol::Tls);
    }

    /// Servidor TLS local con el certificado de los fixtures (firmado por
    /// «raiz»): se lee la cadena y se comprueba la confianza.
    #[test]
    fn local_server_chain_and_trust() {
        use crate::keystore::tests::{RAIZ_PEM, SERVIDOR_PEM};
        // Clave del servidor (sacada de servidor.p12 con openssl: PKCS8 con la clave pública, como pide ring).
        let pem = include_str!("../tests/fixtures/servidor-clave.pem");
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).unwrap().into());
        let leaf = crate::cert::parse_many(SERVIDOR_PEM.as_bytes()).unwrap().remove(0);
        let root = crate::cert::parse_many(RAIZ_PEM.as_bytes()).unwrap().remove(0);
        let certs = vec![CertificateDer::from(leaf.clone()), CertificateDer::from(root.clone())];
        let config = rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(certs, key).unwrap();
        let config = Arc::new(config);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in listener.incoming().take(1) {
                let mut s = s.unwrap();
                let mut c = rustls::ServerConnection::new(config.clone()).unwrap();
                while c.is_handshaking() {
                    if c.complete_io(&mut s).is_err() {
                        break;
                    }
                }
                let _ = c.complete_io(&mut s);
            }
        });
        let f = fetch(&format!("127.0.0.1:{port}"), Protocol::Auto).unwrap();
        assert_eq!(f.chain, vec![leaf.clone(), root.clone()]);
        assert_eq!(f.protocol, Protocol::Tls);
        // Con la raíz en el almacén: de confianza (el certificado tiene IP:127.0.0.1).
        assert_eq!(trusted(&f.chain, [root.as_slice()].into_iter(), "127.0.0.1"), Ok(()));
        // Con otro nombre o sin la raíz, no.
        assert!(trusted(&f.chain, [root.as_slice()].into_iter(), "otro.ejemplo").is_err());
        assert!(trusted(&f.chain[..1], std::iter::empty(), "127.0.0.1").is_err());
    }

    /// Servidores reales (red): KEYUTIL_RED=1 cargo test -- --ignored red
    #[test]
    #[ignore]
    fn red_servidores_reales() {
        for (h, p) in [("www.google.com", Protocol::Auto), ("smtp.gmail.com:587", Protocol::Auto), ("outlook.office365.com:143", Protocol::Imap), ("outlook.office365.com:995", Protocol::Auto)] {
            let f = fetch(h, p).unwrap_or_else(|e| panic!("{h}: {e}"));
            println!("{h}: {:?} {} certificados: {}", f.protocol, f.chain.len(), crate::cert::CertInfo::parse(&f.chain[0]).unwrap().cn);
        }
    }
}
