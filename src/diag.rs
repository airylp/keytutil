//! Diagnóstico de la conexión con un servidor: trae la cadena, la completa
//! hasta la raíz (con lo que haya en el almacén, en los cacerts de otros Java
//! o descargando los emisores por AIA) y dice qué falla y qué agregar.

use crate::cert::{self, CertInfo, Links};
use crate::fetch::{self, Fetched, Protocol};
use std::path::PathBuf;

/// De dónde salió un certificado de la cadena.
#[derive(Clone, Debug, PartialEq)]
pub enum Origin {
    /// Lo mandó el servidor.
    Server,
    /// Ya está en el almacén abierto.
    Store,
    /// Está en el cacerts de otro Java (nombre del JDK).
    Java(String),
    /// Se descargó de la dirección que indica el certificado hijo (AIA).
    Aia(String),
}

#[derive(Clone, Debug)]
pub struct Link {
    pub der: Vec<u8>,
    pub info: CertInfo,
    pub origin: Origin,
}

/// Resultado de la consulta (lo que no depende del almacén abierto).
#[derive(Clone, Debug)]
pub struct Chain {
    pub fetched: Fetched,
    /// Del certificado del servidor hacia la raíz.
    pub links: Vec<Link>,
    /// Se llegó a una raíz (autofirmada).
    pub complete: bool,
    /// El servidor mandó la cadena en otro orden.
    pub disordered: bool,
    /// Certificados que mandó el servidor y no forman parte de la cadena.
    pub unused: Vec<String>,
    /// Emisor que no se encontró, o motivo por el que no se pudo descargar.
    pub missing: Option<String>,
}

/// Lugares donde buscar emisores que el servidor no manda.
pub struct Pool {
    /// Certificados de confianza del almacén abierto.
    pub store: Vec<Vec<u8>>,
    /// Otros cacerts (nombre, ruta).
    pub java: Vec<(String, PathBuf)>,
}

/// Consulta el servidor y completa la cadena (bloquea: llamar desde un hilo).
pub fn run(input: &str, protocol: Protocol, pool: Pool) -> Result<Chain, String> {
    let fetched = fetch::fetch(input, protocol)?;
    Ok(complete(fetched, pool, &fetch::http_get))
}

fn complete(fetched: Fetched, pool: Pool, get: &dyn Fn(&str) -> Result<Vec<u8>, String>) -> Chain {
    let sent: Vec<(Vec<u8>, Links)> = fetched.chain.iter().filter_map(|d| Links::of(d).map(|l| (d.clone(), l))).collect();
    let disordered = sent.windows(2).any(|w| !w[0].1.issued_by(&w[1].1) && !w[0].1.self_signed());
    // Otros cacerts: se leen solo si hacen falta.
    let mut java: Option<Vec<(String, Vec<u8>, Links)>> = None;
    let load_java = |pool: &Pool| -> Vec<(String, Vec<u8>, Links)> {
        let mut v = Vec::new();
        for (label, path) in &pool.java {
            let Ok(data) = std::fs::read(path) else { continue };
            let Ok((ks, _)) = crate::keystore::Keystore::open(&data, "") else { continue };
            for d in ks.anchors() {
                if let Some(l) = Links::of(d) {
                    v.push((label.clone(), d.to_vec(), l));
                }
            }
        }
        v
    };
    let store: Vec<(Vec<u8>, Links)> = pool.store.iter().filter_map(|d| Links::of(d).map(|l| (d.clone(), l))).collect();
    let mut links: Vec<(Vec<u8>, Links, Origin)> = Vec::new();
    let mut used = vec![false; sent.len()];
    if let Some((d, l)) = sent.first() {
        links.push((d.clone(), l.clone(), Origin::Server));
        used[0] = true;
    }
    let mut complete = false;
    let mut missing = None;
    while let Some((_, cur, _)) = links.last().cloned() {
        if cur.self_signed() {
            complete = true;
            break;
        }
        if links.len() >= 10 {
            break;
        }
        let seen = |d: &[u8], links: &[(Vec<u8>, Links, Origin)]| links.iter().any(|(x, _, _)| x == d);
        if let Some(i) = (0..sent.len()).find(|&i| !seen(&sent[i].0, &links) && cur.issued_by(&sent[i].1)) {
            used[i] = true;
            links.push((sent[i].0.clone(), sent[i].1.clone(), Origin::Server));
            continue;
        }
        if let Some((d, l)) = store.iter().find(|(d, l)| !seen(d, &links) && cur.issued_by(l)) {
            links.push((d.clone(), l.clone(), Origin::Store));
            continue;
        }
        let java = java.get_or_insert_with(|| load_java(&pool));
        if let Some((label, d, l)) = java.iter().find(|(_, d, l)| !seen(d, &links) && cur.issued_by(l)) {
            links.push((d.clone(), l.clone(), Origin::Java(label.clone())));
            continue;
        }
        let mut found = None;
        let mut why = None;
        for url in cur.ca_issuers.iter().filter(|u| u.starts_with("http://")) {
            match get(url) {
                Ok(body) => {
                    let ders = cert::parse_many(&body).unwrap_or_else(|_| cert::certs_in_der(&body));
                    found = ders.into_iter().filter_map(|d| Links::of(&d).map(|l| (d, l))).find(|(d, l)| !seen(d, &links) && cur.issued_by(l)).map(|(d, l)| (d, l, url.clone()));
                    if found.is_some() {
                        break;
                    }
                }
                Err(e) => why = Some(e),
            }
        }
        match found {
            Some((d, l, url)) => links.push((d, l, Origin::Aia(url))),
            None => {
                let name = links.last().and_then(|(d, _, _)| CertInfo::parse(d).ok()).map(|i| i.issuer_cn).unwrap_or_default();
                missing = Some(match why {
                    Some(e) => tf!("no se pudo descargar «{n}»: {e}", n = name, e = e),
                    None => tf!("no se encontró «{n}»", n = name),
                });
                break;
            }
        }
    }
    let unused = sent.iter().zip(&used).filter(|(_, u)| !**u).filter_map(|((d, _), _)| CertInfo::parse(d).ok()).map(|i| i.cn).collect();
    let links = links.into_iter().filter_map(|(der, _, origin)| CertInfo::parse(&der).ok().map(|info| Link { der, info, origin })).collect();
    Chain { fetched, links, complete, disordered, unused, missing }
}

impl Chain {
    /// La intermedia que el servidor debería mandar y no manda.
    pub fn missing_intermediate(&self) -> Option<&Link> {
        self.links.iter().find(|l| l.origin != Origin::Server && !l.info.self_signed)
    }

    /// Índice del certificado (el más alto de la cadena) que, agregado al
    /// almacén, haría que Java confíe en el servidor.
    pub fn recommended<'a>(&self, anchors: &[&'a [u8]]) -> Option<usize> {
        (0..self.links.len()).rev().find(|&i| {
            let extra = self.links[i].der.as_slice();
            !anchors.contains(&extra) && fetch::trusted(&self.fetched.chain, anchors.iter().copied().chain(std::iter::once(extra)), &self.fetched.host).is_ok()
        })
    }
}

/// ¿El certificado es para `host`? (nombres alternativos o, si no tiene, el CN).
pub fn name_matches(info: &CertInfo, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let names: Vec<String> = if info.sans.is_empty() { vec![info.cn.clone()] } else { info.sans.clone() };
    names.iter().any(|n| {
        let n = n.trim_end_matches('.').to_ascii_lowercase();
        match n.strip_prefix("*.") {
            Some(base) => host.split_once('.').is_some_and(|(first, rest)| !first.is_empty() && rest == base),
            None => n == host,
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Level {
    Ok,
    Warn,
    Bad,
}

/// Lista de comprobaciones para mostrar.
pub fn checks(c: &Chain, verdict: &Result<(), String>, recommended: Option<usize>, now: i64) -> Vec<(Level, String)> {
    let mut v = Vec::new();
    let f = &c.fetched;
    v.push((Level::Ok, tf!("Conexión {pr}: {tls}", pr = f.protocol.label(), tls = f.tls)));
    if let Some(leaf) = c.links.first() {
        if name_matches(&leaf.info, &f.host) {
            v.push((Level::Ok, tf!("El certificado es para {h}", h = f.host)));
        } else {
            let names = if leaf.info.sans.is_empty() { leaf.info.cn.clone() } else { leaf.info.sans.iter().take(6).cloned().collect::<Vec<_>>().join(", ") };
            v.push((Level::Bad, tf!("El certificado no es para {h} (es para: {n})", h = f.host, n = names)));
        }
    }
    let mut dates_ok = true;
    for l in &c.links {
        let d = l.info.days_left(now);
        if now < l.info.not_before {
            v.push((Level::Bad, tf!("«{n}» aún no es válido (desde {f})", n = l.info.cn, f = cert::date(l.info.not_before))));
            dates_ok = false;
        } else if d < 0 {
            v.push((Level::Bad, tf!("«{n}» venció el {f}", n = l.info.cn, f = cert::date(l.info.not_after))));
            dates_ok = false;
        } else if d < 30 {
            v.push((Level::Warn, tf!("«{n}» vence en {d} días", n = l.info.cn, d = d)));
            dates_ok = false;
        }
    }
    if dates_ok {
        v.push((Level::Ok, t!("Todos los certificados de la cadena están vigentes").into()));
    }
    match c.missing_intermediate() {
        Some(l) => v.push((Level::Warn, tf!("El servidor no manda la intermedia «{n}»: Java no puede armar la cadena aunque tenga la raíz", n = l.info.cn))),
        None if c.links.len() > 1 || c.complete => v.push((Level::Ok, t!("El servidor manda las intermedias que hacen falta").into())),
        None => {}
    }
    if c.disordered {
        v.push((Level::Warn, t!("El servidor manda la cadena en desorden").into()));
    }
    if !c.unused.is_empty() {
        v.push((Level::Warn, tf!("El servidor manda certificados que sobran: {l}", l = c.unused.join(", "))));
    }
    if let Some(m) = &c.missing {
        v.push((Level::Warn, tf!("No se pudo completar la cadena hasta la raíz: {m}", m = m)));
    }
    match verdict {
        Ok(()) => v.push((Level::Ok, t!("Java confía en este servidor con este almacén").into())),
        Err(why) => {
            v.push((Level::Bad, tf!("Java no confiaría en este servidor: {m}", m = why)));
            match recommended {
                Some(i) => {
                    let l = &c.links[i];
                    let role = if i == 0 { t!("el certificado del servidor") } else if l.info.self_signed { t!("la raíz") } else { t!("la intermedia") };
                    v.push((Level::Ok, tf!("Se arregla agregando {r} «{n}» (ya está marcado abajo)", r = role, n = l.info.cn)));
                }
                None => v.push((Level::Warn, t!("Agregar certificados no lo arregla: hay que corregirlo en el servidor").into())),
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::tests::{RAIZ_PEM, SERVIDOR_PEM};

    fn der(pem: &str) -> Vec<u8> {
        cert::parse_many(pem.as_bytes()).unwrap().remove(0)
    }

    fn fetched(chain: Vec<Vec<u8>>) -> Fetched {
        Fetched { host: "127.0.0.1".into(), port: 443, protocol: Protocol::Tls, chain, tls: "TLS 1.3".into() }
    }

    #[test]
    fn links_and_p7() {
        let (leaf, root) = (der(SERVIDOR_PEM), der(RAIZ_PEM));
        let (l, r) = (Links::of(&leaf).unwrap(), Links::of(&root).unwrap());
        assert!(l.issued_by(&r) && !r.issued_by(&l));
        assert!(r.self_signed() && !l.self_signed());
        // Un contenedor DER cualquiera con los dos dentro (como un .p7c).
        let mut body = root.clone();
        body.extend_from_slice(&leaf);
        let mut wrap = vec![0x30, 0x82, (body.len() >> 8) as u8, body.len() as u8];
        wrap.extend_from_slice(&body);
        assert_eq!(cert::certs_in_der(&wrap), vec![root, leaf]);
    }

    #[test]
    fn completes_chain_from_store_java_or_aia() {
        let (leaf, root) = (der(SERVIDOR_PEM), der(RAIZ_PEM));
        let none = |_: &str| -> Result<Vec<u8>, String> { Err("sin red".into()) };
        // El servidor manda todo.
        let c = complete(fetched(vec![leaf.clone(), root.clone()]), Pool { store: vec![], java: vec![] }, &none);
        assert!(c.complete && c.missing.is_none() && !c.disordered && c.unused.is_empty());
        assert_eq!(c.links.len(), 2);
        assert!(c.missing_intermediate().is_none());
        // Solo el suyo; la raíz está en el almacén.
        let c = complete(fetched(vec![leaf.clone()]), Pool { store: vec![root.clone()], java: vec![] }, &none);
        assert!(c.complete);
        assert_eq!(c.links[1].origin, Origin::Store);
        // Ni en el almacén ni descargable: incompleta, con el motivo.
        let c = complete(fetched(vec![leaf.clone()]), Pool { store: vec![], java: vec![] }, &none);
        assert!(!c.complete && c.missing.is_some());
        // Recomendación: agregar la raíz.
        let c = complete(fetched(vec![leaf.clone(), root.clone()]), Pool { store: vec![], java: vec![] }, &none);
        assert_eq!(c.recommended(&[]), Some(1));
        let v = checks(&c, &Err("x".into()), Some(1), cert::now());
        assert!(v.iter().any(|(l, t)| *l == Level::Ok && t.starts_with("Se arregla agregando la raíz")));
    }

    #[test]
    fn names() {
        let mut i = CertInfo::parse(&der(SERVIDOR_PEM)).unwrap();
        i.sans = vec!["*.ejemplo.com".into(), "ejemplo.com".into(), "10.0.0.1".into()];
        assert!(name_matches(&i, "www.ejemplo.com"));
        assert!(name_matches(&i, "EJEMPLO.com."));
        assert!(name_matches(&i, "10.0.0.1"));
        assert!(!name_matches(&i, "a.b.ejemplo.com"));
        assert!(!name_matches(&i, "otro.com"));
    }
}
