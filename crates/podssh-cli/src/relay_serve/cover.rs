//! `podssh relay serve --cover DIR` (#225, T-764 and T-768): the static
//! site of the role's own certificate name, its `Server` value, the names
//! that the role terminates itself (`--cover-name`) and the hygiene of the
//! certificate. A wildcard leaf is refused at the start, with or without
//! `--cover`; so is a leaf that does not hold the name that `--acme` asked
//! for. More than one leaf name is a warning, and `--cover` needs each own
//! name named by `--cover-name`, so that no name is shared without a
//! decision. The tree, its routing and its 404 are `pod-cover`'s, which the
//! role serves; this module only reads the flags and the leaf.

use std::path::Path;
use std::sync::Arc;

use pod_cover::{Script, Site};
use podssh_relay::serve::cover::{Cover, Issuer};

use super::certs::{Certs, Source};
use crate::acme::certs::Leaf;
use crate::relay_settings::Refusal;

/// The flag, for its refusals.
pub const FLAG: &str = "--cover";

/// Whether the leaf's names are one public name, and whether it is the one
/// that `--acme` asked for (CERT-1, T-768). A wildcard leaf, a leaf with no
/// DNS name and a leaf that does not hold the `--acme` name are refused in
/// both modes (78). More than one name is the warning that the first line
/// says, in both modes; under `--cover` each own name must be named by
/// `--cover-name`, which [`open`] checks. A certificate that is not held yet
/// is no cover at all, which fails closed.
pub(super) fn hygiene(source: &Source, facts: Option<&Leaf>, with_cover: bool) -> Result<Option<String>, Refusal> {
    const ONE: &str = "one name from a public CA for each deployment (CERT-1)";
    let Some(facts) = facts else {
        let why = "--cover needs the certificate of its name now: the CA's certificate is not held yet, so start \
                   once without --cover, or give --cert and --key";
        return if with_cover { Err(Refusal::config(why)) } else { Ok(None) };
    };
    let names: Vec<&str> = facts.names.iter().map(String::as_str).collect();
    if let Some(name) = names.iter().find(|name| name.contains('*')) {
        return Err(Refusal::config(format!(
            "{FLAG}: the certificate names the wildcard {name}: {ONE}; --acme NAME is the way to one, or a --cert \
             whose leaf names that one"
        )));
    }
    if names.is_empty() {
        return Err(Refusal::config(format!(
            "{FLAG}: the certificate names no DNS name: {ONE}; --acme NAME is the way to one, or a --cert whose leaf \
             names that one"
        )));
    }
    if let Source::Acme { name, .. } = source
        && !names.iter().any(|held| held.eq_ignore_ascii_case(name))
    {
        return Err(Refusal::config(format!(
            "{FLAG}: the certificate names {}, not the --acme name {name}: {ONE}",
            names.join(", ")
        )));
    }
    if names.len() == 1 {
        return Ok(None);
    }
    Ok(Some(format!(
        "warning: the certificate names {} names ({}): {ONE}; --cover needs each own name as a --cover-name",
        names.len(),
        names.join(", ")
    )))
}

/// The script at `path`, read now: a missing script, one with no date, one
/// with no cover version and one with no split policy are each a refusal
/// (78), as podnet#491's SCRIPT-2 and SCRIPT-3 say.
pub(super) fn script(path: &str) -> Result<Script, Refusal> {
    Script::load(path).map_err(|why| Refusal::config(format!("--cover-script {path}: {why}")))
}

/// The operator key of the cover: the secret in `key`, the public key that
/// the role pins in `public`, both in the hexadecimal that the flags name.
/// A role with neither makes a key for this process. A public key that is
/// not the secret's is refused by fingerprint, without showing the secret.
pub(super) fn issuer(key: Option<&str>, public: Option<&str>) -> Result<Issuer, Refusal> {
    let pinned = public
        .map(podssh_ws::delegated::parse_verifying_key)
        .transpose()
        .map_err(|why| Refusal::usage(format!("--cover-issuer-public: {why}")))?;
    let Some(path) = key else {
        return match pinned {
            Some(pinned) => Ok(Issuer::verify_only(pinned)),
            None => Ok(Issuer::random()),
        };
    };
    let text = std::fs::read_to_string(path).map_err(|e| Refusal::config(format!("--cover-issuer-key {path}: {e}")))?;
    let signing = podssh_ws::delegated::parse_issuer_seed(&text)
        .map_err(|why| Refusal::config(format!("--cover-issuer-key {path}: {why}")))?;
    let issuer = Issuer::from_signing(signing);
    if let Some(pinned) = pinned
        && pinned != issuer.pinned()
    {
        return Err(Refusal::config(format!(
            "--cover-issuer-key {path} is not the key of --cover-issuer-public (key {}, pinned {})",
            issuer.fingerprint(),
            pinned.as_bytes()[..8].iter().map(|byte| format!("{byte:02x}")).collect::<String>()
        )));
    }
    Ok(issuer)
}

/// The cover site of `dir` for the names of the leaf `facts`, with `server`
/// as its `Server` value, `issuer` as the operator key that signs and checks
/// the credentials, and `script` as its measurement. With no `cover_names`
/// the leaf must name exactly one name; with them, the first is the role's
/// name and each must be a name of the leaf. The certificate's names are
/// checked again here, so that a caller that skipped [`hygiene`] gets no
/// cover.
pub(super) fn open(
    dir: &str,
    facts: &Leaf,
    cover_names: &[String],
    issuer: Issuer,
    server: Option<&str>,
    script: Option<Script>,
) -> Result<Arc<Cover>, Refusal> {
    let held: Vec<String> = facts.names.iter().map(|name| name.to_ascii_lowercase()).collect();
    let names = if cover_names.is_empty() {
        match facts.names.as_slice() {
            [name] if !name.contains('*') => vec![name.clone()],
            [] => return Err(Refusal::config(format!("{FLAG}: the certificate names no DNS name"))),
            [..] => {
                return Err(Refusal::config(format!(
                    "{FLAG}: the certificate names {} names ({}): name each own name with --cover-name",
                    facts.names.len(),
                    facts.names.join(", ")
                )));
            }
        }
    } else {
        let mut chosen = Vec::new();
        for given in cover_names {
            let name = podssh_relay::serve::published::dns_name(given).ok_or_else(|| {
                Refusal::usage(format!("{FLAG}: --cover-name {given}: not a DNS name of two labels or more"))
            })?;
            if !held.contains(&name) {
                return Err(Refusal::config(format!(
                    "{FLAG}: --cover-name {name} is not a name of the certificate ({})",
                    facts.names.join(", ")
                )));
            }
            if !chosen.contains(&name) {
                chosen.push(name);
            }
        }
        chosen
    };
    // A directory that is missing or unread is a fault of the host's files
    // (78), as a missing --cert is (T-943).
    if !Path::new(dir).is_dir() {
        return Err(Refusal::config(format!("{FLAG} {dir}: not a directory")));
    }
    let site = Site::load(dir).map_err(|e| Refusal::config(format!("{FLAG} {dir}: {e}")))?;
    let (name, owned) = names.split_first().expect("a cover has a name");
    Cover::new_covered(site, name, owned, issuer, server, script)
        .map_err(|why| Refusal::usage(format!("{FLAG} {dir}: {why}")))
}

/// The site of the flags, with the certificate that the role serves: the
/// cover when `--cover` is given, and the warning that its first line says
/// when the certificate is not one deployment's (T-768). `--cover-server`
/// and `--control-socket` go with `--cover`, and `--cover` needs the latter.
pub(super) fn of(
    args: &super::ServeArgs,
    source: &Source,
    certs: &Certs,
) -> Result<(Option<Arc<Cover>>, Option<String>), Refusal> {
    if args.cover.is_none() {
        if args.cover_server.is_some() {
            return Err(Refusal::usage("--cover-server goes with --cover DIR"));
        }
        if args.control_socket.is_some() {
            return Err(Refusal::usage("--control-socket goes with --cover DIR, whose documents it serves"));
        }
        if !args.cover_name.is_empty() {
            return Err(Refusal::usage("--cover-name goes with --cover DIR"));
        }
        if args.cover_script.is_some() {
            return Err(Refusal::usage("--cover-script goes with --cover DIR"));
        }
        if args.cover_issuer_key.is_some() || args.cover_issuer_public.is_some() {
            return Err(Refusal::usage("--cover-issuer-key and --cover-issuer-public go with --cover DIR"));
        }
        return Ok((None, hygiene(source, certs.facts().as_ref(), false)?));
    }
    if args.control_socket.is_none() {
        return Err(Refusal::usage(
            "--cover needs --control-socket PATH: the role's documents and probes leave the public listener for it",
        ));
    }
    if args.sshd.is_some() {
        return Err(Refusal::usage(
            "--sshd does not go with --cover: an SSH client of this port would name the role that the cover hides",
        ));
    }
    let facts = certs.facts();
    let warning = hygiene(source, facts.as_ref(), true)?;
    let facts = facts.expect("a cover has a held certificate");
    certs.leaf_der().ok_or_else(|| Refusal::config("--cover: the leaf certificate is not held"))?;
    let script = args.cover_script.as_deref().map(script).transpose()?;
    let issuer = issuer(args.cover_issuer_key.as_deref(), args.cover_issuer_public.as_deref())?;
    let cover = open(
        args.cover.as_deref().expect("a cover"),
        &facts,
        &args.cover_name,
        issuer,
        args.cover_server.as_deref(),
        script,
    )?;
    for row in &args.publish {
        let name = row.split_once('=').map(|(name, _)| name).unwrap_or(row);
        if let Some(name) = podssh_relay::serve::published::dns_name(name)
            && cover.owned_names().contains(&name)
        {
            return Err(Refusal::usage(format!(
                "--publish {name}: the role terminates that name itself (--cover); a name is either the role's \
                 own or a node's, never both"
            )));
        }
    }
    Ok((Some(cover), warning))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(names: &[&str]) -> Leaf {
        Leaf { names: names.iter().map(|n| n.to_string()).collect(), not_before: 0, not_after: 1 }
    }

    fn files() -> Source {
        Source::Files { cert: "c.pem".into(), key: "k.pem".into() }
    }

    fn acme(name: &str) -> Source {
        Source::Acme { name: name.into(), directory: None, ca_file: None }
    }

    /// T-768 (CERT-1): a wildcard and a name that the CA was asked for and
    /// the leaf does not hold are refused in both modes; two names are a
    /// warning in both, and `--cover` needs each own name named.
    #[test]
    fn a_wildcard_and_a_name_mismatch_are_refused_with_or_without_a_cover() {
        let wildcard = leaf(&["*.example.org"]);
        for with_cover in [true, false] {
            let refused = hygiene(&files(), Some(&wildcard), with_cover).unwrap_err();
            assert_eq!(refused.code, 78, "{refused:?}");
            assert!(refused.message.contains("wildcard"), "{}", refused.message);
            assert!(refused.message.contains("--cover"), "{}", refused.message);
        }

        let two = leaf(&["a.example.org", "b.example.org"]);
        for with_cover in [true, false] {
            let warning = hygiene(&files(), Some(&two), with_cover).unwrap().unwrap();
            assert!(warning.starts_with("warning:") && warning.contains("2 names"), "{warning}");
        }

        let one = leaf(&["a.example.org"]);
        assert_eq!(hygiene(&files(), Some(&one), true), Ok(None));
        assert_eq!(hygiene(&acme("A.Example.Org"), Some(&one), true), Ok(None));
        for with_cover in [true, false] {
            let mismatch = hygiene(&acme("b.example.org"), Some(&one), with_cover).unwrap_err();
            assert_eq!(mismatch.code, 78, "{mismatch:?}");
            assert!(mismatch.message.contains("not the --acme name b.example.org"), "{}", mismatch.message);
        }

        // No certificate held yet: no cover, which fails closed.
        assert!(hygiene(&acme("a.example.org"), None, true).is_err());
    }

    /// The site's tree must be a directory with an index, read once.
    #[test]
    fn a_cover_tree_is_read_or_refused_at_the_start() {
        let dir =
            std::env::temp_dir().join(format!("podssh-cover-{}-{:08x}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(open("no-such-dir-here", &leaf(&["a.example.org"]), &[], Issuer::from_seed([0x11; 32]), None, None)
            .is_err());
        let missing =
            open(dir.to_str().unwrap(), &leaf(&["a.example.org"]), &[], Issuer::from_seed([0x11; 32]), None, None)
                .unwrap_err();
        assert!(missing.message.contains("no index.html"), "{}", missing.message);
        std::fs::write(dir.join("index.html"), b"<html>a page</html>").unwrap();
        let cover = open(
            dir.to_str().unwrap(),
            &leaf(&["a.example.org"]),
            &[],
            Issuer::from_seed([0x11; 32]),
            Some("nginx/1.24.0"),
            None,
        )
        .unwrap();
        assert_eq!(cover.name, "a.example.org");
        assert_eq!(cover.server, "nginx/1.24.0");
        // A Server value that names the project is refused.
        let named = open(
            dir.to_str().unwrap(),
            &leaf(&["a.example.org"]),
            &[],
            Issuer::from_seed([0x11; 32]),
            Some("podssh"),
            None,
        )
        .unwrap_err();
        assert!(named.message.contains("not a visible value"), "{}", named.message);
        // Two leaf names: each own name must be named, and each must be held.
        let two = leaf(&["a.example.org", "b.example.org"]);
        assert!(open(dir.to_str().unwrap(), &two, &[], Issuer::from_seed([0x11; 32]), None, None).is_err());
        let both = vec!["a.example.org".to_string(), "b.example.org".to_string()];
        let cover = open(dir.to_str().unwrap(), &two, &both, Issuer::from_seed([0x11; 32]), None, None).unwrap();
        assert_eq!(cover.owned_names(), both.as_slice());
        let not_held = vec!["a.example.org".to_string(), "c.example.org".to_string()];
        let refused =
            open(dir.to_str().unwrap(), &two, &not_held, Issuer::from_seed([0x11; 32]), None, None).unwrap_err();
        assert_eq!(refused.code, 78, "{refused:?}");
        assert!(refused.message.contains("not a name of the certificate"), "{}", refused.message);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
