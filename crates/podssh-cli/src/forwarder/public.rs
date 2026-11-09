//! The public Wisp servers that their operators run for the use of others
//! (T-535, the operator's ruling Q75), tried in the fallback after the
//! forwarders that the binary names and before their `ws://` forms. The
//! list is the services of the kind `wisp-public` of `pod-services`, each
//! with the facts `word`, `template` and `note`; podssh holds no host of
//! another party. A release of `pod-services` with no such service gives an
//! empty list, and the fallback is what it was. The words are for the
//! lines and the manual only: `--forwarder` takes the words of the built-in
//! forwarders and templates, not these.

use std::sync::LazyLock;

use podssh_ws::forwarder::{Template, WISP};

use super::Forwarder;

/// The kind of service in `pod-services` that holds them.
pub const KIND: &str = "wisp-public";

/// A public Wisp server that its operator offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Public {
    pub word: &'static str,
    pub template: &'static str,
    pub note: &'static str,
}

/// The servers of the catalog, by their rank.
pub static PUBLIC: LazyLock<Vec<Public>> = LazyLock::new(|| {
    let fact = |s: &'static pod_services::Service, name: &str| s.text(name).unwrap_or_default();
    pod_services::of_kind(KIND)
        .map(|s| Public { word: fact(s, "word"), template: fact(s, "template"), note: fact(s, "note") })
        .collect()
});

/// The forwarders of `list`, in order. An entry whose template does not
/// parse, or is not a Wisp one, is left out: a bad row of the catalog must
/// not end the fallback.
pub fn forwarders_of(list: &[Public]) -> Vec<Forwarder> {
    let each = |p: &Public| {
        let template = Template::parse(p.template).ok().filter(|_| p.template.starts_with(WISP))?;
        let name = format!("{} ({})", p.word, template.shown());
        Some(Forwarder { template, name })
    };
    list.iter().filter_map(each).collect()
}

/// The public Wisp servers of the catalog, as forwarders.
pub fn forwarders() -> Vec<Forwarder> {
    forwarders_of(&PUBLIC)
}

/// The words of `list`, as the announcement lists them after the built-in
/// ones: `, w1, w2`, or nothing for an empty list.
pub fn words_of(list: &[Forwarder]) -> String {
    list.iter().map(|f| f.name.split(' ').next().unwrap_or_default()).map(|w| format!(", {w}")).collect()
}

/// The order of the fallback's wss:// round: the forwarders that the binary
/// names, then `public`, each once.
pub fn chain(builtins: Vec<Forwarder>, public: &[Forwarder]) -> Vec<Forwarder> {
    let mut all = builtins;
    for p in public {
        if !all.contains(p) {
            all.push(p.clone());
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stand_in(word: &'static str, host: &str) -> Public {
        let template: &'static str = Box::leak(format!("wisp+wss://{host}/").into_boxed_str());
        Public { word, template, note: "a stand-in" }
    }

    /// The catalog of `pod-services` v0.7.0 has no public Wisp server: the
    /// list is empty, and the fallback's chain is the built-ins alone.
    #[test]
    fn an_empty_list_leaves_the_chain_as_it_was() {
        assert!(forwarders_of(&[]).is_empty());
        assert_eq!(words_of(&[]), "");
        let built = super::super::builtins();
        assert_eq!(chain(built.clone(), &[]), built);
        assert_eq!(forwarders().len(), PUBLIC.len(), "each row of the catalog is a Wisp template");
    }

    /// The public servers come after each built-in one, in the list's
    /// order, each once; the demo server stays before them.
    #[test]
    fn the_public_servers_come_after_the_built_in_forwarders_in_order() {
        let list = [stand_in("one", "w1.example"), stand_in("two", "w2.example"), stand_in("one", "w1.example")];
        let public = forwarders_of(&list);
        assert_eq!(public.len(), 3);
        let built = super::super::builtins();
        let all = chain(built.clone(), &public);
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(&all[..built.len()], &built[..], "the built-ins first");
        assert!(built.last().unwrap().name.starts_with("wisp "), "the demo server is the last built-in");
        assert_eq!(&names[built.len()..], ["one (wisp+wss://w1.example/)", "two (wisp+wss://w2.example/)"]);
        assert_eq!(words_of(&public[..2]), ", one, two");
    }

    /// A row that is no Wisp template, or does not parse, is left out.
    #[test]
    fn a_bad_row_is_left_out() {
        let bad = [
            Public { word: "plain", template: "wss://h.example/?host={host}&port={port}", note: "" },
            Public { word: "junk", template: "wisp+wss://", note: "" },
            stand_in("good", "w.example"),
        ];
        let got = forwarders_of(&bad);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].name.starts_with("good "));
    }
}
