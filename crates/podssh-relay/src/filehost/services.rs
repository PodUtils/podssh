//! The file hosts of `pod-services` (its kind [`KIND`]) as the carrier's
//! [`Form`]s: each fact of a service read into the form that `form.rs`
//! builds its requests from. The hosts, their order and their limits are the
//! catalog's alone; a service whose facts do not read is left out by name,
//! so that a change of the catalog that this code cannot follow drops one
//! host and never carries a piece by a guess.

use super::form::{Answer, Delete, Form};

/// The kind of `pod-services` whose services are the file hosts.
pub const KIND: &str = "file-host";
/// The endpoint of a service that takes an upload.
pub const ENDPOINT: &str = "upload";

/// The form of the file host `service`, or why its facts do not make one.
pub fn form_of(service: &pod_services::Service) -> Result<Form, String> {
    let id = service.id();
    let text = |name: &str| service.text(name).map(str::to_string).ok_or_else(|| format!("{id}: no fact {name}"));
    let texts = |name: &str| -> Result<Vec<String>, String> {
        let list = service.texts(name).ok_or_else(|| format!("{id}: no fact {name}"))?;
        Ok(list.iter().map(|t| t.to_string()).collect())
    };
    let upload = service.endpoint(ENDPOINT).ok_or_else(|| format!("{id}: no endpoint {ENDPOINT}"))?;
    if upload.scheme() != "https" {
        return Err(format!("{id}: an upload that is not https://"));
    }
    let mut fields = Vec::new();
    for pair in texts("fields")? {
        let (name, value) = pair.split_once('=').ok_or_else(|| format!("{id}: a field {pair:?} with no ="))?;
        fields.push((name.to_string(), value.to_string()));
    }
    let answer = match text("answer")?.as_str() {
        "text" => Answer::Text,
        "json" => Answer::Json(pointer(&text("answer-pointer")?).ok_or_else(|| format!("{id}: answer-pointer"))?),
        other => return Err(format!("{id}: an answer {other:?} that this code does not read")),
    };
    let fetch_post = match text("fetch-method")?.as_str() {
        "GET" => false,
        "POST" => true,
        other => return Err(format!("{id}: a fetch-method {other:?}")),
    };
    let delete = match text("delete")?.as_str() {
        "none" => Delete::Never,
        "token-form" => token_form(service)?,
        other => return Err(format!("{id}: a delete {other:?} that this code does not make")),
    };
    let most = service.int("upload-bytes-most").filter(|n| *n > 0).ok_or_else(|| format!("{id}: upload-bytes-most"))?;
    Ok(Form {
        id: id.to_string(),
        upload: upload.url(),
        field: text("file-field")?,
        fields,
        answer,
        serves: texts("serves")?.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
        fetch_segment: service.text("fetch-segment").filter(|s| !s.is_empty()).map(str::to_string),
        fetch_post,
        link_prefix: service.text("fetch-link-prefix").filter(|p| !p.is_empty()).map(str::to_string),
        delete,
        most: usize::try_from(most).unwrap_or(usize::MAX),
        per_hour: service.int("uploads-per-hour").and_then(|n| u32::try_from(n).ok()).filter(|n| *n > 0),
        // A host that does not say is told as one person's: the line errs
        // toward the warning.
        one_person: service.bool("one-person").unwrap_or(true),
    })
}

/// The delete of a host that gives a token: its header, its field, and the
/// one field that asks for the delete. A form of more fields than this code
/// sends is no delete: the piece waits for its shortest life.
fn token_form(service: &pod_services::Service) -> Result<Delete, String> {
    let id = service.id();
    let header = service.text("delete-token-header").filter(|h| !h.is_empty());
    let token_field = service.text("delete-token-field").filter(|f| !f.is_empty());
    let (Some(header), Some(token_field)) = (header, token_field) else {
        return Err(format!("{id}: a token-form delete with no header or field"));
    };
    let fields = service.texts("delete-fields").unwrap_or_default();
    let [only] = fields else { return Ok(Delete::Never) };
    let only: &str = only;
    let (name, value) = only.split_once('=').unwrap_or((only, ""));
    if name.is_empty() || !value.is_empty() {
        return Ok(Delete::Never);
    }
    Ok(Delete::TokenForm {
        header: header.to_string(),
        token_field: token_field.to_string(),
        delete_field: name.to_string(),
    })
}

/// The keys of a JSON pointer (RFC 6901): `/data/url` is `data`, `url`.
pub fn pointer(text: &str) -> Option<Vec<String>> {
    let rest = text.strip_prefix('/')?;
    let keys: Vec<String> = rest.split('/').map(|k| k.replace("~1", "/").replace("~0", "~")).collect();
    (!keys.iter().any(String::is_empty)).then_some(keys)
}

/// Whether the catalog takes `service` with no word of the user: it has a
/// rank, its terms do not refuse automated uploads, and the catalog does not
/// say that it is off by default (`on-by-default` false: a host that refused
/// the networks it was measured from). The others are taken only when
/// [`super::ENV`] names them, which is the user's consent that such a host's
/// operator asks for.
pub fn unasked(service: &pod_services::Service) -> bool {
    service.rank().is_some()
        && service.bool("automated-uploads-refused") != Some(true)
        && service.bool("on-by-default") != Some(false)
}

/// The ids of the file hosts, in the catalog's order: each one, and those
/// taken unasked.
pub fn ids() -> (Vec<&'static str>, Vec<&'static str>) {
    let all: Vec<&'static pod_services::Service> = pod_services::of_kind(KIND).collect();
    let every = all.iter().map(|s| s.id()).collect();
    let unasked = all.iter().filter(|s| unasked(s)).map(|s| s.id()).collect();
    (every, unasked)
}

/// The forms of `ids`, in that order; a service whose facts do not read is
/// left out, with why, for a line.
pub fn forms(ids: &[&str]) -> (Vec<Form>, Vec<String>) {
    let (mut forms, mut missed) = (Vec::new(), Vec::new());
    for id in ids {
        match pod_services::get(id).ok_or_else(|| format!("{id}: not in the catalog")).and_then(form_of) {
            Ok(form) => forms.push(form),
            Err(why) => missed.push(why),
        }
    }
    (forms, missed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_file_host_of_the_catalog_reads_into_a_form_that_its_facts_make() {
        let (every, unasked_ids) = ids();
        assert!(every.len() >= 2, "the catalog lists the file hosts: {every:?}");
        let (forms, missed) = forms(&every);
        assert!(missed.is_empty(), "{missed:?}");
        for (form, id) in forms.iter().zip(&every) {
            let service = pod_services::get(id).unwrap();
            assert_eq!(form.id, *id);
            assert_eq!(form.upload, service.endpoint(ENDPOINT).unwrap().url());
            assert!(form.upload.starts_with("https://") && !form.serves.is_empty(), "{form:?}");
            assert_eq!(form.fields.len(), service.texts("fields").unwrap().len(), "{id}");
            assert_eq!(form.fetch_post, service.text("fetch-method") == Some("POST"), "{id}");
            assert_eq!(form.link_prefix.as_deref(), service.text("fetch-link-prefix").filter(|p| !p.is_empty()), "{id}");
            assert_eq!(matches!(form.answer, Answer::Json(_)), service.text("answer") == Some("json"), "{id}");
            assert_eq!(form.per_hour.map(i64::from), service.int("uploads-per-hour"), "{id}");
            let deletes = matches!(form.delete, Delete::TokenForm { .. });
            assert_eq!(deletes, service.text("delete") == Some("token-form"), "{id}: its delete");
            if let Answer::Json(keys) = &form.answer {
                assert_eq!(Some(format!("/{}", keys.join("/"))).as_deref(), service.text("answer-pointer"));
            }
        }
        // A host whose terms refuse automated uploads, with no rank, or off
        // by default, is never taken unasked.
        for id in &every {
            let service = pod_services::get(id).unwrap();
            let refused = service.bool("automated-uploads-refused") == Some(true)
                || service.rank().is_none()
                || service.bool("on-by-default") == Some(false);
            assert_eq!(unasked_ids.contains(id), !refused, "{id}");
        }
        assert!(!unasked_ids.is_empty(), "at least one host is taken unasked");
    }

    #[test]
    fn a_json_pointer_reads_its_keys_and_its_escapes() {
        assert_eq!(pointer("/data/url"), Some(vec!["data".to_string(), "url".to_string()]));
        assert_eq!(pointer("/a~1b/c~0d"), Some(vec!["a/b".to_string(), "c~d".to_string()]));
        assert_eq!(pointer("data/url"), None);
        assert_eq!(pointer("/"), None);
        assert_eq!(pointer("/a//b"), None);
    }

    #[test]
    fn an_id_that_the_catalog_does_not_hold_is_left_out_with_why() {
        let (forms, missed) = forms(&["no-such-file-host"]);
        assert!(forms.is_empty());
        assert_eq!(missed, ["no-such-file-host: not in the catalog"]);
    }
}
