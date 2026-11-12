use super::*;

/// A form like a host that answers its URL as text and deletes by a token,
/// with a stand-in's names.
fn text_form() -> Form {
    Form {
        id: "text-host".into(),
        upload: "https://up.stand-in.test/".into(),
        field: "file".into(),
        fields: vec![("secret".into(), String::new()), ("expires".into(), "1".into())],
        answer: Answer::Text,
        serves: vec!["up.stand-in.test".into()],
        fetch_segment: None,
        fetch_post: false,
        delete: Delete::TokenForm {
            header: "X-Token".into(),
            token_field: "token".into(),
            delete_field: "delete".into(),
        },
        most: 512 << 20,
        per_hour: None,
        one_person: true,
    }
}

/// A form like a host that answers JSON, serves a page at the answer's URL
/// and the file under a segment of its own, and deletes nothing.
fn json_form() -> Form {
    Form {
        id: "json-host".into(),
        upload: "https://json.stand-in.test/api/v1/upload".into(),
        field: "file".into(),
        fields: vec![("expire".into(), "60".into())],
        answer: Answer::Json(vec!["data".into(), "url".into()]),
        serves: vec!["json.stand-in.test".into()],
        fetch_segment: Some("dl".into()),
        fetch_post: false,
        delete: Delete::Never,
        most: 100 << 20,
        per_hour: Some(200),
        one_person: false,
    }
}

#[test]
fn an_upload_is_a_form_of_the_fields_then_the_file_as_rfc_7578_writes_it() {
    let body = upload_body(&text_form(), "B0", b"\x00sealed\r\n--B0");
    let want = concat!(
        "--B0\r\nContent-Disposition: form-data; name=\"secret\"\r\n\r\n\r\n",
        "--B0\r\nContent-Disposition: form-data; name=\"expires\"\r\n\r\n1\r\n",
        "--B0\r\nContent-Disposition: form-data; name=\"file\"; filename=\"piece.bin\"\r\n",
        "Content-Type: application/octet-stream\r\n\r\n\x00sealed\r\n--B0\r\n",
        "--B0--\r\n",
    );
    assert_eq!(String::from_utf8_lossy(&body), want);
    assert_eq!(content_type("B0"), "multipart/form-data; boundary=B0");
    let drawn = boundary(&mut crate::session::OsEntropy).unwrap();
    assert!(drawn.len() == 38 && drawn.bytes().all(|b| b.is_ascii_alphanumeric()), "{drawn}");
}

#[test]
fn a_text_answer_gives_its_url_and_the_token_of_its_header() {
    let headers = vec![("x-token".to_string(), " tok123 ".to_string())];
    let stored = read_answer(&text_form(), 200, &headers, b"https://up.stand-in.test/a1B.bin\n").unwrap();
    assert_eq!(stored, Stored { url: "https://up.stand-in.test/a1B.bin".into(), token: Some("tok123".into()) });
    let none = read_answer(&text_form(), 200, &[], b"https://up.stand-in.test/a1B.bin").unwrap();
    assert_eq!(none.token, None, "no header, no delete");
}

#[test]
fn a_json_answer_gives_the_url_at_its_path_and_downloads_under_its_segment() {
    let body = br#"{"status":"success","data":{"url":"https://json.stand-in.test/42/piece.bin"}}"#;
    let stored = read_answer(&json_form(), 200, &[], body).unwrap();
    assert_eq!(stored.url, "https://json.stand-in.test/42/piece.bin");
    assert_eq!(stored.token, None, "the host deletes nothing");
    assert_eq!(fetch_url(&json_form(), &stored.url), "https://json.stand-in.test/dl/42/piece.bin");
    assert_eq!(fetch_url(&text_form(), "https://up.stand-in.test/a.bin"), "https://up.stand-in.test/a.bin");
    let other = read_answer(&json_form(), 200, &[], br#"{"status":"error"}"#).unwrap_err();
    assert!(matches!(other, Refusal::Failed(ref why) if why.contains("names no https:// URL")), "{other:?}");
}

#[test]
fn a_429_is_busy_with_its_wait_and_another_status_or_host_is_a_failure() {
    let wait = vec![("Retry-After".to_string(), "120".to_string())];
    assert_eq!(
        read_answer(&text_form(), 429, &wait, b"slow down"),
        Err(Refusal::Busy(Some(std::time::Duration::from_secs(120))))
    );
    assert_eq!(read_answer(&text_form(), 429, &[], b""), Err(Refusal::Busy(None)));
    let failed = read_answer(&text_form(), 500, &[], b"Internal Server Error").unwrap_err();
    assert_eq!(failed, Refusal::Failed("text-host answered 500 to an upload".into()));
    let elsewhere = read_answer(&text_form(), 200, &[], b"https://elsewhere.test/a.bin").unwrap_err();
    assert!(matches!(elsewhere, Refusal::Failed(ref why) if why.contains("another host")), "{elsewhere:?}");
    let plain = read_answer(&text_form(), 200, &[], b"http://up.stand-in.test/a.bin").unwrap_err();
    assert!(matches!(plain, Refusal::Failed(_)), "no URL without TLS");
}

#[test]
fn owns_reads_the_host_of_an_https_url_alone() {
    let form = text_form();
    assert!(owns(&form, "https://UP.stand-in.test/x"));
    assert!(owns(&form, "https://up.stand-in.test:443/x?y#z"));
    assert!(!owns(&form, "https://up.stand-in.test.elsewhere.test/x"));
    assert!(!owns(&form, "https://elsewhere.test@up.stand-in.test.evil.test/x"));
    assert!(!owns(&form, "http://up.stand-in.test/x"));
    assert!(!owns(&form, "https:///x"));
}

#[test]
fn a_delete_is_a_form_of_the_token_where_the_host_gave_one() {
    let stored = Stored { url: "https://up.stand-in.test/a.bin".into(), token: Some("tok".into()) };
    let body = delete_body(&text_form(), "B1", &stored).unwrap();
    let want = concat!(
        "--B1\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\ntok\r\n",
        "--B1\r\nContent-Disposition: form-data; name=\"delete\"\r\n\r\n\r\n",
        "--B1--\r\n",
    );
    assert_eq!(String::from_utf8_lossy(&body), want);
    assert_eq!(delete_body(&text_form(), "B1", &Stored { token: None, ..stored.clone() }), None);
    assert_eq!(delete_body(&json_form(), "B1", &stored), None, "a host that deletes nothing");
}
