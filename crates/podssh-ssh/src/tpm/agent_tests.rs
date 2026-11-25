//! The keys of a TPM that `podssh agent` holds, against a TPM in software:
//! added by the request of ssh-tpm-agent's `ssh-tpm-add` (as `podssh agent
//! add` sends it), checked by a signature first, listed after russh's keys,
//! signed with in the TPM, removed, refused while locked, and gone at the
//! end of their lifetime. A key whose boot state changed, a certificate, a
//! confirmation of each use and a request of another layout are refused.

use std::sync::Mutex;

use pod_tpm::soft::SoftTpm;
use russh::keys::PublicKey;

use super::super::check;
use super::super::tests::sealed;
use super::*;

/// A TPM whose PCR 7 measured a boot, the way to it, and a key sealed to it.
fn made() -> (Arc<Mutex<SoftTpm>>, Opener, KeyFile, PublicKey) {
    sealed("me@lab")
}

/// [`add_request`] of a file that pod-tpm writes.
fn add_of(file: &KeyFile, lifetime: Option<u32>) -> Zeroizing<Vec<u8>> {
    add_request(file, lifetime).unwrap()
}

/// russh's answer to a request for the keys: one key of its own.
fn russh_list() -> Zeroizing<Vec<u8>> {
    let mut out = vec![IDENTITIES_ANSWER, 0, 0, 0, 1];
    put_string(&mut out, b"its key");
    put_string(&mut out, b"its comment");
    Zeroizing::new(out)
}

fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut request = vec![SIGN_REQUEST];
    put_string(&mut request, blob);
    put_string(&mut request, data);
    request.extend_from_slice(&0u32.to_be_bytes());
    request
}

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
}

fn code(answer: Option<Zeroizing<Vec<u8>>>) -> Option<u8> {
    answer.and_then(|a| a.first().copied())
}

#[test]
fn a_key_of_a_tpm_is_added_listed_signed_with_and_removed() {
    let (tpm, open, file, public) = made();
    let held = Held::with(open);
    let blob = public.to_bytes().unwrap();
    assert_eq!(code(run(held.answer(&add_of(&file, Some(600)), false))), Some(SUCCESS));
    assert_eq!(held.count(), 1);

    let list = held.after(&[REQUEST_IDENTITIES], russh_list(), false);
    let mut rest = &list[1..];
    assert_eq!(list[0], IDENTITIES_ANSWER);
    assert_eq!(take_u32(&mut rest), Some(2), "russh's key and this one");
    assert_eq!(take_string(&mut rest).unwrap(), b"its key");
    assert_eq!(take_string(&mut rest).unwrap(), b"its comment");
    assert_eq!(take_string(&mut rest).unwrap(), blob);
    assert_eq!(take_string(&mut rest).unwrap(), b"me@lab");

    // The TPM signs; ssh-key verifies as a server does.
    let answer = run(held.answer(&sign_request(&blob, b"a login"), false)).unwrap();
    let mut rest = &answer[1..];
    assert_eq!(answer[0], SIGN_RESPONSE);
    check(&public, b"a login", &take_string(&mut rest).unwrap()).unwrap();
    assert_eq!(tpm.lock().unwrap().loaded(), 0, "no handle left");

    // Locked: nothing is signed, listed or removed.
    assert_eq!(code(run(held.answer(&sign_request(&blob, b"a login"), true))), Some(FAILURE));
    assert_eq!(&held.after(&[REQUEST_IDENTITIES], russh_list(), true)[..], &russh_list()[..]);
    let mut remove = vec![REMOVE_IDENTITY];
    put_string(&mut remove, &blob);
    assert_eq!(code(run(held.answer(&remove, true))), Some(FAILURE));
    assert_eq!(code(run(held.answer(&remove, false))), Some(SUCCESS));
    assert_eq!(held.count(), 0);
    // A key that is not held goes on to russh's server.
    assert!(run(held.answer(&remove, false)).is_none());
    assert!(run(held.answer(&sign_request(&blob, b"a login"), false)).is_none());

    // A removal of each key, that russh's server did, removes these too.
    run(held.answer(&add_of(&file, None), false));
    held.after(&[REMOVE_ALL_IDENTITIES], Zeroizing::new(vec![SUCCESS]), false);
    assert_eq!(held.count(), 0);
}

/// After the boot state changed, the TPM refuses the signature: FAILURE,
/// which a client reads as a key that did not sign. A key whose state
/// already changed is not kept.
#[test]
fn a_changed_boot_state_fails_the_signature_and_the_add() {
    let (tpm, open, file, public) = made();
    let held = Held::with(open);
    assert_eq!(code(run(held.answer(&add_of(&file, None), false))), Some(SUCCESS));
    tpm.lock().unwrap().extend(7, b"Secure Boot: off");
    let blob = public.to_bytes().unwrap();
    assert_eq!(code(run(held.answer(&sign_request(&blob, b"a login"), false))), Some(FAILURE));
    assert_eq!(tpm.lock().unwrap().loaded(), 0, "no handle left");
    held.after(&[REMOVE_ALL_IDENTITIES], Zeroizing::new(vec![SUCCESS]), false);
    assert_eq!(code(run(held.answer(&add_of(&file, None), false))), Some(EXTENSION_FAILURE));
    assert_eq!(held.count(), 0);

    // A file of another TPM, and no TPM: refused at the add.
    let (_, other, _, _) = made();
    assert_eq!(code(run(Held::with(other).answer(&add_of(&file, None), false))), Some(EXTENSION_FAILURE));
    let none: Opener = Arc::new(|| Err("no TPM: none here".to_string()));
    assert_eq!(code(run(Held::with(none).answer(&add_of(&file, None), false))), Some(EXTENSION_FAILURE));
}

/// What the agent does not keep: a certificate, a confirmation of each
/// use, an unknown constraint, a request of another layout. Another
/// extension is not this one's; locked, the add is refused.
#[test]
fn what_the_agent_cannot_keep_is_refused() {
    let (_, open, file, _) = made();
    let held = Held::with(open);
    let request = add_of(&file, None);
    let with = |tail: &[u8], cert: &[u8]| {
        let mut body = vec![EXTENSION];
        put_string(&mut body, ADD_EXTENSION.as_bytes());
        body.push(ADD_ID_CONSTRAINED);
        put_string(&mut body, KEY_TYPE);
        put_string(&mut body, file.to_pem().unwrap().as_bytes());
        put_string(&mut body, cert);
        body.extend_from_slice(tail);
        body
    };
    for refused in [with(&[], b"a certificate"), with(&[CONSTRAIN_CONFIRM], b""), with(&[9], b""), with(&[1, 0], b"")] {
        assert_eq!(code(run(held.answer(&refused, false))), Some(EXTENSION_FAILURE));
    }
    let mut other_type = request.to_vec();
    // The first letter of TPMKEY: past the code, the extension's name, the
    // message's code and the type's length.
    let at = 1 + 4 + ADD_EXTENSION.len() + 1 + 4;
    other_type[at] = b'X';
    assert_eq!(code(run(held.answer(&other_type, false))), Some(EXTENSION_FAILURE));
    assert_eq!(code(run(held.answer(&request[..request.len() - 3], false))), Some(EXTENSION_FAILURE));
    let mut another = vec![EXTENSION];
    put_string(&mut another, b"session-bind@openssh.com");
    assert!(run(held.answer(&another, false)).is_none());
    assert_eq!(code(run(held.answer(&request, true))), Some(FAILURE));
    assert_eq!(held.count(), 0);
    // The layout of ssh-tpm-add, constrained, with a lifetime: taken.
    let mut lifetime = vec![CONSTRAIN_LIFETIME];
    lifetime.extend_from_slice(&60u32.to_be_bytes());
    assert_eq!(code(run(held.answer(&with(&lifetime, b""), false))), Some(SUCCESS));
}

#[test]
fn a_key_leaves_at_the_end_of_its_lifetime() {
    let (_, open, file, _) = made();
    let held = Held::with(open);
    assert_eq!(code(run(held.answer(&add_of(&file, Some(1)), false))), Some(SUCCESS));
    assert_eq!(held.count(), 1);
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(held.count(), 0);
}

/// The client's request against the agent's front over a pipe: `add`
/// writes it, and reads SUCCESS, or the agent's refusal in words.
#[test]
fn podssh_agent_add_gives_the_key_through_the_front() {
    let (_, open, file, _) = made();
    let store = Arc::new(crate::credential_store::Store::with_tpm_keys(Held::with(open)));
    let (mut client, agent_end) = tokio::io::duplex(crate::credential_store::MAX_FRAME);
    let (russh_end, _russh_far) = tokio::io::duplex(1024);
    run(async {
        let serving = tokio::spawn({
            let store = store.clone();
            async move { crate::credential_store::serve_client(agent_end, russh_end, &store).await }
        });
        add(&mut client, &file, Some(60)).await.unwrap();
        drop(client);
        let _ = serving.await;
    });
    assert_eq!(store.tpm_keys.count(), 1);
}
