//! A bearer of `--bearer` (T-834) through the end-to-end channel, with no
//! relay: podssh's operator end (`bearer::proof` in `ends::operator_bound`,
//! as `channel::around_told` wires it) to a node whose admission lets no key
//! in, so that only its door for grants (`grants::door`) can:
//!
//! - a bearer that the node's own key signs, read from a key file, lets the
//!   operator in, and the target echoes;
//! - the same bytes on a second session are refused by the binding of the
//!   first channel, and the target is not opened;
//! - a bearer whose signer the node does not take is refused.
//!
//! Plants: let `bearer::signs` take each key: the third test fails; give the
//! verifier no binding (`None` in `bearer::redeem`): the first test fails.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_cli::bearer::{self, Minted, Say, Signer};
use podssh_relay::e2e::ends::{self, Node};
use podssh_relay::e2e::{Ask, Binding, Error};
use podssh_relay::identity::{file, Identity, PublicKey};
use podssh_relay::session::OsEntropy;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const PIPE: usize = 64 * 1024;
const LIMIT: Duration = Duration::from_secs(30);
/// The operator's key, which no line of the node names.
const OPERATOR: u8 = 4;

fn identity(seed: u8) -> Arc<Identity> {
    Arc::new(Identity::from_seed(&[seed; 32]))
}

/// The lines of a node.
type Lines = Arc<Mutex<Vec<String>>>;

/// The node `me`: its admission lets no key in, and its door for grants is
/// podssh's, with no `--allow`.
fn node(me: Arc<Identity>) -> (Node, Lines) {
    let lines = Lines::default();
    let kept = lines.clone();
    let say = Arc::new(move |line: String| kept.lock().unwrap().push(line));
    let admit = Arc::new(|_: &PublicKey, _: &Ask| -> Result<(), String> { Err("no allowlist in this test".into()) });
    let redeem = podssh_cli::grants::door("serve-bearer-test", me.public(), None);
    let node = Node {
        identity: me,
        admit,
        events: podssh_relay::e2e::events(say),
        redeem,
        leases: Default::default(),
        gate: None,
        docs: None,
        holds: Default::default(),
    };
    (node, lines)
}

/// A target that echoes each byte, and counts its opens.
fn echo(opened: Arc<AtomicUsize>) -> impl FnOnce() -> std::future::Ready<Result<DuplexStream, String>> {
    move || {
        opened.fetch_add(1, Ordering::SeqCst);
        let (ours, mut theirs) = tokio::io::duplex(PIPE);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok(n) = theirs.read(&mut buf).await {
                if n == 0 || theirs.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = theirs.shutdown().await;
        });
        std::future::ready(Ok(ours))
    }
}

/// One session of the operator to `node`, whose proof `mint` makes: what
/// the target echoed, or why the channel ended; and the target's opens.
async fn session<M, G>(node: Node, mint: M) -> (Result<Vec<u8>, Error>, usize)
where
    M: FnOnce(PublicKey, Binding) -> G + Send + 'static,
    G: Future<Output = Option<Vec<u8>>> + Send + 'static,
{
    let opened = Arc::new(AtomicUsize::new(0));
    let (app, app_end) = tokio::io::duplex(PIPE);
    let (cipher, channel) = ends::operator_bound(app_end, identity(OPERATOR), |_| Ok(()), None, mint, None, |_| {});
    let target = echo(opened.clone());
    let node_task = tokio::spawn(async move { ends::serve_node(cipher, &node, target).await });
    let channel = tokio::spawn(channel);
    let (mut r, mut w) = tokio::io::split(app);
    let _ = w.write_all(b"hello through a bearer").await;
    let _ = w.shutdown().await;
    let mut read = Vec::new();
    let _ = tokio::time::timeout(LIMIT, r.read_to_end(&mut read)).await;
    let ended = tokio::time::timeout(LIMIT, channel).await.expect("the channel's end in time").unwrap();
    let _ = tokio::time::timeout(LIMIT, node_task).await;
    (ended.map(|_| read), opened.load(Ordering::SeqCst))
}

/// A `say` that keeps nothing: a bearer of a key file is made with no line.
fn quiet() -> Say {
    bearer::shared(|line: String| panic!("a key file's bearer says nothing: {line}"))
}

/// The proof of a bearer of `signer`, which also keeps the bytes it sent.
fn kept(
    signer: Signer,
    sent: Arc<Mutex<Option<Vec<u8>>>>,
) -> impl FnOnce(PublicKey, Binding) -> Minted + Send + 'static {
    let made = bearer::proof_of(Some(signer), None, identity(OPERATOR).public(), quiet());
    move |node: PublicKey, binding: Binding| -> Minted {
        let made = made(node, binding);
        Box::pin(async move {
            let blob = made.await;
            *sent.lock().unwrap() = blob.clone();
            blob
        })
    }
}

fn holds(lines: &Lines, words: &str) -> bool {
    lines.lock().unwrap().iter().any(|line| line.contains(words))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bearer_from_a_key_file_lets_the_operator_in() {
    let dir = std::env::temp_dir().join(format!("podssh-serve-bearer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("node.key");
    let key = file::load(&file::Place::File(path.clone()), &mut OsEntropy).expect("the node's key file");
    // The client's whole path: --bearer FILE, kept for the first channel.
    bearer::ask(Some(&path.to_string_lossy()), false, false).unwrap_or_else(|r| panic!("{}", r.message));
    let proof = bearer::proof(None, identity(OPERATOR).public(), quiet());
    let (node, lines) = node(Arc::new(key.identity));
    let (read, opened) = session(node, proof).await;
    assert_eq!(read.expect("the bearer let the operator in"), b"hello through a bearer");
    assert_eq!(opened, 1, "one open of the target");
    assert!(holds(&lines, "the bearer of"), "the node's line names the bearer: {lines:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_bearer_on_a_second_session_is_refused() {
    let me = identity(2);
    let sent = Arc::new(Mutex::new(None));
    let (first, _) = node(me.clone());
    let (read, _) = session(first, kept(Signer::File(me.clone()), sent.clone())).await;
    assert!(read.is_ok(), "the first session: {read:?}");
    let copy = sent.lock().unwrap().clone().expect("the bearer that the first session sent");
    let (second, lines) = node(me);
    let (read, opened) = session(second, move |_: PublicKey, _: Binding| std::future::ready(Some(copy))).await;
    assert!(
        matches!(&read, Err(Error::Refused(podssh_relay::e2e::Refusal::Other(why))) if why == ends::BEARER_REFUSED),
        "a copy came in: {read:?}"
    );
    assert_eq!(opened, 0, "the target was not opened");
    assert!(holds(&lines, "refused a bearer") && holds(&lines, "(binding)"), "the node names the check: {lines:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signer_that_the_node_does_not_take_is_refused() {
    let (node, lines) = node(identity(3));
    let stranger = Signer::File(identity(9));
    let (read, opened) = session(node, kept(stranger, Arc::default())).await;
    assert!(
        matches!(&read, Err(Error::Refused(podssh_relay::e2e::Refusal::Other(why))) if why == ends::BEARER_REFUSED),
        "a stranger's bearer came in: {read:?}"
    );
    assert_eq!(opened, 0, "the target was not opened");
    assert!(holds(&lines, "refused a bearer") && holds(&lines, "(signer)"), "the node names the check: {lines:?}");
}
