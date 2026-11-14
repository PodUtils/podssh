//! `podssh funnel TARGET --opentunnel` (T-532): the funnel of T-180 over the
//! OpenTunnel road (T-530), whose TLS ends at this host. The funnel keeps
//! one tunnel of OpenTunnel's, made once and kept in the cache as a node's
//! is (`opentunnel-HOST--funnel.json`: no node's name starts with `-`), and a
//! bridge that claims the route `@`, the tunnel's own name, so the URL is
//! `https://NAME/`, NAME as the service gave it. Each visitor's connection
//! comes over the bridge from its ClientHello on; podssh-ws's server ends its
//! TLS with the tunnel's certificate and key, offering `http/1.1` alone, as
//! podssh-ws serves no HTTP/2; then the connection is T-180's origin, TARGET
//! for each path, on the visitor's own connection
//! ([`Funnel::on_own_connections`]): the request's head with `Connection:
//! close`, its body as bytes, the answer as TARGET framed it, and a
//! WebSocket's upgrade passed through. The URL is public, so there is no
//! `--allow`. OpenTunnel sees the names, the times and the sizes, never the
//! plaintext. By the operator's ruling Q76, a funnel that the quick tunnel
//! cannot carry takes this road unasked, `PODSSH_OPENTUNNEL=no` turns that
//! off, and the first tunnel then has a bound, as an unasked node's has.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::opentunnel::api::Api;
use podssh_relay::opentunnel::conn::Visitor;
use podssh_relay::opentunnel::far::{self, TLS_LIMIT};
use podssh_relay::opentunnel::wire::ROOT_ROUTE;
use podssh_relay::opentunnel::{self, dial, Service, Store};
use podssh_relay::quick::funnel::{Dial, Funnel};
use podssh_relay::quick::origin::Origin;
use podssh_ws::tls_server::{TlsAcceptor, HTTP1};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

use crate::exitmap::Fault;
use crate::node_opentunnel::Keys;
use crate::relay_settings::Refusal;

/// The line that a funnel of this road says: who sees its traffic.
pub const TLS_LINE: &str = "TLS ends at this host; OpenTunnel sees the names, the times and the sizes.";
/// The label of the funnel's tunnel in the cache: no node's name, as none
/// starts with `-`, so a node's tunnel is never a funnel's.
pub const LABEL: &str = "-funnel";
/// The bound on the first tunnel of a funnel that takes the road unasked.
const UNASKED_LIMIT: Duration = Duration::from_secs(20);
/// How long a visitor may keep its side open once TARGET's side ended.
const END_WAIT: Duration = Duration::from_secs(10);

/// The road's service, when the road is on; `PODSSH_OPENTUNNEL` read as a
/// node reads it.
pub(crate) fn service() -> Result<Option<Service>, Refusal> {
    crate::node_opentunnel::service()
}

/// Serve TARGET, dialed by `dial` for each request, at the tunnel's name of
/// `service` until `stopped`; `unasked` is why the funnel takes the road
/// with no `--opentunnel`. The URL alone goes to `out`, once the bridge
/// attached. Returns the process exit code.
pub(crate) async fn serve(
    shown: &str,
    dial: Dial,
    service: Service,
    unasked: Option<String>,
    mut stopped: watch::Receiver<bool>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let say: opentunnel::Say = Arc::new(|line: String| podssh_ssh::err_line!("podssh funnel: {line}"));
    // SSL_CERT_FILE replaces the roots, as for each name podssh checks.
    let api = Api::new(service.clone(), dial::tls(crate::pairs::trust(None), ProxyChoice::FromEnvironment));
    let reach = far::online(api, Store::cache(&service, LABEL), &Keys, say.clone());
    let reached = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, reach)
            .await
            .unwrap_or_else(|_| Err(format!("no tunnel within {} s", UNASKED_LIMIT.as_secs()))),
        None => reach.await,
    };
    let (node, provisioned) = match reached {
        Ok(online) => online,
        Err(why) => {
            let message = format!("no OpenTunnel road through {service}: {why}");
            return Refusal { message, code: Fault::RelayUnreachable.code() }.report("funnel", err);
        }
    };
    if let Some(why) = &unasked {
        let _ = writeln!(
            err,
            "podssh funnel: {why}; so the funnel takes the OpenTunnel road unasked, through {service}, by the \
             operator's ruling Q76 ({}=no turns it off)",
            opentunnel::ENV
        );
    }
    let url = url_of(&node.record.hostname);
    let _ = writeln!(err, "podssh funnel: serving {shown} at {url} until Ctrl-C");
    let _ = writeln!(err, "podssh funnel: {TLS_LINE}");
    let kept = crate::node_opentunnel::kept_line(provisioned.path.as_ref(), provisioned.made);
    let _ = writeln!(err, "podssh funnel: {kept}");
    let acceptor = match node.acceptor(&[HTTP1]) {
        Ok(acceptor) => acceptor,
        Err(why) => {
            let message = format!("the funnel's TLS: {why}");
            return Refusal { message, code: Fault::SessionFault.code() }.report("funnel", err);
        }
    };
    let origin: Arc<dyn Origin> = Arc::new(Funnel::new(dial, say.clone()).on_own_connections());
    let opened = {
        let say = say.clone();
        move |visitor: Visitor| {
            tokio::spawn(visit(acceptor.clone(), origin.clone(), say.clone(), visitor));
        }
    };
    // The URL goes out once a bridge holds the route, so that it serves.
    let (told, mut first) = oneshot::channel::<()>();
    let told = Mutex::new(Some(told));
    let attached = move || {
        if let Some(told) = told.lock().unwrap_or_else(|e| e.into_inner()).take() {
            crate::detach::ready("funnel");
            let _ = told.send(());
        }
    };
    let routes = vec![ROOT_ROUTE.to_string()];
    let reached = format!("a visitor opens {url}");
    let bridges = far::bridges(&node, &routes, &reached, opened, attached);
    tokio::pin!(bridges);
    let stop = async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    tokio::pin!(stop);
    let mut printed = false;
    let ended = loop {
        tokio::select! {
            why = &mut bridges => break Some(why),
            () = &mut stop => break None,
            got = &mut first, if !printed => {
                printed = true;
                if got.is_ok() {
                    let _ = writeln!(out, "{url}");
                    let _ = out.flush();
                }
            }
        }
    };
    match ended {
        Some(why) => {
            let message = format!("the OpenTunnel road ended: {why}");
            Refusal { message, code: Fault::RelayUnreachable.code() }.report("funnel", err)
        }
        None => {
            say("stopped".into());
            0
        }
    }
}

/// The funnel's URL: the tunnel's own name, as the service gave it.
pub fn url_of(hostname: &str) -> String {
    format!("https://{hostname}/")
}

/// One visitor: its TLS ended here, then its connection to the origin, both
/// ways, until TARGET's side ended and the visitor's followed, or a bound.
async fn visit(acceptor: TlsAcceptor, origin: Arc<dyn Origin>, say: opentunnel::Say, visitor: Visitor) {
    let peer = visitor.peer.clone();
    let tls = match tokio::time::timeout(TLS_LIMIT, acceptor.accept(visitor)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return say(format!("a visitor from {peer}: TLS failed: {e}")),
        Err(_) => return say(format!("a visitor from {peer}: no TLS within {} s", TLS_LIMIT.as_secs())),
    };
    pump(tls, origin.connect(None)).await;
}

/// Both ways between the visitor and the origin's pipe. The origin's side
/// ends with its answer (or a WebSocket's end); the visitor's then has
/// [`END_WAIT`] to close, so that a visitor that keeps its side open holds
/// no task.
async fn pump<V, P>(visitor: V, pipe: P)
where
    V: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_visitor, mut to_visitor) = tokio::io::split(visitor);
    let (mut from_pipe, mut to_pipe) = tokio::io::split(pipe);
    let up = async {
        let _ = tokio::io::copy(&mut from_visitor, &mut to_pipe).await;
        let _ = to_pipe.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut from_pipe, &mut to_visitor).await;
        // TLS's close_notify, then the end of the visitor's connection.
        let _ = to_visitor.shutdown().await;
    };
    tokio::pin!(up, down);
    tokio::select! {
        () = &mut up => (&mut down).await,
        () = &mut down => {
            let _ = tokio::time::timeout(END_WAIT, &mut up).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn the_url_is_the_tunnel_s_own_name_and_the_label_is_no_node_s() {
        assert_eq!(url_of("abcdefghijkl.opentunnel.xyz"), "https://abcdefghijkl.opentunnel.xyz/");
        assert!(crate::pairs::check_label(LABEL).is_err(), "a node's name never names the funnel's tunnel");
        assert!(TLS_LINE.contains("TLS ends at this host") && TLS_LINE.contains("OpenTunnel sees"));
    }

    #[tokio::test]
    async fn the_pump_ends_once_the_origin_answered_and_the_visitor_closed() {
        let (visitor, mut far_visitor) = tokio::io::duplex(1024);
        let (pipe, mut far_pipe) = tokio::io::duplex(1024);
        let pumping = tokio::spawn(pump(visitor, pipe));
        far_visitor.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut asked = [0u8; 18];
        far_pipe.read_exact(&mut asked).await.unwrap();
        far_pipe.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
        drop(far_pipe);
        let mut answer = Vec::new();
        far_visitor.read_to_end(&mut answer).await.unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 204"));
        drop(far_visitor);
        tokio::time::timeout(Duration::from_secs(5), pumping).await.expect("the pump ended").unwrap();
    }
}
