//! A port of the loopback that refuses each dial, for a test of a target or
//! a relay that is not there. A port that is bound and let go can be handed
//! at once to a listener of a test that runs beside this one, which then
//! answers the dial, or counts it (`tests/ping.rs`, the gate at `04b7759`).
//! On Linux a socket bound and never listening refuses a dial at once, and
//! no other test can take its port while it is held. macOS drops the dial
//! to it, which then times out (the gate at `6c5a680`), so there, and on
//! Windows, the port is let go as before.

/// The port and its socket, which the test holds while the port is dialled.
// Not each file of tests that takes it builds each of its tests.
#[allow(dead_code)]
pub fn refusing() -> (u16, tokio::net::TcpSocket) {
    if cfg!(target_os = "linux") {
        return held();
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    (port, tokio::net::TcpSocket::new_v4().unwrap())
}

/// A port bound and held, never listening, on each system: a dial of it is
/// refused on Linux, and may wait for its limit elsewhere.
#[allow(dead_code)]
pub fn held() -> (u16, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    (socket.local_addr().unwrap().port(), socket)
}
