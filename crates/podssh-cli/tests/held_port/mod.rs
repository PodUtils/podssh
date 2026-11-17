//! A port of the loopback that refuses each dial, for a test of a target or
//! a relay that is not there: bound and never listening, held for as long
//! as its socket lives. A port that is bound and let go can be handed at
//! once to a listener of a test that runs beside this one, which then
//! answers the dial, or counts it (`tests/ping.rs`, the gate at `04b7759`).

/// The port and its socket, which the test holds while the port is dialled.
// Not each file of tests that takes it builds each of its tests.
#[allow(dead_code)]
pub fn refusing() -> (u16, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    (socket.local_addr().unwrap().port(), socket)
}
