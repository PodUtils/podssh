//! A listener of a Unix socket at a path, for the tests of a node's route
//! to one (T-714, T-852): the standard library's on Unix, and an AF_UNIX
//! socket by WinSock on Windows, where the standard library has none.

#![allow(dead_code)]

#[cfg(unix)]
mod sock {
    use std::os::unix::net::{UnixListener, UnixStream};

    pub struct Listener(UnixListener);

    impl Listener {
        pub fn bind(path: &str) -> Listener {
            Listener(UnixListener::bind(path).expect("a socket in the test's directory"))
        }

        pub fn accept(&self) -> Option<UnixStream> {
            self.0.accept().ok().map(|(stream, _)| stream)
        }
    }
}

/// A connected socket of any family carries bytes as a TCP one.
#[cfg(windows)]
mod sock {
    use std::net::TcpStream;
    use std::os::windows::io::FromRawSocket;

    use windows_sys::Win32::Networking::WinSock as ws;

    pub struct Listener(ws::SOCKET);

    impl Listener {
        pub fn bind(path: &str) -> Listener {
            // SAFETY: an all-zero SOCKADDR_UN is valid.
            let mut addr: ws::SOCKADDR_UN = unsafe { std::mem::zeroed() };
            addr.sun_family = ws::AF_UNIX;
            for (slot, b) in addr.sun_path.iter_mut().zip(path.as_bytes()) {
                *slot = *b as _;
            }
            let len = std::mem::size_of::<ws::SOCKADDR_UN>() as i32;
            // SAFETY: WinSock calls on a socket of this test.
            unsafe {
                let mut data: ws::WSADATA = std::mem::zeroed();
                assert_eq!(ws::WSAStartup(0x0202, &mut data), 0);
                let s = ws::socket(ws::AF_UNIX as i32, ws::SOCK_STREAM, 0);
                assert_ne!(s, ws::INVALID_SOCKET, "AF_UNIX on this Windows");
                assert_eq!(ws::bind(s, (&addr as *const ws::SOCKADDR_UN).cast(), len), 0, "bind");
                assert_eq!(ws::listen(s, 8), 0, "listen");
                Listener(s)
            }
        }

        pub fn accept(&self) -> Option<TcpStream> {
            // SAFETY: an accept on the listener above; the socket is owned by the stream.
            unsafe {
                let s = ws::accept(self.0, std::ptr::null_mut(), std::ptr::null_mut());
                (s != ws::INVALID_SOCKET).then(|| TcpStream::from_raw_socket(s as u64))
            }
        }
    }
}

pub use sock::Listener;
