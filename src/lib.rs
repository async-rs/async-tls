//! Asynchronous TLS/SSL streams for async-std and AsyncRead/AsyncWrite sockets using [rustls](https://github.com/ctz/rustls).

#![deny(unsafe_code)]

mod acceptor;
pub mod client;
mod common;
mod connector;
mod rusttls;
pub mod server;

pub use acceptor::{Accept, TlsAcceptor};
pub use connector::{Connect, TlsConnector};

#[cfg(feature = "early-data")]
#[cfg(test)]
mod test_0rtt;
