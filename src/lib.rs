//! Asynchronous TLS/SSL streams for async-std and AsyncRead/AsyncWrite sockets using [rustls](https://github.com/ctz/rustls).

#![deny(unsafe_code)]

pub mod client;
pub mod server;
mod common;
mod rusttls;
mod connector;
mod acceptor;

pub use acceptor::TlsAcceptor as TlsAcceptor;
pub use connector::TlsConnector as TlsConnector;
