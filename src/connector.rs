use crate::common::tls_state::TlsState;

use crate::client;

use futures_io::{AsyncRead, AsyncWrite};
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName};
use std::convert::TryFrom;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// The TLS connecting part. The acceptor drives
/// the client side of the TLS handshake process. It works
/// on any asynchronous stream.
///
/// It provides a simple interface (`connect`), returning a future
/// that will resolve when the handshake process completed. On
/// success, it will hand you an async `TlsStream`.
///
/// To create a `TlsConnector` with a non-default configuation, create
/// a `rusttls::ClientConfig` and call `.into()` on it.
///
/// ## Example
///
/// ```rust
/// use async_tls::TlsConnector;
///
/// async_std::task::block_on(async {
///     let connector = TlsConnector::default();
///     let tcp_stream = async_std::net::TcpStream::connect("example.com").await?;
///     let encrypted_stream = connector.connect("example.com", tcp_stream).await?;
///
///     Ok(()) as async_std::io::Result<()>
/// });
/// ```
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
    #[cfg(feature = "early-data")]
    early_data: bool,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> TlsConnector {
        TlsConnector {
            inner,
            #[cfg(feature = "early-data")]
            early_data: false,
        }
    }
}

impl From<ClientConfig> for TlsConnector {
    fn from(inner: ClientConfig) -> TlsConnector {
        TlsConnector {
            inner: Arc::new(inner),
            #[cfg(feature = "early-data")]
            early_data: false,
        }
    }
}

impl Default for TlsConnector {
    fn default() -> Self {
        let mut root_certs = RootCertStore::empty();
        root_certs.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        Arc::new(config).into()
    }
}

impl TlsConnector {
    /// Create a new TlsConnector with default configuration.
    ///
    /// This is the same as calling `TlsConnector::default()`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Enable 0-RTT.
    ///
    /// You must also set `enable_early_data` to `true` in `ClientConfig`.
    #[cfg(feature = "early-data")]
    pub fn early_data(mut self, flag: bool) -> TlsConnector {
        self.early_data = flag;
        self
    }

    /// Connect to a server. `stream` can be any type implementing `AsyncRead` and `AsyncWrite`,
    /// such as TcpStreams or Unix domain sockets.
    ///
    /// The function will return a `Connect` Future, representing the connecting part of a Tls
    /// handshake. It will resolve when the handshake is over.
    #[inline]
    pub fn connect<'a, IO>(&self, domain: impl AsRef<str>, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with(domain, stream, |_| ())
    }

    // NOTE: Currently private, exposing ClientConnection exposes rusttls
    // Early data should be exposed differently
    fn connect_with<'a, IO, F>(&self, domain: impl AsRef<str>, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientConnection),
    {
        let domain = match ServerName::try_from(domain.as_ref()) {
            Ok(domain) => domain,
            Err(_) => {
                return Connect(ConnectInner::Error(Some(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid domain",
                ))))
            }
        };

        let mut session = match ClientConnection::new(self.inner.clone(), domain) {
            Ok(session) => session,
            Err(_) => {
                return Connect(ConnectInner::Error(Some(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid connection",
                ))))
            }
        };

        f(&mut session);

        #[cfg(not(feature = "early-data"))]
        {
            Connect(ConnectInner::Handshake(client::MidHandshake::Handshaking(
                client::TlsStream {
                    session,
                    io: stream,
                    state: TlsState::Stream,
                },
            )))
        }

        #[cfg(feature = "early-data")]
        {
            Connect(ConnectInner::Handshake(if self.early_data {
                client::MidHandshake::EarlyData(client::TlsStream {
                    session,
                    io: stream,
                    state: TlsState::EarlyData,
                    early_data: (0, Vec::new()),
                })
            } else {
                client::MidHandshake::Handshaking(client::TlsStream {
                    session,
                    io: stream,
                    state: TlsState::Stream,
                    early_data: (0, Vec::new()),
                })
            }))
        }
    }
}

/// Future returned from `TlsConnector::connect` which will resolve
/// once the connection handshake has finished.
pub struct Connect<IO>(ConnectInner<IO>);

enum ConnectInner<IO> {
    Error(Option<io::Error>),
    Handshake(client::MidHandshake<IO>),
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.0 {
            ConnectInner::Error(ref mut err) => {
                Poll::Ready(Err(err.take().expect("Polled twice after being Ready")))
            }
            ConnectInner::Handshake(ref mut handshake) => Pin::new(handshake).poll(cx),
        }
    }
}
