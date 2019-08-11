use crate::common::tls_state::TlsState;

use crate::client;

use futures::io::{AsyncRead, AsyncWrite};
use rustls::{ClientConfig,ClientSession};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::io;
use webpki::DNSNameRef;

/// The TLS connecting part. The acceptor drives
/// the client side of the TLS handshake process. It works
/// on any asynchronous stream.
/// 
/// It provides a simple interface (`connect`), returning a future
/// that will resolve when the handshake process completed. On
/// success, it will hand you an async `TLSStream`.
/// 
/// ## Example
/// 
/// ```rust
/// let mut stream = acceptor.accept(stream).await?;
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

impl Default for TlsConnector {
    fn default() -> Self {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        Arc::new(config).into()
    }
}

impl TlsConnector {
    pub fn new() -> Self {
        Default::default()
    }

    /// Enable 0-RTT.
    ///
    /// Note that you want to use 0-RTT.
    /// You must set `enable_early_data` to `true` in `ClientConfig`.
    #[cfg(feature = "early-data")]
    pub fn early_data(mut self, flag: bool) -> TlsConnector {
        self.early_data = flag;
        self
    }

    pub fn connect<'a, IO>(&self, domain: impl AsRef<str>, stream: IO) -> io::Result<Connect<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with(domain, stream, |_| ())
    }

    #[inline]
    pub fn connect_with<'a, IO, F>(
        &self,
        domain: impl AsRef<str>,
        stream: IO,
        f: F,
    ) -> io::Result<Connect<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ClientSession),
    {
        let domain = DNSNameRef::try_from_ascii_str(domain.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid domain"))?;
        let mut session = ClientSession::new(&self.inner, domain);
        f(&mut session);

        #[cfg(not(feature = "early-data"))]
        {
            Ok(Connect(client::MidHandshake::Handshaking(
                client::TlsStream {
                    session,
                    io: stream,
                    state: TlsState::Stream,
                },
            )))
        }

        #[cfg(feature = "early-data")]
        {
            Ok(Connect(if self.early_data {
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
pub struct Connect<IO>(client::MidHandshake<IO>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<client::TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

#[cfg(feature = "early-data")]
#[cfg(test)]
mod test_0rtt;
