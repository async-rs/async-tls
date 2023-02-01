use super::Stream;
use futures_executor::block_on;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use futures_util::task::{noop_waker_ref, Context};
use futures_util::{future, ready};
use rustls::{
    Certificate, ClientConfig, ClientConnection, ConnectionCommon, PrivateKey, RootCertStore,
    ServerConfig, ServerConnection, ServerName,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::convert::TryFrom;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

struct Good<'a, D>(&'a mut ConnectionCommon<D>);

impl<'a, D> AsyncRead for Good<'a, D> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.0.write_tls(buf.by_ref()))
    }
}

impl<'a, D> AsyncWrite for Good<'a, D> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = self.0.read_tls(buf.by_ref())?;
        self.0
            .process_new_packets()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0
            .process_new_packets()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.send_close_notify();
        self.poll_flush(cx)
    }
}

struct Bad(bool);

impl AsyncRead for Bad {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for Bad {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn stream_good() -> io::Result<()> {
    block_on(_stream_good())
}

async fn _stream_good() -> io::Result<()> {
    const FILE: &[u8] = include_bytes!("../../README.md");
    let (mut server, mut client) = make_pair();
    future::poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;
    io::copy(&mut Cursor::new(FILE), &mut server.writer())?;
    server.send_close_notify();

    {
        let mut good = Good(&mut server);
        let mut stream = Stream::new(&mut good, &mut client);

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        assert_eq!(buf, FILE);
        stream.write_all(b"Hello World!").await?;
        stream.conn.send_close_notify();
        stream.close().await?;
    }

    let mut buf = String::new();
    server.reader().read_to_string(&mut buf)?;
    assert_eq!(buf, "Hello World!");

    Ok(()) as io::Result<()>
}

#[test]
fn stream_bad() -> io::Result<()> {
    let fut = async {
        let (mut server, mut client) = make_pair();
        future::poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;
        client.set_buffer_limit(Some(1024));

        let mut bad = Bad(true);
        let mut stream = Stream::new(&mut bad, &mut client);
        assert_eq!(
            future::poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
            8
        );
        assert_eq!(
            future::poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
            8
        );
        let r = future::poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x00; 1024])).await?; // fill buffer
        assert!(r < 1024);

        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(stream
            .as_mut_pin()
            .poll_write(&mut cx, &[0x01])
            .is_pending());

        Ok(()) as io::Result<()>
    };

    block_on(fut)
}

#[test]
fn stream_handshake() -> io::Result<()> {
    let fut = async {
        let (mut server, mut client) = make_pair();

        {
            let mut good = Good(&mut server);
            let mut stream = Stream::new(&mut good, &mut client);
            let (r, w) = future::poll_fn(|cx| stream.complete_io(cx)).await?;

            assert!(r > 0);
            assert!(w > 0);

            future::poll_fn(|cx| stream.complete_io(cx)).await?; // finish server handshake
        }

        assert!(!server.is_handshaking());
        assert!(!client.is_handshaking());

        Ok(()) as io::Result<()>
    };

    block_on(fut)
}

#[test]
fn stream_handshake_eof() -> io::Result<()> {
    let fut = async {
        let (_, mut client) = make_pair();

        let mut bad = Bad(false);
        let mut stream = Stream::new(&mut bad, &mut client);

        let mut cx = Context::from_waker(noop_waker_ref());
        let r = stream.complete_io(&mut cx);
        assert_eq!(
            r.map_err(|err| err.kind()),
            Poll::Ready(Err(io::ErrorKind::UnexpectedEof))
        );

        Ok(()) as io::Result<()>
    };

    block_on(fut)
}

#[test]
fn stream_eof() -> io::Result<()> {
    let fut = async {
        let (mut server, mut client) = make_pair();
        future::poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

        let mut eof_stream = Bad(false);
        let mut stream = Stream::new(&mut eof_stream, &mut client);

        let mut buf = Vec::new();
        let res = stream.read_to_end(&mut buf).await;
        assert_eq!(
            res.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::UnexpectedEof)
        );

        Ok(()) as io::Result<()>
    };

    block_on(fut)
}

fn make_pair() -> (ServerConnection, ClientConnection) {
    const CERT: &str = include_str!("../../tests/end.cert");
    const CHAIN: &str = include_str!("../../tests/end.chain");
    const RSA: &str = include_str!("../../tests/end.rsa");

    let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
    let cert = cert.into_iter().map(Certificate).collect();
    let mut keys = pkcs8_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();
    let key = PrivateKey(keys.pop().unwrap());
    let sconfig = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    let server = ServerConnection::new(Arc::new(sconfig));

    let domain = ServerName::try_from("localhost").unwrap();
    let mut root_store = RootCertStore::empty();
    let chain = certs(&mut BufReader::new(Cursor::new(CHAIN))).unwrap();
    let (added, ignored) = root_store.add_parsable_certificates(&chain);
    assert!(added >= 1 && ignored == 0);
    let cconfig = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let client = ClientConnection::new(Arc::new(cconfig), domain);

    (server.unwrap(), client.unwrap())
}

fn do_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    let mut good = Good(server);
    let mut stream = Stream::new(&mut good, client);

    if stream.conn.is_handshaking() {
        ready!(stream.complete_io(cx))?;
    }

    if stream.conn.wants_write() {
        ready!(stream.complete_io(cx))?;
    }

    Poll::Ready(Ok(()))
}
