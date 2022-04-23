use async_std::channel::bounded;
use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use async_tls::{TlsAcceptor, TlsConnector};
use lazy_static::lazy_static;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;

const CERT: &str = include_str!("end.cert");
const CHAIN: &str = include_str!("end.chain");
const RSA: &str = include_str!("end.rsa");

lazy_static! {
    static ref TEST_SERVER: (SocketAddr, &'static str, &'static str) = {
        let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
        let cert = cert.into_iter().map(Certificate).collect();
        let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();
        let key = PrivateKey(keys.pop().unwrap());
        let sconfig = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(sconfig));

        let (send, recv) = bounded(1);

        task::spawn(async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let listener = TcpListener::bind(&addr).await?;

            send.send(listener.local_addr()?).await.unwrap();

            let mut incoming = listener.incoming();
            while let Some(stream) = incoming.next().await {
                let acceptor = acceptor.clone();
                task::spawn(async move {
                    use futures_util::io::AsyncReadExt;
                    let stream = acceptor.accept(stream?).await?;
                    let (mut reader, mut writer) = stream.split();
                    io::copy(&mut reader, &mut writer).await?;
                    Ok(()) as io::Result<()>
                });
            }

            Ok(()) as io::Result<()>
        });

        let addr = task::block_on(async move { recv.recv().await.unwrap() });
        (addr, "localhost", CHAIN)
    };
}

fn start_server() -> &'static (SocketAddr, &'static str, &'static str) {
    &*TEST_SERVER
}

async fn start_client(addr: SocketAddr, domain: &str, config: Arc<ClientConfig>) -> io::Result<()> {
    const FILE: &[u8] = include_bytes!("../README.md");

    let config = TlsConnector::from(config);
    let mut buf = vec![0; FILE.len()];

    let stream = TcpStream::connect(&addr).await?;
    let mut stream = config.connect(domain, stream).await?;
    stream.write_all(FILE).await?;
    stream.read_exact(&mut buf).await?;

    assert_eq!(buf, FILE);

    stream.flush().await?;
    Ok(())
}

#[test]
fn pass() {
    let (addr, domain, chain) = start_server();
    let mut root_store = RootCertStore::empty();
    let chain = [chain.as_bytes().to_vec()];
    let (added, ignored) = root_store.add_parsable_certificates(&chain);
    assert!(added >= 1 && ignored == 0);
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    task::block_on(start_client(*addr, domain, Arc::new(config))).unwrap();
}

#[test]
fn fail() {
    let (addr, domain, chain) = start_server();
    let mut root_store = RootCertStore::empty();
    let chain = [chain.as_bytes().to_vec()];
    let (added, ignored) = root_store.add_parsable_certificates(&chain);
    assert!(added >= 1 && ignored == 0);
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);

    assert_ne!(domain, &"google.com");
    assert!(task::block_on(start_client(*addr, "google.com", config)).is_err());
}
