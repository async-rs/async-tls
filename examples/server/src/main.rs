use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::stream::StreamExt;
use async_std::task;
use async_tls::TlsAcceptor;
use futures_lite::io::AsyncWriteExt;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, read_one, Item};

use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Options {
    addr: String,

    /// cert file
    #[structopt(short = "c", long = "cert", parse(from_os_str))]
    cert: PathBuf,

    /// key file
    #[structopt(short = "k", long = "key", parse(from_os_str))]
    key: PathBuf,
}

/// Load the passed certificates file
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    Ok(certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?
        .into_iter()
        .map(Certificate)
        .collect())
}

/// Load the passed keys file
fn load_key(path: &Path) -> io::Result<PrivateKey> {
    match read_one(&mut BufReader::new(File::open(path)?)) {
        Ok(Some(Item::RSAKey(data) | Item::PKCS8Key(data))) => Ok(PrivateKey(data)),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid key in {}", path.display()),
        )),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
    }
}

/// Configure the server using rusttls
/// See https://docs.rs/rustls/0.16.0/rustls/struct.ServerConfig.html for details
///
/// A TLS server needs a certificate and a fitting private key
fn load_config(options: &Options) -> io::Result<ServerConfig> {
    let certs = load_certs(&options.cert)?;
    debug_assert_eq!(1, certs.len());
    let key = load_key(&options.key)?;

    // we don't use client authentication
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        // set this server to use one cert together with the loaded private key
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    Ok(config)
}

/// The connection handling function.
async fn handle_connection(acceptor: &TlsAcceptor, tcp_stream: &mut TcpStream) -> io::Result<()> {
    let peer_addr = tcp_stream.peer_addr()?;
    println!("Connection from: {}", peer_addr);

    // Calling `acceptor.accept` will start the TLS handshake
    let handshake = acceptor.accept(tcp_stream);
    // The handshake is a future we can await to get an encrypted
    // stream back.
    let mut tls_stream = handshake.await?;

    // Use the stream like any other
    tls_stream
        .write_all(
            &b"HTTP/1.0 200 ok\r\n\
        Connection: close\r\n\
        Content-length: 12\r\n\
        \r\n\
        Hello world!"[..],
        )
        .await?;

    tls_stream.close().await?;

    Ok(())
}

fn main() -> io::Result<()> {
    let options = Options::from_args();

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    let config = load_config(&options)?;

    // We create one TLSAcceptor around a shared configuration.
    // Cloning the acceptor will not clone the configuration.
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // We start a classic TCP server, passing all connections to the
    // handle_connection async function
    task::block_on(async {
        let listener = TcpListener::bind(&addr).await?;
        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            // We use one acceptor per connection, so
            // we need to clone the current one.
            let acceptor = acceptor.clone();
            let mut stream = stream?;

            // TODO: scoped tasks?
            task::spawn(async move {
                let res = handle_connection(&acceptor, &mut stream).await;
                match res {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("{:?}", err);
                    }
                };
            });
        }

        Ok(())
    })
}
