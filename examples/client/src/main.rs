#![feature(async_await)]

use async_std::io;
use futures::io::AsyncWriteExt;
use async_std::net::TcpStream;
use async_std::task;
use async_tls::TlsConnector;
use webpki::DNSNameRef;
use std::net::ToSocketAddrs;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Options {
    /// The host to connect to
    host: String,

    /// The port to connect to
    #[structopt(short = "p", long = "port", default_value = "443")]
    port: u16,

    /// The domain to connect to. This may be different from the host!
    #[structopt(short = "d", long = "domain")]
    domain: Option<String>,
}

fn main() -> io::Result<()> {
    let options = Options::from_args();

    // Check if the provided host exists
    // TODO: this is blocking
    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

    // If no domain was passed, the host is also the domain to connect to
    let domain_option = options.domain.unwrap_or(options.host);
    // Use webpki::DNSNameRef to validate the domain for correctness
    let domain = DNSNameRef::try_from_ascii_str(&domain_option)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?
            .to_owned();

    // Create a bare bones HTTP GET request
    let http_request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain_option);

    // Create default connector comes preconfigured with all you need to safely connect
    // to remote servers!
    let connector = TlsConnector::default();

    task::block_on(async {
        // Open a normal TCP connection, just as you are used to
        let tcp_stream = TcpStream::connect(&addr).await?;

        // Use the connector to start the handshake process.
        // This might fail early if you pass an invalid domain
        // (Which we already checked)
        // This consumes the TCP stream.
        let handshake = connector.connect(&domain, tcp_stream)?;
        // Awaiting the handshake gives you an encrypted
        // stream back which you can use like any other
        let tls_stream = handshake.await?;
        // We write our crafted HTTP request to it
        tls_stream.write_all(http_request.as_bytes()).await?;

        // And dump the whole thing to stdio
        let mut stdout = io::stdout();
        io::copy(&mut stream, &mut stdout).await?;

        // Voila, we're done here!
        Ok(())
    })
}
