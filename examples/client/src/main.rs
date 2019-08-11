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

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

    let domain_option = options.domain.unwrap_or(options.host);
    let domain = DNSNameRef::try_from_ascii_str(&domain_option)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?
            .to_owned();

    let http_request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain_option);

    let connector = TlsConnector::default();

    task::block_on(async {
        let stream = TcpStream::connect(&addr).await?;

        let mut stream = connector.connect(&domain, stream)?.await?;
        stream.write_all(http_request.as_bytes()).await?;

        let mut stdout = io::stdout();
        io::copy(&mut stream, &mut stdout).await?;

        Ok(())
    })
}
