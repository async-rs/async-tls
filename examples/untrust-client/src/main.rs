use async_std::io;
use async_std::net::TcpStream;
use async_std::prelude::*;
use async_std::task;
use async_tls::TlsConnector;
use std::sync::Arc;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Options {
    /// The host ip address to connect to
    serverip: String,

    /// The host port to connect to
    #[structopt(short = "p", long = "port", default_value = "443")]
    port: u16,

}

mod danger {

    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

fn main() -> io::Result<()> {
    let options = Options::from_args();
    // Create a bare bones HTTP GET request
    let http_request = format!("GET / HTTP/1.0\r\n");

    task::block_on(async move {
        let addr = format!("{}:{}", options.serverip, options.port);

        let mut config = rustls::ClientConfig::new();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));

        let tcp_stream = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::from(config);
        let mut tls_stream = connector.connect("any", tcp_stream).await.unwrap();

        // We write our crafted HTTP request to it
        tls_stream.write_all(http_request.as_bytes()).await?;

        // And read it all to stdout
        let mut stdout = io::stdout();
        io::copy(&mut tls_stream, &mut stdout).await?;

        // Voila, we're done here!
        Ok(())
    })
}
