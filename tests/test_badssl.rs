extern crate tokio;
extern crate webpki;
extern crate webpki_roots;
extern crate tokio_rustls;

use std::io;
use std::sync::Arc;
use std::net::ToSocketAddrs;
use self::tokio::io as aio;
use self::tokio::prelude::*;
use self::tokio::net::TcpStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::{ TlsConnector, client::TlsStream };


fn get(config: Arc<ClientConfig>, domain: &str)
    -> io::Result<(TlsStream<TcpStream>, String)>
{
    let config = TlsConnector::from(config);
    let input = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let addr = (domain, 443)
        .to_socket_addrs()?
        .next().unwrap();

    TcpStream::connect(&addr)
        .and_then(move |stream| {
            let domain = webpki::DNSNameRef::try_from_ascii_str(&domain).unwrap();
            config.connect(domain, stream)
        })
        .and_then(move |stream| aio::write_all(stream, input))
        .and_then(move |(stream, _)| aio::read_to_end(stream, Vec::new()))
        .map(|(stream, buf)| (stream, String::from_utf8(buf).unwrap()))
        .wait()
}

#[test]
fn test_badssl() {
    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = Arc::new(config);
    let domain = "mozilla-modern.badssl.com";

    let (_, output) = get(config.clone(), domain).unwrap();
    assert!(output.contains("<title>mozilla-modern.badssl.com</title>"));
}
