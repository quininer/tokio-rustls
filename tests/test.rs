use std::{ io, thread };
use std::io::{ BufReader, Cursor };
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::net::SocketAddr;
use lazy_static::lazy_static;
use romio::{ TcpListener, TcpStream };
use futures::prelude::*;
use futures::executor;
use futures::task::SpawnExt;
use rustls::{ ServerConfig, ClientConfig };
use rustls::internal::pemfile::{ certs, rsa_private_keys };
use futures_rustls::{ TlsConnector, TlsAcceptor };

const CERT: &str = include_str!("end.cert");
const CHAIN: &str = include_str!("end.chain");
const RSA: &str = include_str!("end.rsa");

lazy_static!{
    static ref TEST_SERVER: (SocketAddr, &'static str, &'static str) = {
        let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
        let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();

        let mut config = ServerConfig::new(rustls::NoClientAuth::new());
        config.set_single_cert(cert, keys.pop().unwrap())
            .expect("invalid key or certificate");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let (send, recv) = channel();

        thread::spawn(move || {
            let mut localpool = executor::LocalPool::new();
            let mut handle = localpool.spawner();

            let done = async move {
                let addr = SocketAddr::from(([127, 0, 0, 1], 0));
                let mut listener = TcpListener::bind(&addr)?;

                send.send(listener.local_addr()?).unwrap();

                let mut incoming = listener.incoming();
                while let Some(stream) = incoming.next().await {
                    let acceptor = acceptor.clone();
                    let fut = async move {
                        let stream = acceptor.accept(stream?).await?;

                        let (reader, mut writer) = stream.split();
                        reader.copy_into(&mut writer).await?;

                        Ok(()) as io::Result<()>
                    }.unwrap_or_else(|err| eprintln!("server: {:?}", err));

                    handle.spawn(fut).unwrap();
                }

                Ok(()) as io::Result<()>
            }.unwrap_or_else(|err| eprintln!("server: {:?}", err));

            localpool.run_until(done);
        });

        let addr = recv.recv().unwrap();
        (addr, "testserver.com", CHAIN)
    };
}

fn start_server() -> &'static (SocketAddr, &'static str, &'static str) {
    &*TEST_SERVER
}

async fn start_client(addr: SocketAddr, domain: &str, config: Arc<ClientConfig>) -> io::Result<()> {
    const FILE: &'static [u8] = include_bytes!("../README.md");

    let domain = webpki::DNSNameRef::try_from_ascii_str(domain).unwrap();
    let config = TlsConnector::from(config);
    let mut buf = vec![0; FILE.len()];

    let stream = TcpStream::connect(&addr).await?;
    let mut stream = config.connect(domain, stream).await?;
    stream.write_all(FILE).await?;
    stream.flush().await?;
    stream.read_exact(&mut buf).await?;

    assert_eq!(buf, FILE);

    Ok(())
}

async fn async_pass() -> io::Result<()> {
    let (addr, domain, chain) = start_server();

    let mut config = ClientConfig::new();
    let mut chain = BufReader::new(Cursor::new(chain));
    config.root_store.add_pem_file(&mut chain).unwrap();
    let config = Arc::new(config);

    start_client(addr.clone(), domain, config.clone()).await?;

    Ok(())
}

#[test]
fn pass() -> io::Result<()> {
    executor::block_on(async_pass())
}

async fn async_fail() -> io::Result<()> {
    let (addr, domain, chain) = start_server();

    let mut config = ClientConfig::new();
    let mut chain = BufReader::new(Cursor::new(chain));
    config.root_store.add_pem_file(&mut chain).unwrap();
    let config = Arc::new(config);

    assert_ne!(domain, &"google.com");
    let ret = start_client(addr.clone(), "google.com", config).await;
    assert!(ret.is_err());

    Ok(())
}

#[test]
fn fail() -> io::Result<()> {
    executor::block_on(async_fail())
}
