use data_encoding::BASE32;
use futures::{future::Ready, prelude::*};
use libp2p::core::{
    multiaddr::{Multiaddr, Protocol},
    transport::TransportError,
    Transport,
};
use libp2p::tcp::tokio::{Tcp, TcpStream};
use libp2p::tcp::{GenTcpConfig, TcpListenStream, TokioTcpConfig};
use log::{debug, info};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
};
use tokio_socks::{tcp::Socks5Stream, IntoTargetAddr};

/// Default port for the Tor SOCKS5 proxy.
const DEFAULT_SOCKS_PORT: u16 = 9050;

/// Represents the configuration for a TCP/IP transport capability for libp2p.
#[derive(Clone)]
pub struct Socks5TokioTcpConfig {
    inner: GenTcpConfig<Tcp>,
    /// Tor SOCKS5 proxy port number.
    socks_port: u16,
}

impl Socks5TokioTcpConfig {
    pub fn new(socks_port: u16) -> Self {
        let tcp = TokioTcpConfig::new().nodelay(true);
        Self {
            inner: tcp,
            socks_port,
        }
    }
}

impl Default for Socks5TokioTcpConfig {
    /// Creates a new configuration object for TCP/IP using the default Tor
    /// SOCKS5 port - 9050.
    fn default() -> Self {
        let inner = TokioTcpConfig::new().nodelay(true);
        Self {
            inner,
            socks_port: DEFAULT_SOCKS_PORT,
        }
    }
}

impl Transport for Socks5TokioTcpConfig {
    type Output = TcpStream;
    type Error = io::Error;
    type Listener = TcpListenStream<Tcp>;
    type ListenerUpgrade = Ready<Result<Self::Output, Self::Error>>;
    type Dial = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn listen_on(self, addr: Multiaddr) -> Result<Self::Listener, TransportError<Self::Error>> {
        debug!("Trying to listen on: {}", addr);
        self.inner.listen_on(addr)
    }

    fn dial(self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let dest =
            tor_address_string(addr.clone()).ok_or(TransportError::MultiaddrNotSupported(addr))?;
        debug!("Tor destination address: {}", dest);

        async fn do_dial(cfg: Socks5TokioTcpConfig, dest: String) -> Result<TcpStream, io::Error> {
            info!("Connecting to Tor proxy ...");
            let stream = connect_to_socks_proxy(dest, cfg.socks_port)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
            info!("Connection established");

            Ok(stream)
        }

        Ok(Box::pin(do_dial(self, dest)))
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        self.inner.address_translation(listen, observed)
    }
}

// Tor expects address in form: ADDR.onion:PORT
fn tor_address_string(mut multi: Multiaddr) -> Option<String> {
    let (encoded, port) = match multi.pop()? {
        Protocol::Onion(addr, port) => {
            log::warn!("Onion service v2 is being deprecated, consider upgrading to v3");
            (BASE32.encode(addr.as_ref()), port)
        }
        Protocol::Onion3(addr) => (BASE32.encode(addr.hash()), addr.port()),
        _ => return None,
    };
    let addr = format!("{}.onion:{}", encoded.to_lowercase(), port);
    Some(addr)
}

/// Connect to the SOCKS5 proxy socket.
async fn connect_to_socks_proxy<'a>(
    dest: impl IntoTargetAddr<'a>,
    port: u16,
) -> Result<TcpStream, tokio_socks::Error> {
    let sock = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let stream = Socks5Stream::connect(sock, dest).await?;
    Ok(TcpStream(stream.into_inner()))
}
