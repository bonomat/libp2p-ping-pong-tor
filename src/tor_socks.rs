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
        async fn do_dial(cfg: Socks5TokioTcpConfig, dest: String) -> Result<TcpStream, io::Error> {
            info!("Connecting via Tor proxy ...");
            let stream = connect_to_socks_proxy(dest, cfg.socks_port)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
            info!("Connection established");
            Ok(stream)
        }
        if let Some(dest) = to_onion_address(addr.clone()) {
            info!("Dialling via Tor to: {}", dest);
            Ok(Box::pin(do_dial(self, dest)))
        } else {
            info!("Dialling via clear net to: {}", addr);
            self.inner.dial(addr)
        }
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        self.inner.address_translation(listen, observed)
    }
}

/// iterates through multi address until we have onion protocol, else return
/// None Tor expects address in form: ADDR.onion:PORT or ADDR:PORT
fn to_onion_address(multi: Multiaddr) -> Option<String> {
    let components = multi.iter();
    for protocol in components {
        match protocol {
            Protocol::Onion(addr, port) => {
                log::warn!("Onion service v2 is being deprecated, consider upgrading to v3");
                return Some(format!(
                    "{}.onion:{}",
                    BASE32.encode(addr.as_ref()).to_lowercase(),
                    port
                ));
            }
            Protocol::Onion3(addr) => {
                return Some(format!(
                    "{}.onion:{}",
                    BASE32.encode(addr.hash()).to_lowercase(),
                    addr.port()
                ));
            }
            _ => {
                // ignore
            }
        }
    }

    // Deal with non-onion addresses
    let protocols = multi.iter().collect::<Vec<_>>();
    let address_string = protocols
        .iter()
        .filter_map(|protocol| match protocol {
            Protocol::Ip4(addr) => Some(format!("{}", addr)),
            Protocol::Ip6(addr) => Some(format!("{}", addr)),
            Protocol::Dns(addr) => Some(format!("{}", addr)),
            Protocol::Dns4(addr) => Some(format!("{}", addr)),
            Protocol::Dns6(addr) => Some(format!("{}", addr)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if address_string.is_empty() {
        return None;
    }

    let mut address_string = address_string
        .get(0)
        .expect("Valid multiaddr consist only out of 1 address")
        .clone();
    let port = protocols
        .iter()
        .filter_map(|protocol| match protocol {
            Protocol::Sctp(port) => Some(format!("{}", port)),
            Protocol::Tcp(port) => Some(format!("{}", port)),
            Protocol::Udp(port) => Some(format!("{}", port)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if port.len() > 1 {
        log::warn!("This should not happen :D ")
    } else if port.len() == 1 {
        address_string.push_str(
            format!(
                ":{}",
                port.get(0)
                    .expect("Already verified the length of the vec.")
            )
            .as_str(),
        )
    }

    Some(address_string.clone())
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

#[cfg(test)]
pub mod test {
    use crate::tor_socks::to_onion_address;

    #[test]
    fn test_tor_address_string() {
        let address =
            "/onion3/oarchy4tamydxcitaki6bc2v4leza6v35iezmu2chg2bap63sv6f2did:1024/p2p/12D3KooWPD4uHN74SHotLN7VCH7Fm8zZgaNVymYcpeF1fpD2guc9"
            ;
        let address_base32 = to_onion_address(address.parse().unwrap())
            .expect("To be a multi address formatted to base32 ");
        assert_eq!(
            address_base32,
            "oarchy4tamydxcitaki6bc2v4leza6v35iezmu2chg2bap63sv6f2did.onion:1024"
        );
    }

    #[test]
    fn tcp_to_address_string_should_be_some() {
        let address = "/ip4/127.0.0.1/tcp/7777";
        let address_string =
            to_onion_address(address.parse().unwrap()).expect("To be a multi address formatted. ");
        assert_eq!(address_string, "127.0.0.1:7777");
    }

    #[test]
    fn udp_to_address_string_should_be_some() {
        let address = "/ip4/127.0.0.1/udp/7777";
        let address_string =
            to_onion_address(address.parse().unwrap()).expect("To be a multi address formatted. ");
        assert_eq!(address_string, "127.0.0.1:7777");
    }

    #[test]
    fn ws_to_address_string_should_be_some() {
        let address = "/ip4/127.0.0.1/tcp/7777/ws";
        let address_string =
            to_onion_address(address.parse().unwrap()).expect("To be a multi address formatted. ");
        assert_eq!(address_string, "127.0.0.1:7777");
    }

    #[test]
    fn scpt_to_address_string_should_be_some() {
        let address = "/ip4/127.0.0.1/sctp/7777";
        let address_string =
            to_onion_address(address.parse().unwrap()).expect("To be a multi address formatted. ");
        assert_eq!(address_string, "127.0.0.1:7777");
    }

    #[test]
    fn dnsaddr_to_address_string_should_be_none() {
        let address = "/dnsaddr/xmr-btc-asb.coblox.tech";
        let address_string = to_onion_address(address.parse().unwrap());
        assert_eq!(address_string, None);
    }
}
