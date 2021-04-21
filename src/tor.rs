use anyhow::{anyhow, bail, Result};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::TcpStream;
use torut::control::{AsyncEvent, AuthenticatedConn, ConnError, UnauthenticatedConn};
use torut::onion::TorSecretKeyV3;

#[derive(Debug, Clone, Copy)]
pub struct UnauthenticatedConnection {
    tor_proxy_address: SocketAddrV4,
    tor_control_port_address: SocketAddr,
}

impl Default for UnauthenticatedConnection {
    fn default() -> Self {
        Self {
            tor_proxy_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9050),
            tor_control_port_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9051)),
        }
    }
}

impl UnauthenticatedConnection {
    pub fn with_ports(proxy_port: u16, control_port: u16) -> Self {
        Self {
            tor_proxy_address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, proxy_port),
            tor_control_port_address: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                control_port,
            )),
        }
    }

    /// checks if tor is running
    async fn assert_tor_running(&self) -> Result<()> {
        // Make sure you are running tor and this is your socks port
        let proxy = reqwest::Proxy::all(format!("socks5h://{}", self.tor_proxy_address).as_str())
            .map_err(|_| anyhow!("tor proxy should be there"))?;
        let client = reqwest::Client::builder().proxy(proxy).build()?;

        let res = client.get("https://check.torproject.org").send().await?;
        let text = res.text().await?;

        if !text.contains("Congratulations. This browser is configured to use Tor.") {
            log::debug!("Found text: \n{}", text);
            bail!("Tor is currently not running")
        }

        Ok(())
    }

    async fn init_unauthenticated_connection(&self) -> Result<UnauthenticatedConn<TcpStream>> {
        // Connect to local tor service via control port
        let sock = TcpStream::connect(self.tor_control_port_address).await?;
        let uc = UnauthenticatedConn::new(sock);
        Ok(uc)
    }

    /// Create a new authenticated connection to your local Tor service
    pub async fn into_authenticated_connection(self) -> Result<AuthenticatedConnection> {
        self.assert_tor_running().await?;

        let mut uc = self
            .init_unauthenticated_connection()
            .await
            .map_err(|_| anyhow!("Tor instance not running."))?;

        let tor_info = uc
            .load_protocol_info()
            .await
            .map_err(|_| anyhow!("Failed to load protocol info from Tor."))?;

        let tor_auth_data = tor_info
            .make_auth_data()?
            .ok_or_else(|| anyhow!("Failed to make auth data."))?;

        // Get an authenticated connection to the Tor via the Tor Controller protocol.
        uc.authenticate(&tor_auth_data)
            .await
            .map_err(|_| anyhow!("Failed to authenticate with Tor"))?;

        Ok(AuthenticatedConnection {
            authenticated_connection: uc.into_authenticated().await,
        })
    }
}

type Handler = fn(AsyncEvent<'_>) -> Box<dyn Future<Output = Result<(), ConnError>> + Unpin>;

#[allow(missing_debug_implementations)]
pub struct AuthenticatedConnection {
    authenticated_connection: AuthenticatedConn<TcpStream, Handler>,
}

impl AuthenticatedConnection {
    /// Add an ephemeral tor service on localhost with the provided key
    pub async fn add_service(
        &mut self,
        service_port: u16,
        onion_port: u16,
        tor_key: &TorSecretKeyV3,
    ) -> Result<()> {
        self.authenticated_connection
            .add_onion_v3(
                tor_key,
                false,
                false,
                false,
                None,
                &mut [(
                    onion_port,
                    SocketAddr::new(IpAddr::from(Ipv4Addr::new(127, 0, 0, 1)), service_port),
                )]
                .iter(),
            )
            .await
            .map_err(|e| anyhow!("Could not add onion service.: {:#?}", e))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct TorConf {
    pub control_port: u16,
    pub proxy_port: u16,
    pub service_port: u16,
}

impl Default for TorConf {
    fn default() -> Self {
        Self {
            control_port: 9051,
            proxy_port: 9050,
            service_port: 9090,
        }
    }
}

impl TorConf {
    pub fn with_control_port(self, control_port: u16) -> Self {
        Self {
            control_port,
            ..self
        }
    }

    pub fn with_proxy_port(self, proxy_port: u16) -> Self {
        Self { proxy_port, ..self }
    }

    pub fn with_service_port(self, service_port: u16) -> Self {
        Self {
            service_port,
            ..self
        }
    }
}
