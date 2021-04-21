# Ping-Pong using rust-libp2p TCP/IP via a Tor proxy

This is a small show case for a server/client ping-pong chat using libp2p via Tor using Tor's socks5 proxy.

## Usage

See `src/main.rs` for a complete running example using Tor.

You should configure your Tor onion service to redirect traffic to some local port.

Example Tor configuration (e.g. in `/usr/local/etc/tor/torrc`)

```
HiddenServiceDir /usr/local/etc/tor/hidden_service
HiddenServicePort 7776 127.0.0.1:7777
```

Check the hidden service data directory for a file called `hostname`,
this contains the onion address for the service.

Run server first, it will print the `ONION_ADDRESS` it is listening on

```bash
RUST_LOG=info cargo run
...
[2021-04-21T04:28:35Z INFO  libp2p_ping_pong_tor] /onion3/db2v7w2c5fzcuhcg2hoqvcppn7djzrohvgdwqgavvave5t6d6gf5ddid:7776
```

Use the `ONION_ADDRESS` and start the dialer:

```bash
cargo run -- --dialer --onion=ONION_ADDRESS
```
