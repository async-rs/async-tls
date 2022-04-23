<h1 align="center">async-tls</h1>
<div align="center">
 <strong>
   Async TLS/SSL streams using <a href="https://github.com/ctz/rustls">Rustls</a>.
 </strong>
</div>

<br />

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/async-tls">
    <img src="https://img.shields.io/crates/v/async-tls.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/async-tls">
    <img src="https://img.shields.io/crates/d/async-tls.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- docs.rs docs -->
  <a href="https://docs.rs/async-tls">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square"
      alt="docs.rs docs" />
  </a>

  <a href="https://discord.gg/JvZeVNe">
    <img src="https://img.shields.io/discord/598880689856970762.svg?logo=discord&style=flat-square"
      alt="chat" />
  </a>
</div>

<div align="center">
  <h3>
    <a href="https://docs.rs/async-tls">
      API Docs
    </a>
    <span> | </span>
    <a href="https://github.com/async-rs/async-tls/releases">
      Releases
    </a>
    <span> | </span>
    <a href="https://async.rs/contribute">
      Contributing
    </a>
  </h3>
</div>

<br/>

# Maintenance Notice

I, [Florian Gilcher](https://github.com/skade), am currently the main maintainer of `async-tls`. Due to general workload, I would like the hand the maintenance off to someone else carrying the general vision of `async-tls`:

* Runtime-independence
* Backend-independence (currently not implemented)
* Focused on _use-case based_ configuration rather then exposing all configurations

I expect applicants for maintainership to present a committment of at least 4h of time/week initially, so I recommend getting corporate backing first. The number isn't strict, but I want the process to improve maintenance. I'm happy with a group of multiple maintainers.

I commit to weekly feedback of 30 minutes for the first 2 months - more in the initial days of handover.

If interested, please reach out to me at [through email](mailto:flo@andersground.net).

# Features

`async-tls` can be used both in server and client programs. To save compilation times, you
can switch off parts of this for faster compile times.

To only use async-tls on a client, deactivate default features and use the "client" feature.

```toml
[dependencies.async-tls]
version = "0.8"
default-features = false
features = ["client"]
```

To only use async-tls on for the server side, deactivate default features and use the "server" feature.

```toml
[dependencies.async-tls]
version = "0.8"
default-features = false
features = ["server"]
```

### Simple Client

```rust
use async_tls::TlsConnector;
use async_std::net::TcpStream;

// ...

let tcp_stream = TcpStream::connect("rust-lang.org:443").await?;
let connector = TlsConnector::default();
let mut tls_stream = connector.connect("www.rust-lang.org", tcp_stream).await?;

// ...
```

### Client Example Program

See [examples/client](examples/client/src/main.rs). You can run it with:

```sh
cd examples/client
cargo run -- hsts.badssl.com
```

### Server Example Program

See [examples/server](examples/server/src/main.rs). You can run it with:

```sh
cd examples/server
cargo run -- 127.0.0.1:8080 --cert ../../tests/end.cert --key ../../tests/end.rsa
```

and point the client at it with:

```sh
cd examples/client
cargo run -- 127.0.0.1 --port 8080 --domain localhost --cafile ../../tests/end.chain
```

**NOTE**: Don't ever use those certificate files anywhere but for testing!

## Safety

This crate uses ``#![deny(unsafe_code)]`` to ensure everything is implemented in
100% Safe Rust.

### License & Origin

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

This started as a fork of [tokio-rustls](https://github.com/quininer/tokio-rustls).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in async-tls by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
