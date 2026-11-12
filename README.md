# PWShare

A TLS 1.2 server written from scratch in Rust. The handshake, key exchange, signing and record-layer encryption are implemented directly on top of big-integer arithmetic rather than a TLS library.

> **Warning:** This is an educational project. It has not been audited and must not be used to protect real data.

## Features

- **TLS 1.2 handshake** (server side)
- **ECDHE key exchange** with NIST and Weierstrass curves (for example X25519)
- **RSA** for server authentication (signatures) and static RSA key exchange
- **AES-GCM** and **AES-CBC + HMAC** (SHA-1 / SHA-256) record protection, with SHA-256 and SHA-384 PRFs
- **Own elliptic-curve arithmetic** built on [`crypto-bigint`](https://crates.io/crates/crypto-bigint) (`BoxedUint`)
- **Constant-time considerations** for secret-dependent code, with a custom constant-time testing framework inspired by the [dudect](https://eprint.iacr.org/2016/1123) paper

## Supported cipher suites

| Suite | Key exchange | Cipher | MAC / AEAD | PRF |
|-------|--------------|--------|------------|-----|
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | ECDHE (RSA-signed) | AES-128-GCM | AEAD | SHA-256 |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` | ECDHE (RSA-signed) | AES-128-CBC | HMAC-SHA256 | SHA-256 |
| `TLS_RSA_WITH_AES_128_GCM_SHA256` | RSA | AES-128-GCM | AEAD | SHA-256 |
| `TLS_RSA_WITH_AES_256_GCM_SHA384` | RSA | AES-256-GCM | AEAD | SHA-384 |
| `TLS_RSA_WITH_AES_128_CBC_SHA256` | RSA | AES-128-CBC | HMAC-SHA256 | SHA-256 |
| `TLS_RSA_WITH_AES_256_CBC_SHA256` | RSA | AES-256-CBC | HMAC-SHA256 | SHA-256 |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | RSA | AES-128-CBC | HMAC-SHA1 | SHA-256 |
| `TLS_RSA_WITH_AES_256_CBC_SHA` | RSA | AES-256-CBC | HMAC-SHA1 | SHA-256 |

Suites using static RSA key exchange provide no forward secrecy; prefer the ECDHE suites.

## Getting started

- Place RSA key at backend/key.pem
- Place certificate at backend/cert.pem

### Requirements

- Rust (stable) and Cargo

### Build

```sh
git clone https://github.com/Talonflame/PWShare
cd PWShare
cargo build --release
```

### Run

```sh
cargo run --release
```

Connect via

```sh
openssl s_client -connect 127.0.0.1:4981 -tls1_2 -servername localhost -state -cipher ECDHE-RSA-AES128-GCM-SHA256
```

<!-- TODO: arguments, port, certificate/key configuration -->

## Project layout

```
Split into frontend and backend. Frontend project was half given up on as I wanted to focus on technical stuff and have lost interest in a GUI.
backend is hence the interesting directory.
```

## Limitations

- TLS 1.2 only (no TLS 1.3)
- Not audited; side-channel resistance is best-effort
- DON'T USE OUTSIDE OF EDUCTION/TESTING: There is for sure a bug of some kind.
