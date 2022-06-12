# jktls

[![CI](https://github.com/ocadaruma/jktls/actions/workflows/ci.yml/badge.svg)](https://github.com/ocadaruma/jktls/actions/workflows/ci.yml)

[Kernel TLS](https://docs.kernel.org/networking/tls.html) on Java

## Overview

Kernel TLS (kTLS), which is introduced in Linux 4.13 is a mechanism to offload TLS symmetric crypto processing to the kernel.

In a nutshell, kTLS works like below:

- Establish the TCP connection between client and server as usual
- Begin the TLS handshake as usual
- Once the handshake has finished, pass crypto information from the application to the kernel via `setsockopt`
- After that, kernel offloads symmetric crypto processing for data exchange

`jktls` provides Java API to enable kTLS on sockets.

Currently, tested only on following platforms.

- JDK: 8, 11
- OS: linux
- Architecture: x86_64

## Setup

Add following line to your build.gradle:

```
implementation "com.mayreh.jktls:jktls:LATEST_VERSION"
```

Also, you need to load `tls` kernel module.

```
$ sudo modprobe tls
```
## Usage

As soon as TLS handshake has finished, you need to extract crypto information from `SSLEngine`
and configure the socket options as well.

```java
KTlsSocketChannel ch = KTlsSocketChannel.wrap(socketChannel);
TlsCryptoInfo info = TlsCryptoInfo.from(engine);

// Enable TLS upper layer protocol
ch.setOption(KTlsSocketOptions.TCP_ULP, "tls");

// Enable TLS Data transmission offload
ch.setOption(KTlsSocketOptions.TLS_TX, info);
```

See `KTlsServer` in `testing` module for detailed example.
