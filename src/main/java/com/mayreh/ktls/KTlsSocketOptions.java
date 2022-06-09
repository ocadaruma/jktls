package com.mayreh.ktls;

import java.net.SocketOption;

import lombok.Value;
import lombok.experimental.Accessors;
import sun.security.ssl.TlsCryptoInfo;

public final class KTlsSocketOptions {
    private KTlsSocketOptions() {}

    public static final SocketOption<String> TCP_ULP =
            new SockOption<>("TCP_ULP", String.class);

    public static final SocketOption<TlsCryptoInfo> TLS_TX =
            new SockOption<>("TLS_TX", TlsCryptoInfo.class);

    @Value
    @Accessors(fluent = true)
    private static class SockOption<T> implements SocketOption<T> {
        String name;
        Class<T> type;
    }
}
