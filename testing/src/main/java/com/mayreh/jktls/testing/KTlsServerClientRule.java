package com.mayreh.jktls.testing;

import org.junit.rules.ExternalResource;

import com.mayreh.jktls.testing.KTlsServer.Handler;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class KTlsServerClientRule extends ExternalResource {
    private KTlsServer server;
    @Getter
    private TlsClient client;
    private final String[] enabledCipherSuites;

    public KTlsServerClientRule() {
        this(null);
    }

    public int port() {
        return server.getPort();
    }

    public void setHandler(Handler handler) {
        server.setHandler(handler);
    }

    @Override
    protected void before() throws Throwable {
        super.before();
        server = new KTlsServer(0, enabledCipherSuites);
        server.start();
        client = new TlsClient("localhost", server.getPort());
    }

    @Override
    protected void after() {
        server.close();
        client.close();
        super.after();
    }
}
