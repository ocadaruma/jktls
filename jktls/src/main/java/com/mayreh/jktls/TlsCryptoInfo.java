package com.mayreh.jktls;

import javax.net.ssl.SSLEngine;

import com.mayreh.jktls.sun.security.ssl.SSLEngineImpl;
import com.mayreh.jktls.sun.security.ssl.SSLWriteCipher;

import lombok.Value;
import lombok.experimental.Accessors;

@Value
@Accessors(fluent = true)
public class TlsCryptoInfo {
    String protocol;
    String cipherSuite;
    byte[] iv;
    byte[] key;
    byte[] salt;
    byte[] recSeq;

    public static TlsCryptoInfo from(SSLEngine engine) {
        if (!SSLEngineImpl.isInstance(engine)) {
            throw new UnsupportedOperationException("Unsupported SSLEngine implementation");
        }
        SSLWriteCipher writeCipher = new SSLEngineImpl(engine)
                .conContext()
                .outputRecord()
                .writeCipher();
        return writeCipher.context()
                          .map(ctx -> new TlsCryptoInfo(
                                  engine.getSession().getProtocol(),
                                  engine.getSession().getCipherSuite(),
                                  ctx.getIv(),
                                  ctx.getKey(),
                                  ctx.getSalt(),
                                  ctx.getRecSeq()))
                          .orElseThrow(() -> new UnsupportedOperationException(
                                  String.format("Unsupported protocol or cipher suite: protocol=%s, suite=%s",
                                                engine.getSession().getProtocol(),
                                                engine.getSession().getCipherSuite())));
    }
}
