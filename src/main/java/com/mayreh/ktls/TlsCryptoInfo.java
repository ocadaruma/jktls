package com.mayreh.ktls;

import javax.net.ssl.SSLEngine;

import com.mayreh.ktls.sun.security.ssl.SSLEngineImpl;
import com.mayreh.ktls.sun.security.ssl.SSLWriteCipher;

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
                                  "Unsupported cipher suite: " + engine.getSession().getCipherSuite()));
    }
}
