package com.mayreh.ktls.sun.security.ssl;

import static com.mayreh.ktls.reflection.Utils.classForName;
import static com.mayreh.ktls.reflection.Utils.doReflection;
import static com.mayreh.ktls.reflection.Utils.getField;

import java.lang.reflect.Field;
import java.util.Optional;

import javax.crypto.spec.SecretKeySpec;

import lombok.RequiredArgsConstructor;
import lombok.Value;

/**
 * Mirror of {@link sun.security.ssl.SSLCipher$SSLWriteCipher} for exposure
 */
@RequiredArgsConstructor
public class SSLWriteCipher {
    private static final Class<?> clazz = classForName("sun.security.ssl.SSLCipher$SSLWriteCipher");
    private static final Field authenticator = getField(clazz, "authenticator");

    private final Object obj;

    public Authenticator authenticator() {
        return new Authenticator(doReflection(() -> authenticator.get(obj)));
    }

    public Optional<WriteCipherContext> context() {
        for (WriteCipherType type : WriteCipherType.values()) {
            if (type.isSupported(this)) {
                return Optional.of(type.extractor.extract(this));
            }
        }
        return Optional.empty();
    }

    /**
     * Context information to configure kTLS socket's parameters
     */
    @Value
    public static class WriteCipherContext {
        byte[] iv;
        byte[] key;
        byte[] salt;
        byte[] recSeq;
    }

    @RequiredArgsConstructor
    public enum WriteCipherType {
        T12_GCM(new WriteCipherContextExtractor.T12_GCM()),
        ;
        final WriteCipherContextExtractor extractor;

        boolean isSupported(SSLWriteCipher cipher) {
            return extractor.clazz.isInstance(cipher.obj);
        }
    }

    /**
     * Extract {@link WriteCipherContext} from given cipher object
     */
    abstract static class WriteCipherContextExtractor {
        final Class<?> clazz;
        protected WriteCipherContextExtractor(Class<?> clazz) {
            this.clazz = clazz;
        }

        abstract WriteCipherContext extract(SSLWriteCipher cipher);

        static class T12_GCM extends WriteCipherContextExtractor {
            private static final Class<?> clazz =
                    classForName("sun.security.ssl.SSLCipher$T12GcmWriteCipherGenerator$GcmWriteCipher");
            private static final Field key = getField(clazz, "key");
            private static final Field fixedIv = getField(clazz, "fixedIv");

            T12_GCM() {
                super(clazz);
            }

            @Override
            WriteCipherContext extract(SSLWriteCipher cipher) {
                SecretKeySpec keySpec = (SecretKeySpec) doReflection(() -> key.get(cipher.obj));
                byte[] salt = (byte[]) doReflection(() -> fixedIv.get(cipher.obj));
                byte[] seq = cipher.authenticator().sequenceNumber();

                return new WriteCipherContext(seq, keySpec.getEncoded(), salt, seq);
            }
        }
    }
}
