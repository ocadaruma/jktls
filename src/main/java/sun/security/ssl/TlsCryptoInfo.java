package sun.security.ssl;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLEngine;

import lombok.Value;
import lombok.experimental.Accessors;
import sun.security.ssl.SSLCipher.SSLWriteCipher;

@Value
@Accessors(fluent = true)
public class TlsCryptoInfo {
    private static final Class<?> T12Gcm_GcmWriteCipherClazz;
    private static final Class<?> SSLEngineImplClazz;
    private static final Class<?> SSLWriteCipherClazz;
    private static final Class<?> TransportContextClazz;
    private static final Class<?> OutputRecordClazz;
    private static final Class<?> AuthenticatorClazz;
    static {
        try {
            T12Gcm_GcmWriteCipherClazz = Class.forName("sun.security.ssl.SSLCipher$T12GcmWriteCipherGenerator$GcmWriteCipher");
            SSLEngineImplClazz = Class.forName("sun.security.ssl.SSLEngineImpl");
            SSLWriteCipherClazz = Class.forName("sun.security.ssl.SSLCipher$SSLWriteCipher");
            TransportContextClazz = Class.forName("sun.security.ssl.TransportContext");
            OutputRecordClazz = Class.forName("sun.security.ssl.OutputRecord");
            AuthenticatorClazz = Class.forName("sun.security.ssl.Authenticator");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    String protocol;
    String cipherSuite;
    byte[] iv;
    byte[] key;
    byte[] salt;
    byte[] recSeq;

    public static TlsCryptoInfo from(SSLEngine engine) {
        if (!(engine instanceof SSLEngineImpl)) {
            throw new UnsupportedOperationException("Unsupported SSLEngine implementation");
        }
        SSLWriteCipher writeCipher = ((SSLEngineImpl) engine).conContext.outputRecord.writeCipher;

        if (T12Gcm_GcmWriteCipherClazz.isInstance(writeCipher)) {
            SecretKeySpec keySpec = (SecretKeySpec) getField(T12Gcm_GcmWriteCipherClazz, writeCipher, "key");
            byte[] fixedIv = (byte[]) getField(T12Gcm_GcmWriteCipherClazz, writeCipher, "fixedIv");
            byte[] seq = writeCipher.authenticator.sequenceNumber();

            return new TlsCryptoInfo(
                    engine.getSession().getProtocol(),
                    engine.getSession().getCipherSuite(),
                    seq,
                    keySpec.getEncoded(),
                    fixedIv,
                    seq);
        }

        throw new UnsupportedOperationException("Unsupported cipher suite");
    }

    private static Object getField(Class<?> clazz, Object obj, String fieldName) {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
