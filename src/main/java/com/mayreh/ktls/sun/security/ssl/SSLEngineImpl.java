package com.mayreh.ktls.sun.security.ssl;

import static com.mayreh.ktls.reflection.Utils.classForName;
import static com.mayreh.ktls.reflection.Utils.doReflection;
import static com.mayreh.ktls.reflection.Utils.getField;

import java.lang.reflect.Field;

import lombok.RequiredArgsConstructor;

/**
 * Mirror of {@link sun.security.ssl.SSLEngineImpl} for exposure
 */
@RequiredArgsConstructor
public class SSLEngineImpl {
    private static final Class<?> clazz = classForName("sun.security.ssl.SSLEngineImpl");
    private static final Field conContext = getField(clazz, "conContext");
    private final Object obj;

    public TransportContext conContext() {
        return new TransportContext(doReflection(() -> conContext.get(obj)));
    }

    public static boolean isInstance(Object obj) {
        return clazz.isInstance(obj);
    }
}
