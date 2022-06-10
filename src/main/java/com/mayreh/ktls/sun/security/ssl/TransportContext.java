package com.mayreh.ktls.sun.security.ssl;

import static com.mayreh.ktls.reflection.Utils.classForName;
import static com.mayreh.ktls.reflection.Utils.doReflection;
import static com.mayreh.ktls.reflection.Utils.getField;

import java.lang.reflect.Field;

import lombok.RequiredArgsConstructor;

/**
 * Mirror of {@link sun.security.ssl.TransportContext} for exposure
 */
@RequiredArgsConstructor
public class TransportContext {
    private static final Class<?> clazz = classForName("sun.security.ssl.TransportContext");
    private static final Field outputRecord = getField(clazz, "outputRecord");

    private final Object obj;

    public OutputRecord outputRecord() {
        return new OutputRecord(doReflection(() -> outputRecord.get(obj)));
    }
}
