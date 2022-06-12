package com.mayreh.jktls.sun.security.ssl;

import static com.mayreh.jktls.reflection.Utils.classForName;
import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getField;

import java.lang.reflect.Field;

import lombok.RequiredArgsConstructor;

/**
 * Mirror of `sun.security.ssl.TransportContext` for exposure
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
