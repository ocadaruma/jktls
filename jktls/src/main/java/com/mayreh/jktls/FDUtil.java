package com.mayreh.jktls;

import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getField;

import java.io.FileDescriptor;
import java.lang.reflect.Field;

public final class FDUtil {
    private static final Field fd = getField(FileDescriptor.class, "fd");

    private FDUtil() {}

    /**
     * Returns the raw fd of {@link FileDescriptor}
     */
    public static int fdVal(FileDescriptor fileDescriptor) {
        return (int) doReflection(() -> fd.get(fileDescriptor));
    }
}
