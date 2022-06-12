package com.mayreh.jktls.sun.nio.ch;

import static com.mayreh.jktls.reflection.Utils.classForName;
import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getField;

import java.io.FileDescriptor;
import java.lang.reflect.Field;

import lombok.RequiredArgsConstructor;

/**
 * Mirror of {@link sun.nio.ch.FileChannelImpl} for exposure
 */
@RequiredArgsConstructor
public class FileChannelImpl {
    private static final Class<?> clazz = classForName("sun.nio.ch.FileChannelImpl");
    private static final Field fd = getField(clazz, "fd");

    private final Object obj;

    public FileDescriptor fd() {
        return (FileDescriptor) doReflection(() -> fd.get(obj));
    }

    public static boolean isInstance(Object obj) {
        return clazz.isInstance(obj);
    }
}
