package com.mayreh.jktls.sun.nio.ch;

import static com.mayreh.jktls.reflection.Utils.classForName;
import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getMethod;

import java.io.FileDescriptor;
import java.lang.reflect.Method;

import lombok.RequiredArgsConstructor;

/**
 * Mirror of `sun.nio.ch.SocketChannelImpl` for exposure
 */
@RequiredArgsConstructor
public class SocketChannelImpl {
    private static final Class<?> clazz = classForName("sun.nio.ch.SocketChannelImpl");
    private static final Method getFD = getMethod(clazz, "getFD");

    private final Object obj;

    public FileDescriptor getFD() {
        return (FileDescriptor) doReflection(() -> getFD.invoke(obj));
    }

    public static boolean isInstance(Object obj) {
        return clazz.isInstance(obj);
    }
}
