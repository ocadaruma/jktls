package com.mayreh.jktls.reflection;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public final class Utils {
    private Utils() {}

    public static <T> T doReflection(ReflectiveSupplier<T> supplier) {
        try {
            return supplier.get();
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    public static Class<?> classForName(String name) {
        return doReflection(() -> Class.forName(name));
    }

    public static Method getMethod(Class<?> clazz, String name, Class<?>... parameterTypes) {
        return doReflection(() -> {
            Method method = clazz.getDeclaredMethod(name, parameterTypes);
            method.setAccessible(true);
            return method;
        });
    }

    public static Field getField(Class<?> clazz, String name) {
        return doReflection(() -> {
            Field field = clazz.getDeclaredField(name);
            field.setAccessible(true);
            return field;
        });
    }
}
