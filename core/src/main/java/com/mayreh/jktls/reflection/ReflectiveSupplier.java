package com.mayreh.jktls.reflection;

@FunctionalInterface
public interface ReflectiveSupplier<T> {
    T get() throws ReflectiveOperationException;
}
