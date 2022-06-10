package com.mayreh.ktls.reflection;

@FunctionalInterface
public interface ReflectiveSupplier<T> {
    T get() throws ReflectiveOperationException;
}
