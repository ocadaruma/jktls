package com.mayreh.ktls;

import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;

import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.loading.ClassInjector;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.pool.TypePool.Default;

public class DemoMain {
    public static void main(String[] args) throws Exception {
        TypePool typePool = Default.ofSystemLoader();
        Map<TypeDescription, byte[]> types = new HashMap<>();
        types.put(typePool.describe("sun.security.ssl.TlsCryptoInfo").resolve(),
                  ClassFileLocator.ForClassLoader.ofSystemLoader().locate("sun.security.ssl.TlsCryptoInfo").resolve());
        types.put(typePool.describe("com.mayreh.ktls.KTlsSocketChannel").resolve(),
                  ClassFileLocator.ForClassLoader.ofSystemLoader().locate("com.mayreh.ktls.KTlsSocketChannel").resolve());
        types.put(typePool.describe("com.mayreh.ktls.KTlsSocketOptions").resolve(),
                  ClassFileLocator.ForClassLoader.ofSystemLoader().locate("com.mayreh.ktls.KTlsSocketOptions").resolve());
        types.put(typePool.describe("com.mayreh.ktls.KTlsSocketOptions$SockOption").resolve(),
                  ClassFileLocator.ForClassLoader.ofSystemLoader().locate("com.mayreh.ktls.KTlsSocketOptions$SockOption").resolve());
        types.put(typePool.describe("sun.nio.ch.KTlsSocketChannelImpl").resolve(),
                  ClassFileLocator.ForClassLoader.ofSystemLoader().locate("sun.nio.ch.KTlsSocketChannelImpl").resolve());
        ClassInjector.UsingUnsafe.ofBootLoader()
                                 .inject(types);

        SocketChannel ch = SocketChannel.open();

        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9090;
        DemoServer server = new DemoServer(port);

        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.run();
    }
}
