package com.mayreh.ktls;

import java.nio.channels.SocketChannel;

public class DemoMain {
    public static void main(String[] args) throws Exception {
        SocketChannel ch = SocketChannel.open();

        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9090;
        DemoServer server = new DemoServer(port);

        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        server.run();
    }
}
