package com.mayreh.jktls.demo;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.mayreh.jktls.testing.KTlsServer;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DemoMain {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9090;

        Path resourceDir = Files.createTempDirectory("resource");
        Path file = resourceDir.resolve("lorem-ipsum.txt");
        try (InputStream is = DemoMain.class.getClassLoader().getResourceAsStream("lorem-ipsum.txt")) {
            Files.copy(is, file);
        }

        FileChannel fileChannel = FileChannel.open(file);
        KTlsServer tlsServer = new KTlsServer(port);
        tlsServer.setHandler((channel, m) -> {
            String message = new String(m, StandardCharsets.UTF_8).trim();
            log.info("Received: {}", message);
            if ("lorem-ipsum".equals(message)) {
                fileChannel.position(0);
                channel.transferFrom(fileChannel, 0, fileChannel.size());
            } else {
                ByteBuffer buf = ByteBuffer.allocate(m.length);
                buf.put(m);
                buf.flip();
                channel.write(buf);
            }
        });
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            tlsServer.close();
            try {
                fileChannel.close();
                Utils.delete(resourceDir);
            } catch (IOException e) {
                log.error("Failed to delete directory: {}", resourceDir);
                throw new UncheckedIOException(e);
            }
        }));
        tlsServer.start();
    }
}
