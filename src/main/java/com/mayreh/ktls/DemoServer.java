package com.mayreh.ktls;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import sun.security.ssl.TlsCryptoInfo;

/**
 * A SSL server that returns:
 * - if a string "lorem-ipsum.txt" is received => lorem-ipsum.txt's content
 * - otherwise => echo received string
 */
@Slf4j
public class DemoServer {
    private final Path resourceDir;
    private final FileChannel loremIpsum;
    private final Selector selector;
    private final SSLContext context;
    private final ExecutorService taskExecutor;
    private volatile boolean running;

    public DemoServer(int port) throws IOException {
        taskExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setName("ssl-task-executor");
            return t;
        });
        try {
            context = SSLContext.getInstance("TLSv1.2");
            context.init(createKeyManagers(), null, new SecureRandom());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        resourceDir = Files.createTempDirectory("resource");
        Path file = resourceDir.resolve("lorem-ipsum.txt");
        try {
            Files.copy(DemoServer.class.getClassLoader().getResourceAsStream("lorem-ipsum.txt"), file);
            loremIpsum = FileChannel.open(file, StandardOpenOption.READ);
        } catch (IOException e) {
            Utils.delete(resourceDir);
            throw e;
        }

        try {
            selector = Selector.open();
            ServerSocketChannel socketChannel = ServerSocketChannel.open();
            socketChannel.configureBlocking(false);
            socketChannel.socket().bind(new InetSocketAddress("0.0.0.0", port));
            socketChannel.register(selector, SelectionKey.OP_ACCEPT);
            Socket c;
        } catch (IOException e) {
            Utils.delete(resourceDir);
            throw e;
        }

        running = true;
    }

    public void run() {
        try {
            while (running) {
                selector.select(500L);
                Iterator<SelectionKey> selectedKeys = selector.selectedKeys().iterator();
                while (selectedKeys.hasNext()) {
                    SelectionKey key = selectedKeys.next();
                    selectedKeys.remove();

                    if (!key.isValid()) {
                        continue;
                    }
                    if (key.isAcceptable()) {
                        accept(key);
                    } else if (key.isReadable()) {
                        read(key);
                    }
                }
            }
        } catch (IOException e) {
            log.error("Exception occurred", e);
        }

        try {
            Utils.delete(resourceDir);
        } catch (IOException e) {
            log.error("Failed to cleanup directory", e);
        }
    }

    private void accept(SelectionKey key) throws IOException {
        SocketChannel socketChannel = ((ServerSocketChannel) key.channel()).accept();
        socketChannel.configureBlocking(false);
        SSLEngine engine = context.createSSLEngine();
        engine.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_GCM_SHA256"});

        Connection connection = doHandshake(socketChannel, engine);
        if (connection != null) {
            TlsCryptoInfo cryptoInfo = TlsCryptoInfo.from(engine);
            connection.channel.setOption(KTlsSocketOptions.TCP_ULP, "tls");
            connection.channel.setOption(KTlsSocketOptions.TLS_TX, cryptoInfo);
            socketChannel.register(selector, SelectionKey.OP_READ, connection);
        } else {
            log.warn("Closing channel due to handshake failure");
            socketChannel.close();
        }
    }

    private void read(SelectionKey key) throws IOException {
        Connection connection = (Connection) key.attachment();

        connection.peerNetData.clear();
        int read = connection.channel.read(connection.peerNetData);
        if (read > 0) {
            connection.peerNetData.flip();
            while (connection.peerNetData.hasRemaining()) {
                connection.peerAppData.clear();
                SSLEngineResult engineResult = connection.engine.unwrap(
                        connection.peerNetData,
                        connection.peerAppData);
                switch (engineResult.getStatus()) {
                    case BUFFER_OVERFLOW:
                        connection.peerAppData = grow(
                                connection.peerAppData,
                                connection.engine.getSession().getApplicationBufferSize());
                        break;
                    case BUFFER_UNDERFLOW:
                        connection.peerNetData = handlePacketBufferUnderflow(
                                connection.peerNetData,
                                connection.engine.getSession().getPacketBufferSize());
                        break;
                    case CLOSED:
                        log.warn("Closed");
                        break;
                    case OK:
                        connection.peerAppData.flip();
                        break;
                }
            }

            byte[] buf = new byte[connection.peerAppData.remaining()];
            connection.peerAppData.get(buf);
            String message = new String(buf, StandardCharsets.UTF_8);

            connection.appData.clear();
            if ("lorem-ipsum.txt".equals(message.trim())) {
                log.info("Received lorem-ipsum");
                loremIpsum.position(0);
                connection.channel.transferFrom(loremIpsum, 0, loremIpsum.size());
            } else {
                connection.appData.put(message.getBytes(StandardCharsets.UTF_8));
                connection.appData.flip();
                connection.channel.write(connection.appData);
            }
//            connection.appData.flip();
//            while (connection.appData.hasRemaining()) {
//                connection.netData.clear();
//                SSLEngineResult engineResult = connection.engine.wrap(connection.appData, connection.netData);
//                switch (engineResult.getStatus()) {
//                    case BUFFER_OVERFLOW:
//                        connection.netData = grow(connection.netData,
//                                                  connection.engine.getSession().getPacketBufferSize());
//                        break;
//                    case BUFFER_UNDERFLOW:
//                        throw new IllegalStateException("Should not happen");
//                    case CLOSED:
//                        log.warn("Closed");
//                        break;
//                    case OK:
//                        connection.netData.flip();
//                        while (connection.netData.hasRemaining()) {
//                            connection.channel.write(connection.netData);
//                        }
//                        break;
//                }
//            }
        }
    }

    private Connection doHandshake(SocketChannel socketChannel, SSLEngine engine) throws IOException {
        int appBufferSize = engine.getSession().getApplicationBufferSize();
        int packetBufferSize = engine.getSession().getPacketBufferSize();

        ByteBuffer appData = ByteBuffer.allocate(appBufferSize);
        ByteBuffer netData = ByteBuffer.allocate(packetBufferSize);
        ByteBuffer peerAppData = ByteBuffer.allocate(appBufferSize);
        ByteBuffer peerNetData = ByteBuffer.allocate(packetBufferSize);

        engine.setUseClientMode(false);
        engine.beginHandshake();

        SSLEngineResult engineResult;
        HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
        while (handshakeStatus != HandshakeStatus.FINISHED &&
               handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {
            switch (handshakeStatus) {
                case NEED_UNWRAP:
                    if (socketChannel.read(peerNetData) < 0) {
                        if (engine.isInboundDone() && engine.isOutboundDone()) {
                            return null;
                        }
                        engine.closeInbound();
                        engine.closeOutbound();
                        handshakeStatus = engine.getHandshakeStatus();
                        break;
                    }
                    peerNetData.flip();
                    engineResult = engine.unwrap(peerNetData, peerAppData);
                    peerNetData.compact();
                    handshakeStatus = engine.getHandshakeStatus();
                    switch (engineResult.getStatus()) {
                        case BUFFER_OVERFLOW:
                            peerAppData = grow(peerAppData, engine.getSession().getApplicationBufferSize());
                            break;
                        case BUFFER_UNDERFLOW:
                            peerNetData = handlePacketBufferUnderflow(
                                    peerNetData,
                                    engine.getSession().getApplicationBufferSize());
                            break;
                        case CLOSED:
                            if (engine.isOutboundDone()) {
                                return null;
                            }
                            engine.closeOutbound();
                            handshakeStatus = engine.getHandshakeStatus();
                            break;
                        case OK:
                            break;
                    }
                    break;
                case NEED_WRAP:
                    netData.clear();
                    engineResult = engine.wrap(appData, netData);
                    handshakeStatus = engineResult.getHandshakeStatus();
                    switch (engineResult.getStatus()) {
                        case BUFFER_OVERFLOW:
                            netData = grow(netData, engine.getSession().getPacketBufferSize());
                            break;
                        case BUFFER_UNDERFLOW:
                            throw new IllegalStateException("Should not happen");
                        case CLOSED:
                            netData.flip();
                            while (netData.hasRemaining()) {
                                socketChannel.write(netData);
                            }
                            peerNetData.clear();
                            break;
                        case OK:
                            netData.flip();
                            while (netData.hasRemaining()) {
                                socketChannel.write(netData);
                            }
                            break;
                    }
                    break;
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        taskExecutor.execute(task);
                    }
                    handshakeStatus = engine.getHandshakeStatus();
                    break;
                default:
                    throw new IllegalStateException("Bug. Got status: " + handshakeStatus);
            }
        }

        return new Connection(
                KTlsSocketChannel.wrap(socketChannel),
                engine,
                appData,
                netData,
                peerAppData,
                peerNetData);
    }

    private static ByteBuffer grow(ByteBuffer buffer, int proposedCapacity) {
        if (proposedCapacity > buffer.capacity()) {
            return ByteBuffer.allocate(proposedCapacity);
        }
        return ByteBuffer.allocate(buffer.capacity() * 2);
    }

    private static ByteBuffer handlePacketBufferUnderflow(
            ByteBuffer packetBuffer, int proposedCapacity) {
        if (proposedCapacity < packetBuffer.limit()) {
            return packetBuffer;
        }
        ByteBuffer newBuffer = grow(packetBuffer, proposedCapacity);
        packetBuffer.flip();
        newBuffer.put(packetBuffer);
        return newBuffer;
    }

    private static KeyManager[] createKeyManagers() {
        char[] pass = "password".toCharArray();
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(DemoServer.class.getClassLoader().getResourceAsStream("server.keystore.p12"),
                          pass);
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keyStore, pass);
            return factory.getKeyManagers();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() {
        running = false;
    }

    @AllArgsConstructor
    static class Connection {
        final KTlsSocketChannel channel;
        final SSLEngine engine;
        ByteBuffer appData;
        ByteBuffer netData;
        ByteBuffer peerAppData;
        ByteBuffer peerNetData;
    }
}
