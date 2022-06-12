package com.mayreh.jktls.testing;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

import com.mayreh.jktls.KTlsSocketChannel;
import com.mayreh.jktls.KTlsSocketOptions;
import com.mayreh.jktls.TlsCryptoInfo;

import lombok.AllArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * Reference implementation of TCP server that uses kernel TLS for data encryption.
 * The code is highly inspired by alkarn's <a href="https://github.com/alkarn/sslengine.example">sslengine.example</a>
 */
@Slf4j
public class KTlsServer extends Thread implements AutoCloseable {
    @FunctionalInterface
    public interface Handler {
        void handleIncomingMessage(KTlsSocketChannel channel, byte[] message) throws IOException;
    }

    private final String[] enabledCipherSuites;
    private final ExecutorService taskExecutor;
    private final SSLContext sslContext;
    private final Selector selector;
    private final ServerSocketChannel serverSocketChannel;

    @Setter
    private volatile Handler handler;

    private volatile boolean running;

    public KTlsServer(int port) {
        this(port, null);
    }

    public KTlsServer(int port, String[] enabledCipherSuites) {
        this.enabledCipherSuites = enabledCipherSuites;
        taskExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setName("ssl-task-executor");
            return t;
        });

        try {
            sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(createKeyManagers(), null, new SecureRandom());

            selector = Selector.open();
            serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.configureBlocking(false);
            serverSocketChannel.socket().bind(new InetSocketAddress("0.0.0.0", port));
            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void run() {
        running = true;

        while (running) {
            try {
                selector.select(100L);
                Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();

                    if (!key.isValid()) {
                        continue;
                    }
                    if (key.isAcceptable()) {
                        accept();
                    } else if (key.isReadable()) {
                        read(key);
                    }
                }
            } catch (IOException e) {
                log.error("Exception occurred", e);
            }
        }
    }

    private void accept() throws IOException {
        SocketChannel socketChannel = serverSocketChannel.accept();
        socketChannel.configureBlocking(false);
        SSLEngine engine = sslContext.createSSLEngine();
        if (enabledCipherSuites != null) {
            engine.setEnabledCipherSuites(enabledCipherSuites);
        }

        Connection connection = doHandshake(socketChannel, engine);
        if (connection != null) {
            connection.channel.setOption(KTlsSocketOptions.TCP_ULP, "tls");
            connection.channel.setOption(KTlsSocketOptions.TLS_TX, TlsCryptoInfo.from(engine));
            socketChannel.register(selector, SelectionKey.OP_READ, connection);
        } else {
            log.warn("Closing the channel due to handshake failure");
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

            byte[] message = new byte[connection.peerAppData.remaining()];
            connection.peerAppData.get(message);

            Handler currentHandler = handler;
            if (currentHandler != null) {
                currentHandler.handleIncomingMessage(connection.channel, message);
            }
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

    @Override
    public void close() {
        running = false;
        try {
            join();
            serverSocketChannel.close();
            selector.close();
        } catch (InterruptedException e) {
            interrupt();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static KeyManager[] createKeyManagers() {
        char[] pass = "password".toCharArray();
        try(InputStream keyStream = KTlsServer.class.getClassLoader().getResourceAsStream("server.keystore.p12")) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(keyStream, pass);
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keyStore, pass);

            return factory.getKeyManagers();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
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
