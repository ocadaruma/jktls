package com.mayreh.ktls;

import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.ScatteringByteChannel;
import java.nio.channels.SocketChannel;
import java.util.Set;

import com.mayreh.ktls.sun.nio.ch.FileChannelImpl;
import com.mayreh.ktls.sun.nio.ch.SocketChannelImpl;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import sun.nio.ch.IOUtil;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class KTlsSocketChannel implements ByteChannel,
                                          ScatteringByteChannel,
                                          GatheringByteChannel,
                                          NetworkChannel {
    private static native void setTcpUlp(int fd, String name);
    private static native void setTlsTx_Tls12_Aes_Gcm128(
            int fd, byte[] iv, byte[] key, byte[] salt, byte[] recSeq);
    private static native long sendFile(int outFd, int inFd, long position, long count);

    private final SocketChannel delegate;
    private final SocketChannelImpl impl;

    static KTlsSocketChannel wrap(SocketChannel channel) {
        if (!SocketChannelImpl.isInstance(channel)) {
            throw new UnsupportedOperationException("Unsupported SocketChannel implementation");
        }
        return new KTlsSocketChannel(channel, new SocketChannelImpl(channel));
    }

    public long transferFrom(FileChannel channel, long position, long count) {
        if (FileChannelImpl.isInstance(channel)) {
            FileChannelImpl fileChannel = new FileChannelImpl(channel);
            return sendFile(IOUtil.fdVal(impl.getFD()),
                            IOUtil.fdVal(fileChannel.fd()),
                            position,
                            count);
        }
        throw new UnsupportedOperationException("Unsupported FileChannel implementation");
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        return delegate.write(srcs, offset, length);
    }

    @Override
    public long write(ByteBuffer[] srcs) throws IOException {
        return delegate.write(srcs);
    }

    @Override
    public KTlsSocketChannel bind(SocketAddress local) throws IOException {
        delegate.bind(local);
        return this;
    }

    @Override
    public SocketAddress getLocalAddress() throws IOException {
        return delegate.getLocalAddress();
    }

    @Override
    public <T> KTlsSocketChannel setOption(SocketOption<T> name, T value) throws IOException {
        if (name == KTlsSocketOptions.TCP_ULP) {
            setTcpUlp(IOUtil.fdVal(impl.getFD()), (String) value);
            return this;
        }
        if (name == KTlsSocketOptions.TLS_TX) {
            TlsCryptoInfo info = (TlsCryptoInfo) value;
            if ("TLS_RSA_WITH_AES_128_GCM_SHA256".equals(info.cipherSuite())) {
                setTlsTx_Tls12_Aes_Gcm128(IOUtil.fdVal(impl.getFD()), info.iv(), info.key(), info.salt(), info.recSeq());
                return this;
            }
            throw new UnsupportedOperationException("Unsupported cipher suite");
        }
        delegate.setOption(name, value);
        return this;
    }

    @Override
    public <T> T getOption(SocketOption<T> name) throws IOException {
        return delegate.getOption(name);
    }

    @Override
    public Set<SocketOption<?>> supportedOptions() {
        return delegate.supportedOptions();
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        return delegate.read(dsts, offset, length);
    }

    @Override
    public long read(ByteBuffer[] dsts) throws IOException {
        return delegate.read(dsts);
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        return delegate.read(dst);
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        return delegate.write(src);
    }

    @Override
    public boolean isOpen() {
        return delegate.isOpen();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
