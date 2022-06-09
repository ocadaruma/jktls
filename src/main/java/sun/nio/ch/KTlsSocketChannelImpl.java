package sun.nio.ch;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.util.Set;

import com.mayreh.ktls.KTlsSocketChannel;
import com.mayreh.ktls.KTlsSocketOptions;

import sun.security.ssl.TlsCryptoInfo;

/**
 * Need to inherit {@link SelChImpl} so that {@link FileChannel#transferTo} can work
 */
public class KTlsSocketChannelImpl implements KTlsSocketChannel, SelChImpl {
    static {
        System.load(System.getenv("JKTLS_LIB_PATH"));
    }

    private final SocketChannelImpl delegate;

    private static native void setTcpUlp(int fd, String name);
    private static native void setTlsTxTls12AesGcm128(
            int fd, byte[] iv, byte[] key, byte[] salt, byte[] recSeq);

    public KTlsSocketChannelImpl(SocketChannel delegate) {
        if (!(delegate instanceof SocketChannelImpl)) {
            throw new UnsupportedOperationException("Only SocketChannelImpl is now supported");
        }
        this.delegate = (SocketChannelImpl) delegate;
    }

    @Override
    public KTlsSocketChannel bind(SocketAddress local) throws IOException {
        delegate.bind(local);
        return this;
    }

    @Override
    public <T> KTlsSocketChannel setOption(SocketOption<T> name, T value) throws IOException {
        if (name == KTlsSocketOptions.TCP_ULP) {
            setTcpUlp(getFDVal(), (String) value);
            return this;
        }
        if (name == KTlsSocketOptions.TLS_TX) {
            TlsCryptoInfo info = (TlsCryptoInfo) value;
            if ("TLS_RSA_WITH_AES_128_GCM_SHA256".equals(info.cipherSuite())) {
                setTlsTxTls12AesGcm128(getFDVal(), info.iv(), info.key(), info.salt(), info.recSeq());
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
    public int read(ByteBuffer dst) throws IOException {
        return delegate.read(dst);
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
    public int write(ByteBuffer src) throws IOException {
        return delegate.write(src);
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
    public SocketAddress getLocalAddress() throws IOException {
        return delegate.getLocalAddress();
    }

    @Override
    public FileDescriptor getFD() {
        return delegate.getFD();
    }

    @Override
    public int getFDVal() {
        return delegate.getFDVal();
    }

    @Override
    public boolean translateAndUpdateReadyOps(int ops, SelectionKeyImpl sk) {
        return delegate.translateAndUpdateReadyOps(ops, sk);
    }

    @Override
    public boolean translateAndSetReadyOps(int ops, SelectionKeyImpl sk) {
        return delegate.translateAndSetReadyOps(ops, sk);
    }

    @Override
    public void translateAndSetInterestOps(int ops, SelectionKeyImpl sk) {
        delegate.translateAndSetInterestOps(ops, sk);
    }

    @Override
    public int validOps() {
        return delegate.validOps();
    }

    @Override
    public void kill() throws IOException {
        delegate.kill();
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
