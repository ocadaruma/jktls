package com.mayreh.ktls;

import java.nio.channels.ByteChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.GatheringByteChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.ScatteringByteChannel;
import java.nio.channels.SocketChannel;

import sun.nio.ch.KTlsSocketChannelImpl;

public interface KTlsSocketChannel extends ByteChannel,
                                           ScatteringByteChannel,
                                           GatheringByteChannel,
                                           NetworkChannel {
    static KTlsSocketChannel wrap(SocketChannel channel) {
        return new KTlsSocketChannelImpl(channel);
    }

    long transferFrom(FileChannel channel, long position, long count);
}
