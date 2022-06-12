package com.mayreh.jktls;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.mayreh.jktls.testing.KTlsServerClientRule;

public class KTlsTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    @Rule
    public KTlsServerClientRule rule = new KTlsServerClientRule();

    @Test(timeout = 15000L)
    public void testEcho() {
        rule.setHandler((channel, message) -> {
            ByteBuffer buf = ByteBuffer.allocate(message.length);
            buf.put(message);
            buf.flip();
            channel.write(buf);
        });

        assertEquals("hello", rule.getClient().sendAndWaitReply("hello"));
    }

//    @Test(timeout = 30000L)
//    public void testSendfile() {
//
//    }
}
