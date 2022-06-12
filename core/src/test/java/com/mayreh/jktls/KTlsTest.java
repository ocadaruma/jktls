package com.mayreh.jktls;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.mayreh.jktls.testing.KTlsServerClientRule;

public class KTlsTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    @Rule
    public KTlsServerClientRule rule = new KTlsServerClientRule(new String[] {
            "TLS_RSA_WITH_AES_128_GCM_SHA256"
    });

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

    @Test(timeout = 15000L)
    public void testSendfile() throws Exception {
        Path file = folder.newFile().toPath();
        Files.write(file, "sendfile!!\n".getBytes(StandardCharsets.UTF_8));
        try (FileChannel fileChannel = FileChannel.open(file)) {
            rule.setHandler((channel, message) -> {
                channel.transferFrom(fileChannel, 0, fileChannel.size());
            });

            assertEquals("sendfile!!", rule.getClient().sendAndWaitReply("hello"));
        }
    }
}
