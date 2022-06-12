package com.mayreh.jktls.demo;

import static org.junit.Assert.assertFalse;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class UtilsTest {
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testDelete() throws Exception {
        File testDir = folder.newFolder("test");
        Files.write(testDir.toPath().resolve("foo.txt"),
                    "foo bar baz".getBytes(StandardCharsets.UTF_8));

        Utils.delete(testDir.toPath());
        assertFalse(testDir.exists());
    }
}
