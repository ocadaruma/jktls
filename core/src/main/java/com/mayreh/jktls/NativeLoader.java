package com.mayreh.jktls;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

class NativeLoader {
    private static boolean loaded;

    static synchronized void load() {
        if (loaded) {
            return;
        }
        String resourceName = resourceName();
        try (TemporaryFile file = new TemporaryFile();
             InputStream is = NativeLoader.class.getClassLoader().getResourceAsStream(resourceName)) {
            Files.copy(is, file.path, StandardCopyOption.REPLACE_EXISTING);
            System.load(file.path.toAbsolutePath().toString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        loaded = true;
    }

    private static String resourceName() {
        String os = os();
        String arch = arch();

        final String extension;
        if ("macos".equals(os)) {
            extension = "dylib";
        } else {
            extension = "so";
        }

        return String.format("libjktls-%s-%s.%s", arch, os, extension);
    }

    private static String os() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("linux")) {
            return "linux";
        }
        if (os.contains("mac os") || os.contains("darwin")) {
            return "macos";
        }
        throw new RuntimeException("platform not supported: " + System.getProperty("os.name"));
    }

    private static String arch() {
        return System.getProperty("os.arch");
    }

    private static class TemporaryFile implements AutoCloseable {
        final Path path;

        TemporaryFile() {
            try {
                path = Files.createTempFile("jktls", ".tmp");
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Override
        public void close() {
            try {
                Files.deleteIfExists(path);
            } catch (IOException e) {
                // ignore
            }
        }
    }
}
