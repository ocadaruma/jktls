package com.mayreh.jktls.testing;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public class TlsClient implements AutoCloseable {
    private final SSLSocket socket;
    private final BufferedReader reader;
    private final PrintWriter writer;

    public TlsClient(String host, int port) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.2");
            context.init(null, createTrustManagers(), null);
            socket = (SSLSocket) context
                    .getSocketFactory()
                    .createSocket(host, port);

            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(socket.getOutputStream());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public String sendAndWaitReply(String message) {
        writer.println(message);
        writer.flush();

        try {
            return reader.readLine();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static TrustManager[] createTrustManagers() {
        return new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
    }

    @Override
    public void close() {
        try {
            socket.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
