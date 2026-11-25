// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.http;

import com.iyasec.pep.PepException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Back-channel HTTP to the service. Redirects are not followed and the
 * process proxy environment is ignored. Plain {@code http} is sent as-is,
 * including off loopback; the caller chooses the URL.
 */
public final class HttpClient {
    /** The most a response body may be. */
    public static final int MAX_BODY = 8 * 1024 * 1024;
    /** {@code User-Agent} on every request. */
    public static final String USER_AGENT = "iya-pep-java/0.1.0";

    private final java.net.http.HttpClient client;
    private final Duration timeout;

    private HttpClient(java.net.http.HttpClient client, Duration timeout) {
        this.client = client;
        this.timeout = timeout;
    }

    /**
     * {@code ca} is PEM trust anchors added to the platform trust store, or empty.
     */
    public static HttpClient create(String ca, Duration timeout) throws PepException {
        java.net.http.HttpClient.Builder builder = java.net.http.HttpClient.newBuilder()
                .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                .version(java.net.http.HttpClient.Version.HTTP_1_1)
                .connectTimeout(timeout)
                .proxy(noProxy());
        SSLContext ssl = trust(ca);
        if (ssl != null) {
            builder.sslContext(ssl);
        }
        return new HttpClient(builder.build(), timeout);
    }

    /**
     * Sends one request. Any status is an {@link Answer}; only a transport
     * failure is an error.
     */
    public Answer send(String method, String url, List<Field> headers, Body body) throws PepException {
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(timeout);
            request.header("User-Agent", USER_AGENT);
            if (headers != null) {
                for (Field header : headers) {
                    request.header(header.name(), header.value());
                }
            }
            if (body == null) {
                if ("POST".equals(method)) {
                    request.method(method, HttpRequest.BodyPublishers.ofString(""));
                } else {
                    request.method(method, HttpRequest.BodyPublishers.noBody());
                }
            } else if (body.kind == Body.Kind.JSON) {
                request.header("Content-Type", "application/json");
                String text = body.json == null ? "null" : body.json.toString();
                request.method(method, HttpRequest.BodyPublishers.ofString(text));
            } else if (body.kind == Body.Kind.FORM) {
                request.header("Content-Type", "application/x-www-form-urlencoded");
                request.method(method, HttpRequest.BodyPublishers.ofString(encodeForm(body.form)));
            } else {
                request.header("Content-Type", "application/xml");
                request.method(method, HttpRequest.BodyPublishers.ofString(body.xml == null ? "" : body.xml));
            }
            HttpResponse<InputStream> response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            Answer answer = new Answer();
            answer.status = response.statusCode();
            answer.contentType = first(response, "content-type");
            answer.dpopNonce = first(response, "dpop-nonce");
            answer.etag = first(response, "etag");
            answer.wwwAuthenticate = String.join(", ", response.headers().allValues("www-authenticate"));
            try (InputStream in = response.body()) {
                byte[] buf = in.readNBytes(MAX_BODY + 1);
                if (buf.length > MAX_BODY) {
                    throw new PepException("transport", url + " answered more than " + MAX_BODY + " bytes");
                }
                answer.body = new String(buf, StandardCharsets.UTF_8);
            }
            return answer;
        } catch (PepException e) {
            throw e;
        } catch (Exception e) {
            String message = e.getMessage();
            if (message == null || message.isEmpty()) {
                message = e.getClass().getSimpleName();
            }
            throw new PepException("transport", url + ": " + message);
        }
    }

    /** {@code url} without its query and fragment: a DPoP proof's {@code htu}. */
    public static String htu(String url) {
        if (url == null) {
            return "";
        }
        int end = url.length();
        int query = url.indexOf('?');
        int fragment = url.indexOf('#');
        if (query >= 0) {
            end = Math.min(end, query);
        }
        if (fragment >= 0) {
            end = Math.min(end, fragment);
        }
        return url.substring(0, end);
    }

    private static String first(HttpResponse<?> response, String name) {
        return response.headers().firstValue(name).orElse("");
    }

    static String encodeForm(List<Field> fields) {
        StringBuilder out = new StringBuilder();
        if (fields == null) {
            return "";
        }
        for (Field field : fields) {
            if (out.length() > 0) {
                out.append('&');
            }
            out.append(URLEncoder.encode(field.name(), StandardCharsets.UTF_8));
            out.append('=');
            out.append(URLEncoder.encode(field.value() == null ? "" : field.value(), StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    private static ProxySelector noProxy() {
        return new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                return List.of(Proxy.NO_PROXY);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, java.io.IOException ioe) {}
        };
    }

    /**
     * PEM anchors added to the default trust store. Empty means the
     * platform default, so null is returned and the client keeps it.
     * A repeated certificate is added once.
     */
    private static SSLContext trust(String ca) throws PepException {
        if (ca == null || ca.trim().isEmpty()) {
            return null;
        }
        List<String> blocks = pemBlocks(ca);
        if (blocks.isEmpty()) {
            throw new PepException("config", "tlsCa holds no PEM certificate");
        }
        try {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            Path cacerts = Path.of(System.getProperty("java.home"), "lib", "security", "cacerts");
            try (InputStream in = Files.newInputStream(cacerts)) {
                store.load(in, "changeit".toCharArray());
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            int added = 0;
            for (String block : blocks) {
                X509Certificate certificate;
                try {
                    certificate = (X509Certificate) factory.generateCertificate(
                            new ByteArrayInputStream(block.getBytes(StandardCharsets.US_ASCII)));
                } catch (CertificateException e) {
                    throw new PepException("config", "tlsCa is not a PEM trust anchor");
                }
                store.setCertificateEntry("iya-pep-tls-" + added, certificate);
                added++;
            }
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trust.getTrustManagers(), null);
            return context;
        } catch (PepException e) {
            throw e;
        } catch (Exception e) {
            throw new PepException("config", "tlsCa: " + e.getMessage());
        }
    }

    private static List<String> pemBlocks(String ca) {
        List<String> seen = new ArrayList<>();
        for (String part : ca.split("-----END CERTIFICATE-----")) {
            String block = part.trim();
            if (!block.contains("BEGIN CERTIFICATE")) {
                continue;
            }
            String pem = block + "\n-----END CERTIFICATE-----\n";
            if (!seen.contains(pem)) {
                seen.add(pem);
            }
        }
        return seen;
    }
}
