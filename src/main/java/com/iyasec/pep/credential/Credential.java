// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.PepConfig;
import com.iyasec.pep.PepException;
import com.iyasec.pep.http.Answer;
import com.iyasec.pep.http.Body;
import com.iyasec.pep.http.Field;
import com.iyasec.pep.http.HttpClient;
import com.iyasec.pep.key.SigningKey;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The PEP's one credential: an RFC 7523 self-assertion through
 * {@code sts-remote-pep} for a DPoP-bound access token, on every call.
 * One key signs the assertion and every proof. Three audiences, one token
 * each, used until 30 seconds before it expires. A refused grant is not
 * asked again for five seconds. A call with no token is not made.
 */
public final class Credential {
    /** The token endpoint, under the PDP URL. */
    public static final String TOKEN_PATH = "/oauth2/token";
    private static final String JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final long ASSERTION_LIFETIME_S = 120;
    private static final long RENEW_BEFORE_S = 30;
    private static final Duration REFUSED_HOLD = Duration.ofSeconds(5);

    private final String name;
    private final String clientId;
    private final String base;
    private final Path keyPath;
    private final HttpClient client;
    private final Object keyLock = new Object();
    private LoadedKey key;
    private final Object tokenLock = new Object();
    private final Held[] tokens = new Held[3];
    private final Refused[] refusedUntil = new Refused[3];
    private final Object[] gates = {new Object(), new Object(), new Object()};
    private final Object nonceLock = new Object();
    private final Map<String, String> nonces = new HashMap<>();

    private Credential(String name, String clientId, String base, Path keyPath, HttpClient client, LoadedKey key) {
        this.name = name;
        this.clientId = clientId;
        this.base = base;
        this.keyPath = keyPath;
        this.client = client;
        this.key = key;
    }

    /** Reads the key. A key that cannot be used is refused here. */
    public static Credential create(PepConfig config, HttpClient client) throws PepException {
        Path path = Path.of(config.assertionKey);
        return new Credential(config.name, config.clientId, config.base(), path, client, readKey(path));
    }

    /** The key's RFC 7638 thumbprint. */
    public String thumbprint() {
        synchronized (keyLock) {
            return key.key.thumbprint();
        }
    }

    /**
     * Reads the key again when its file changed. A key that no longer loads
     * keeps the one held, and the error is returned. A changed key drops every token.
     *
     * @return whether the key material changed
     */
    public boolean reloadKey() throws PepException {
        FileTime modified = mtime(keyPath);
        synchronized (keyLock) {
            if (sameTime(modified, key.modified)) {
                return false;
            }
        }
        LoadedKey loaded = readKey(keyPath);
        boolean changed;
        synchronized (keyLock) {
            changed = !key.key.thumbprint().equals(loaded.key.thumbprint());
            key = loaded;
        }
        if (changed) {
            synchronized (tokenLock) {
                tokens[0] = null;
                tokens[1] = null;
                tokens[2] = null;
            }
        }
        return changed;
    }

    /** Drops the token held for {@code audience} when it is still {@code token}. */
    public void dropToken(Audience audience, String token) {
        synchronized (tokenLock) {
            Held held = tokens[audience.index()];
            if (held != null && held.value.equals(token)) {
                tokens[audience.index()] = null;
            }
        }
    }

    /** Whether a token is held for {@code audience}. */
    public boolean holds(Audience audience) {
        return fresh(audience) != null;
    }

    /**
     * The token for {@code audience}: the one held, or one fetch shared by
     * every caller waiting for it.
     */
    public String token(Audience audience) throws PepException {
        String held = fresh(audience);
        if (held != null) {
            return held;
        }
        synchronized (gates[audience.index()]) {
            held = fresh(audience);
            if (held != null) {
                return held;
            }
            synchronized (tokenLock) {
                Refused refused = refusedUntil[audience.index()];
                if (refused != null && Instant.now().isBefore(refused.until)) {
                    throw new PepException("refused", refused.why);
                }
            }
            try {
                Held fetched = fetch(audience);
                synchronized (tokenLock) {
                    tokens[audience.index()] = fetched;
                    refusedUntil[audience.index()] = null;
                }
                return fetched.value;
            } catch (PepException e) {
                if ("refused".equals(e.code())) {
                    synchronized (tokenLock) {
                        refusedUntil[audience.index()] = new Refused(Instant.now().plus(REFUSED_HOLD), e.detail());
                    }
                }
                throw e;
            }
        }
    }

    /**
     * One call to a resource of {@code audience}, with its token and a proof.
     * A nonce demand is answered once, and a refused token is replaced once.
     */
    public Answer call(Audience audience, String method, String url, String accept, List<Field> extra, Body body) throws PepException {
        String role = audience.scope();
        boolean nonceRetried = false;
        boolean tokenReplaced = false;
        while (true) {
            String token = token(audience);
            String nonce = nonce(url, role);
            List<Field> headers = new ArrayList<>();
            headers.add(new Field("Authorization", "DPoP " + token));
            headers.add(new Field("DPoP", proof(method, url, token, nonce)));
            headers.add(new Field("Accept", accept));
            if (extra != null) {
                headers.addAll(extra);
            }
            Answer answer = client.send(method, url, headers, body);
            rememberNonce(url, role, answer);
            if (answer.status == 401) {
                String challenge = answer.wwwAuthenticate.toLowerCase();
                if (challenge.contains("use_dpop_nonce") && !nonceRetried && !answer.dpopNonce.isEmpty()) {
                    nonceRetried = true;
                    continue;
                }
                if (challenge.contains("invalid_token") && !tokenReplaced) {
                    tokenReplaced = true;
                    dropToken(audience, token);
                    continue;
                }
            }
            return answer;
        }
    }

    private Held fetch(Audience audience) throws PepException {
        String tokenUrl = base + TOKEN_PATH;
        boolean retried = false;
        while (true) {
            String nonce = nonce(tokenUrl, "token");
            String dpop = proof("POST", tokenUrl, null, nonce);
            List<Field> form = List.of(
                    new Field("grant_type", JWT_BEARER),
                    new Field("assertion", assertion(tokenUrl)),
                    new Field("client_id", clientId),
                    new Field("scope", audience.scope()),
                    new Field("resource", base + audience.path()));
            List<Field> headers = List.of(
                    new Field("DPoP", dpop),
                    new Field("Accept", "application/json"));
            Answer answer = client.send("POST", tokenUrl, headers, Body.form(form));
            rememberNonce(tokenUrl, "token", answer);
            JsonNode json = answer.json();
            String error = text(json, "error");
            if (answer.status == 400 && "use_dpop_nonce".equals(error) && !retried && !answer.dpopNonce.isEmpty()) {
                retried = true;
                continue;
            }
            if (answer.status != 200) {
                String description = text(json, "error_description");
                String message = ("the token endpoint refused " + audience.scope() + " for " + name + ": "
                        + answer.status + " " + error + " " + description).stripTrailing();
                throw new PepException("refused", message);
            }
            String value = text(json, "access_token");
            if (value.isEmpty()) {
                throw new PepException("transport", "the token endpoint answered 200 without an access_token");
            }
            String type = text(json, "token_type");
            if (!type.equalsIgnoreCase("DPoP")) {
                throw new PepException("refused", "the token endpoint issued a token that is not DPoP-bound");
            }
            long expiresIn = 60;
            if (json != null) {
                JsonNode expires = json.get("expires_in");
                if (expires != null && expires.isIntegralNumber() && expires.canConvertToLong() && expires.longValue() >= 0) {
                    expiresIn = expires.longValue();
                }
            }
            long life = Math.max(0, expiresIn - RENEW_BEFORE_S);
            return new Held(value, Instant.now().plusSeconds(life));
        }
    }

    private String fresh(Audience audience) {
        synchronized (tokenLock) {
            Held held = tokens[audience.index()];
            if (held != null && Instant.now().isBefore(held.renewAt)) {
                return held.value;
            }
            return null;
        }
    }

    private String proof(String method, String url, String token, String nonce) {
        SigningKey signing = signingKey();
        ObjectNode claims = com.iyasec.pep.Json.object();
        claims.put("jti", SigningKey.randomId());
        claims.put("htm", method);
        claims.put("htu", HttpClient.htu(url));
        claims.put("iat", nowSeconds());
        if (token != null) {
            claims.put("ath", sha256B64(token.getBytes(StandardCharsets.UTF_8)));
        }
        if (nonce != null) {
            claims.put("nonce", nonce);
        }
        ObjectNode header = com.iyasec.pep.Json.object();
        header.put("typ", "dpop+jwt");
        header.set("jwk", signing.jwk());
        return signing.jws(header, claims);
    }

    private String assertion(String audience) {
        long now = nowSeconds();
        ObjectNode claims = com.iyasec.pep.Json.object();
        claims.put("iss", name);
        claims.put("sub", name);
        claims.put("aud", audience);
        claims.put("iat", now);
        claims.put("exp", now + ASSERTION_LIFETIME_S);
        claims.put("jti", SigningKey.randomId());
        ObjectNode header = com.iyasec.pep.Json.object();
        header.put("typ", "JWT");
        return signingKey().jws(header, claims);
    }

    private SigningKey signingKey() {
        synchronized (keyLock) {
            return key.key;
        }
    }

    private String nonce(String url, String role) {
        synchronized (nonceLock) {
            return nonces.get(origin(url) + " " + role);
        }
    }

    private void rememberNonce(String url, String role, Answer answer) {
        String nonce = answer.dpopNonce == null ? "" : answer.dpopNonce.trim();
        if (!nonce.isEmpty()) {
            synchronized (nonceLock) {
                nonces.put(origin(url) + " " + role, nonce);
            }
        }
    }

    private static String origin(String url) {
        try {
            URI uri = URI.create(url);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return "";
            }
            if (uri.getPort() < 0) {
                return uri.getScheme() + "://" + uri.getHost();
            }
            return uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort();
        } catch (Exception e) {
            return "";
        }
    }

    private static long nowSeconds() {
        return System.currentTimeMillis() / 1000L;
    }

    private static String sha256B64(byte[] data) {
        try {
            return SigningKey.b64Url(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String text(JsonNode json, String field) {
        if (json == null) {
            return "";
        }
        JsonNode value = json.get(field);
        return value != null && value.isTextual() ? value.asText() : "";
    }

    private static LoadedKey readKey(Path path) throws PepException {
        FileTime modified = mtime(path);
        String pem;
        try {
            pem = Files.readString(path);
        } catch (Exception e) {
            throw new PepException("config", "the assertion key " + path + " could not be read: " + e.getMessage());
        }
        return new LoadedKey(SigningKey.fromPem(pem), modified);
    }

    private static FileTime mtime(Path path) {
        try {
            return Files.getLastModifiedTime(path);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean sameTime(FileTime left, FileTime right) {
        if (left == null || right == null) {
            return left == right;
        }
        return left.equals(right);
    }

    private static final class Held {
        final String value;
        final Instant renewAt;

        Held(String value, Instant renewAt) {
            this.value = value;
            this.renewAt = renewAt;
        }
    }

    private static final class Refused {
        final Instant until;
        final String why;

        Refused(Instant until, String why) {
            this.until = until;
            this.why = why;
        }
    }

    private static final class LoadedKey {
        final SigningKey key;
        final FileTime modified;

        LoadedKey(SigningKey key, FileTime modified) {
            this.key = key;
            this.modified = modified;
        }
    }
}
