// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.key;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Json;
import com.iyasec.pep.PepException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * The PEP's own key. It signs the self-assertion and every DPoP proof.
 * EC P-256 (ES256) is preferred; RSA of 2048 bits or more (RS256) is accepted.
 */
public final class SigningKey {
    /** The smallest RSA modulus accepted, in bits. */
    public static final int MIN_RSA_BITS = 2048;

    private static final BigInteger P256_ORDER = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final PrivateKey key;
    private final String alg;
    private final ObjectNode jwk;
    private final String thumbprint;

    private SigningKey(PrivateKey key, String alg, ObjectNode jwk, String thumbprint) {
        this.key = key;
        this.alg = alg;
        this.jwk = jwk;
        this.thumbprint = thumbprint;
    }

    /**
     * Reads a PEM private key: PKCS#8 ({@code PRIVATE KEY}), SEC 1
     * ({@code EC PRIVATE KEY}) or PKCS#1 ({@code RSA PRIVATE KEY}).
     */
    public static SigningKey fromPem(String pem) throws PepException {
        Object parsed;
        try (PEMParser parser = new PEMParser(new StringReader(pem == null ? "" : pem))) {
            parsed = parser.readObject();
        } catch (IOException e) {
            throw neither();
        }
        if (parsed == null) {
            throw neither();
        }
        PrivateKey key;
        try {
            key = toPrivateKey(parsed);
        } catch (Exception e) {
            throw neither();
        }
        if (key instanceof ECPrivateKey ec) {
            if (!isP256(ec)) {
                throw neither();
            }
            return ec(ec);
        }
        if (key instanceof RSAPrivateCrtKey rsa) {
            int bits = rsa.getModulus().bitLength();
            if (bits < MIN_RSA_BITS) {
                throw new PepException("config",
                        "the assertion key is RSA of " + bits + " bits; at least " + MIN_RSA_BITS + " are required");
            }
            return rsa(rsa);
        }
        throw neither();
    }

    /** {@code ES256} or {@code RS256}. */
    public String alg() {
        return alg;
    }

    /** The public key as a JWK. */
    public ObjectNode jwk() {
        return jwk.deepCopy();
    }

    /** The RFC 7638 SHA-256 thumbprint, base64url. */
    public String thumbprint() {
        return thumbprint;
    }

    /**
     * A compact JWS of {@code claims} under {@code header}, with {@code alg} added.
     * An ES256 signature is R||S, 32 bytes each, not DER.
     */
    public String jws(JsonNode header, JsonNode claims) {
        ObjectNode signed = header instanceof ObjectNode object ? object.deepCopy() : Json.object();
        signed.put("alg", alg);
        String input = b64Url(jsonBytes(signed)) + "." + b64Url(jsonBytes(claims));
        byte[] signature;
        try {
            if ("ES256".equals(alg)) {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(key);
                signer.update(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                signature = joseEc(signer.sign(), 32);
            } else {
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(key);
                signer.update(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                signature = signer.sign();
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        return input + "." + b64Url(signature);
    }

    /**
     * The RFC 7638 thumbprint of a public JWK (EC, RSA or OKP).
     * Null when the JWK cannot be canonicalised.
     */
    public static String jwkThumbprint(JsonNode jwk) {
        if (jwk == null) {
            return null;
        }
        String kty = textual(jwk, "kty");
        if (kty == null) {
            return null;
        }
        String canonical = switch (kty) {
            case "EC" -> {
                String crv = textual(jwk, "crv");
                String x = textual(jwk, "x");
                String y = textual(jwk, "y");
                if (crv == null || x == null || y == null) {
                    yield null;
                }
                yield "{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
            }
            case "RSA" -> {
                String e = textual(jwk, "e");
                String n = textual(jwk, "n");
                if (e == null || n == null) {
                    yield null;
                }
                yield "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
            }
            case "OKP" -> {
                String crv = textual(jwk, "crv");
                String x = textual(jwk, "x");
                if (crv == null || x == null) {
                    yield null;
                }
                yield "{\"crv\":\"" + crv + "\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}";
            }
            default -> null;
        };
        if (canonical == null) {
            return null;
        }
        return b64Url(sha256(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    /**
     * The RFC 7638 thumbprint of a PEM private key's public half
     * (EC P-256 or RSA of at least 2048 bits). Null for a key that cannot be read.
     */
    public static String pemThumbprint(String pem) {
        try {
            return fromPem(pem).thumbprint();
        } catch (PepException e) {
            return null;
        }
    }

    /** 128 random bits as hex, for a {@code jti}. */
    public static String randomId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    public static String b64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static byte[] b64UrlDecode(String text) {
        String padded = text == null ? "" : text;
        int mod = padded.length() % 4;
        if (mod != 0) {
            padded = padded + "=".repeat(4 - mod);
        }
        return Base64.getUrlDecoder().decode(padded);
    }

    private static SigningKey ec(ECPrivateKey key) throws PepException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        org.bouncycastle.math.ec.ECPoint point = spec.getG().multiply(key.getS()).normalize();
        String x = b64Url(fixed(point.getAffineXCoord().getEncoded(), 32));
        String y = b64Url(fixed(point.getAffineYCoord().getEncoded(), 32));
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
        ObjectNode jwk = Json.object();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", x);
        jwk.put("y", y);
        return new SigningKey(key, "ES256", jwk, b64Url(sha256(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }

    private static SigningKey rsa(RSAPrivateCrtKey key) {
        String n = b64Url(unsigned(key.getModulus()));
        String e = b64Url(unsigned(key.getPublicExponent()));
        String canonical = "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
        ObjectNode jwk = Json.object();
        jwk.put("kty", "RSA");
        jwk.put("n", n);
        jwk.put("e", e);
        return new SigningKey(key, "RS256", jwk, b64Url(sha256(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }

    private static boolean isP256(ECPrivateKey key) {
        if (key.getParams() == null || key.getParams().getCurve() == null || key.getParams().getOrder() == null) {
            return false;
        }
        return key.getParams().getCurve().getField().getFieldSize() == 256 && P256_ORDER.equals(key.getParams().getOrder());
    }

    private static PrivateKey toPrivateKey(Object parsed) throws IOException {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        if (parsed instanceof PEMKeyPair pair) {
            return converter.getKeyPair(pair).getPrivate();
        }
        if (parsed instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo info) {
            return converter.getPrivateKey(info);
        }
        if (parsed instanceof PrivateKey key) {
            return key;
        }
        throw new IOException("unsupported PEM");
    }

    /** RFC 7518: R and S concatenated, each {@code size} bytes, from a DER signature. */
    static byte[] joseEc(byte[] der, int size) {
        ASN1Sequence sequence = ASN1Sequence.getInstance(der);
        byte[] r = ((ASN1Integer) sequence.getObjectAt(0)).getValue().toByteArray();
        byte[] s = ((ASN1Integer) sequence.getObjectAt(1)).getValue().toByteArray();
        byte[] out = new byte[size * 2];
        System.arraycopy(fixed(r, size), 0, out, 0, size);
        System.arraycopy(fixed(s, size), 0, out, size, size);
        return out;
    }

    private static byte[] fixed(byte[] src, int size) {
        if (src.length == size) {
            return src;
        }
        byte[] out = new byte[size];
        if (src.length > size) {
            System.arraycopy(src, src.length - size, out, 0, size);
        } else {
            System.arraycopy(src, 0, out, size - src.length, src.length);
        }
        return out;
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static byte[] jsonBytes(JsonNode node) {
        try {
            return Json.MAPPER.writeValueAsBytes(node == null ? Json.object() : node);
        } catch (JsonProcessingException e) {
            return new byte[0];
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String textual(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    private static PepException neither() {
        return new PepException("config", "the assertion key is neither an EC P-256 nor an RSA private key in PEM");
    }
}
