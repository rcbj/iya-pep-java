// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.key;

import com.fasterxml.jackson.databind.JsonNode;
import com.iyasec.pep.Json;
import com.iyasec.pep.PepException;
import com.iyasec.pep.support.Keys;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningKeyTest {
    @Test
    void anEcKeySignsEs256WithA64ByteSignature() throws Exception {
        SigningKey key = SigningKey.fromPem(Keys.ecPem((byte) 7));
        assertEquals("ES256", key.alg());
        String jws = key.jws(Json.MAPPER.readTree("{\"typ\":\"JWT\"}"), Json.MAPPER.readTree("{\"a\":1}"));
        String[] parts = jws.split("\\.", -1);
        assertEquals(3, parts.length);
        assertEquals(64, SigningKey.b64UrlDecode(parts[2]).length);
        JsonNode header = Json.MAPPER.readTree(SigningKey.b64UrlDecode(parts[0]));
        assertEquals("ES256", header.get("alg").asText());
        assertEquals(key.thumbprint(), SigningKey.jwkThumbprint(key.jwk()));
    }

    @Test
    void aPemThumbprintIsTheKeys() throws Exception {
        String pem = Keys.ecPem((byte) 7);
        SigningKey key = SigningKey.fromPem(pem);
        assertEquals(key.thumbprint(), SigningKey.pemThumbprint(pem));
        assertNull(SigningKey.pemThumbprint("garbage"));
    }

    @Test
    void aSmallRsaKeyAndGarbageAreRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        RSAPrivateKey small = (RSAPrivateKey) generator.generateKeyPair().getPrivate();
        assertEquals(1024, small.getModulus().bitLength());
        PepException err = assertThrows(PepException.class, () -> SigningKey.fromPem(pkcs8(small)));
        assertTrue(err.detail().contains("1024"), err.detail());
        PepException garbage = assertThrows(PepException.class, () -> SigningKey.fromPem("not a key"));
        assertEquals("config", garbage.code());
    }

    @Test
    void anRsaKeySignsRs256AndHasAStableThumbprint() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        SigningKey loaded = SigningKey.fromPem(pkcs8(pair.getPrivate()));
        assertEquals("RS256", loaded.alg());
        assertEquals(loaded.thumbprint(), SigningKey.jwkThumbprint(loaded.jwk()));
    }

    private static String pkcs8(java.security.PrivateKey key) {
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }
}
