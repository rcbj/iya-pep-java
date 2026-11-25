// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.support;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** P-256 PKCS#8 keys for the tests. */
public final class Keys {
    private Keys() {}

    /** A P-256 key whose scalar is {@code fill} repeated, as PKCS#8 PEM. */
    public static String ecPem(byte fill) {
        try {
            byte[] scalar = new byte[32];
            Arrays.fill(scalar, fill);
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPrivateKey key = (ECPrivateKey) KeyFactory.getInstance("EC")
                    .generatePrivate(new ECPrivateKeySpec(new BigInteger(1, scalar), spec));
            String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded());
            return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Writes the test scalar (byte 9) and returns the path. */
    public static String keyFile(String tag) {
        return write(tag, ecPem((byte) 9));
    }

    public static String write(String tag, String pem) {
        try {
            Path path = Path.of(System.getProperty("java.io.tmpdir"),
                    "iya-pep-test-" + tag + "-" + ProcessHandle.current().pid() + ".pem");
            Files.writeString(path, pem);
            return path.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
