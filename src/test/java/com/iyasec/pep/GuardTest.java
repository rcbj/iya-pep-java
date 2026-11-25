// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GuardTest {
    @Test
    void aPanicWhileDecidingIsUnavailableAndNoted() {
        String[] noted = {""};
        Decision failed = Pep.guarded(() -> {
            throw new RuntimeException("engine bug");
        }, why -> noted[0] = why);
        assertEquals(Decision.Kind.UNAVAILABLE, failed.kind());
        assertTrue(failed.why().contains("engine bug"), failed.why());
        assertTrue(noted[0].contains("engine bug"), noted[0]);
        assertEquals(403, failed.httpStatus());
        Decision ok = Pep.guarded(() -> Decision.deny("policy"), why -> {
            throw new RuntimeException("not noted");
        });
        assertEquals(Decision.deny("policy"), ok);
    }
}
