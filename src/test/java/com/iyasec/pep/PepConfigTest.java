// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PepConfigTest {
    @Test
    void aSectionReadsWithDefaultsAndRefusesUnknownMembers() throws Exception {
        PepConfig defaults = PepConfig.fromJson(Json.MAPPER.readTree("{\"name\":\"pep-1\",\"assertionKey\":\"/k.pem\"}"),
                "https://sts.example/realm/r1/", "app");
        assertEquals(Mode.LOCAL, defaults.mode);
        PepConfig central = PepConfig.fromJson(
                Json.MAPPER.readTree("{\"name\":\"pep-1\",\"assertionKey\":\"/k.pem\",\"mode\":\"central\"}"),
                "https://sts.example/realm/r1/", "app");
        assertEquals(PepConfig.DEFAULT_CLIENT_ID, central.clientId);
        assertEquals("https://sts.example/realm/r1", central.base());
        assertEquals("r1", central.realm());
        assertEquals(300_000L, central.fallbackPollMs);
        PepException err = assertThrows(PepException.class, () -> PepConfig.fromJson(
                Json.MAPPER.readTree("{\"name\":\"p\",\"assertionKey\":\"k\",\"polIntervalMs\":5}"), "https://s", "a"));
        assertTrue(err.detail().contains("polIntervalMs"), err.detail());
    }

    @Test
    void badValuesAreRefused() throws Exception {
        assertThrows(PepException.class, () -> read(extra("mode", "remote")));
        assertThrows(PepException.class, () -> read(extra("name", "a b")));
        assertThrows(PepException.class, () -> read(extra("pdpUrl", "ftp://x")));
        assertThrows(PepException.class, () -> read(number("pollIntervalMs", 10)));
        assertThrows(PepException.class, () -> read(number("permitCacheMs", 120000)));
        assertThrows(PepException.class, () -> read(extra("application", "")));
        PepConfig bare = read(Json.object());
        assertEquals("", bare.realm());
    }

    private static PepConfig read(ObjectNode extra) throws PepException {
        ObjectNode section = Json.object();
        section.put("name", "pep-1");
        section.put("assertionKey", "/k.pem");
        section.put("mode", "central");
        extra.fields().forEachRemaining(field -> section.set(field.getKey(), field.getValue()));
        return PepConfig.fromJson(section, "https://sts.example", "app");
    }

    private static ObjectNode extra(String key, String value) {
        ObjectNode node = Json.object();
        node.put(key, value);
        return node;
    }

    private static ObjectNode number(String key, long value) {
        ObjectNode node = Json.object();
        node.put(key, value);
        return node;
    }
}
