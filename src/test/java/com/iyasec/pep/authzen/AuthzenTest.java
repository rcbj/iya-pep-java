// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Json;
import com.iyasec.pep.engine.Names;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthzenTest {
    @Test
    void numbersReadAsJavascriptWritesThem() throws Exception {
        assertEquals("1", Authzen.numberText(1.0));
        assertEquals("1.5", Authzen.numberText(1.5));
        assertEquals("-0.25", Authzen.numberText(-0.25));
        assertEquals("1e+21", Authzen.numberText(1e21));
        assertEquals("100000000000000000000", Authzen.numberText(1e20));
        assertEquals("1.5e-7", Authzen.numberText(1.5e-7));
        assertEquals("0.000001", Authzen.numberText(0.000001));
        assertEquals("123.456", Authzen.numberText(123.456));
        assertEquals("3", Authzen.lexical(Authzen.INTEGER, Json.MAPPER.readTree("3.0")));
        assertNull(Authzen.lexical(Authzen.INTEGER, Json.MAPPER.readTree("1.5")));
        assertNull(Authzen.lexical(Authzen.INTEGER, Json.MAPPER.readTree("9007199254740993")));
        assertNull(Authzen.lexical(Names.STRING, Json.MAPPER.readTree("3")));
        assertEquals("true", Authzen.lexical(Authzen.BOOLEAN, Json.MAPPER.readTree("true")));
    }

    @Test
    void keysFollowObjectKeysOrder() throws Exception {
        ObjectNode value = (ObjectNode) Json.MAPPER.readTree("{\"b\":1,\"10\":1,\"a\":1,\"2\":1,\"01\":1}");
        assertEquals(List.of("2", "10", "b", "a", "01"), Authzen.keysInJsOrder(value));
    }

    @Test
    void lexicalFormsParseByTheEnginesRules() {
        assertTrue(Authzen.lexicallyValid(Authzen.DATETIME, "2026-01-02T03:04:05Z"));
        assertFalse(Authzen.lexicallyValid(Authzen.DATETIME, "2026-13-02T03:04:05Z"));
        assertTrue(Authzen.lexicallyValid(Authzen.DAYTIME_DURATION, "P1DT2H"));
        assertFalse(Authzen.lexicallyValid(Authzen.DAYTIME_DURATION, "P1DT"));
        assertTrue(Authzen.lexicallyValid(Authzen.YEARMONTH_DURATION, "-P1Y2M"));
        assertFalse(Authzen.lexicallyValid(Authzen.YEARMONTH_DURATION, "P"));
        assertTrue(Authzen.lexicallyValid(Authzen.BASE64BINARY, "AAA="));
        assertFalse(Authzen.lexicallyValid(Authzen.BASE64BINARY, "A==="));
        assertTrue(Authzen.lexicallyValid(Authzen.IPADDRESS, "[::1]:443"));
        assertFalse(Authzen.lexicallyValid(Authzen.IPADDRESS, "[::1"));
        assertTrue(Authzen.lexicallyValid(Authzen.X500NAME, "cn=a\\,b,o=x"));
        assertFalse(Authzen.lexicallyValid(Authzen.X500NAME, "=a"));
        assertTrue(Authzen.lexicallyValid(Authzen.RFC822NAME, "a@example.com"));
        assertFalse(Authzen.lexicallyValid(Authzen.RFC822NAME, "a@"));
    }
}
