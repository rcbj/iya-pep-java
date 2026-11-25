// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class DecisionTest {
    @Test
    void aPermitIs200AndEverythingElse403() {
        assertEquals(200, Decision.permit(List.of(), List.of()).httpStatus());
        assertEquals(403, Decision.deny("no").httpStatus());
        assertEquals(403, Decision.unavailable("down").httpStatus());
        assertFalse(Decision.deny("no").isPermit());
    }

    @Test
    void theBodyCarriesTheBoundApplicationAndNoEmptyProperties() {
        Access access = Access.of("read", "document", "42");
        access.context.put("application", Json.text("someone-else"));
        access.context.put("ip", Json.text("10.0.0.1"));
        ObjectNode body = Bodies.evaluationBody(Subject.user("alice", new LinkedHashMap<>()), access, "app-a",
                List.of("step-up"));
        assertEquals("app-a", body.get("context").get("application").asText());
        assertEquals("10.0.0.1", body.get("context").get("ip").asText());
        assertEquals(Json.strings(List.of("step-up")), body.get("context").get("supported_obligations"));
        assertNull(body.get("subject").get("properties"));
        assertEquals("read", body.get("action").get("name").asText());
        assertFalse(body.get("action").has("properties"));
    }
}
