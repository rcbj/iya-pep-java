// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.iyasec.pep.authzen.Authzen;
import com.iyasec.pep.authzen.Outcome;
import com.iyasec.pep.engine.Names;
import com.iyasec.pep.engine.Obligation;
import com.iyasec.pep.engine.Response;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnforcementTest {
    @Test
    void everyRowOfTheTableIsEnforcedDenyBiased() throws Exception {
        JsonNode table = table();
        JsonNode cases = table.get("cases");
        assertEquals(7, cases.size());
        List<String> wrong = new ArrayList<>();
        for (int i = 0; i < cases.size(); i++) {
            JsonNode one = cases.get(i);
            String status = "Indeterminate".equals(one.get("decision").asText())
                    ? "urn:oasis:names:tc:xacml:1.0:status:missing-attribute"
                    : Names.STATUS_OK;
            Response response = new Response(decision(one.get("decision").asText()), obligations(one.get("obligations")),
                    List.of(), status);
            Outcome got = Authzen.outcome(response, null, false);
            if (got.decision != one.get("deny-biased").asBoolean()) {
                wrong.add("case " + i + " (" + one + "): allowed " + got.decision);
            }
        }
        assertTrue(wrong.isEmpty(), String.join("\n", wrong));
    }

    @Test
    void onlyAProcessingOrSyntaxErrorIsAFault() {
        Outcome missing = Authzen.outcome(indeterminate("urn:oasis:names:tc:xacml:1.0:status:missing-attribute"), null, false);
        assertFalse(missing.decision);
        assertFalse(missing.fault);
        for (String status : List.of(
                "urn:oasis:names:tc:xacml:1.0:status:processing-error",
                "urn:oasis:names:tc:xacml:1.0:status:syntax-error")) {
            Outcome got = Authzen.outcome(indeterminate(status), null, false);
            assertFalse(got.decision, status);
            assertTrue(got.fault, status);
        }
    }

    private static Response indeterminate(String status) {
        return new Response(com.iyasec.pep.engine.Decision.INDETERMINATE, List.of(), List.of(), status);
    }

    private static com.iyasec.pep.engine.Decision decision(String name) {
        return switch (name) {
            case "Permit" -> com.iyasec.pep.engine.Decision.PERMIT;
            case "Deny" -> com.iyasec.pep.engine.Decision.DENY;
            case "NotApplicable" -> com.iyasec.pep.engine.Decision.NOT_APPLICABLE;
            default -> com.iyasec.pep.engine.Decision.INDETERMINATE;
        };
    }

    private static List<Obligation> obligations(JsonNode list) {
        List<Obligation> obligations = new ArrayList<>();
        if (list != null && list.isArray()) {
            for (JsonNode item : list) {
                obligations.add(new Obligation(item.asText(), List.of()));
            }
        }
        return obligations;
    }

    private static JsonNode table() throws Exception {
        try (InputStream in = EnforcementTest.class.getResourceAsStream("/corpus/enforcement.json")) {
            return Json.MAPPER.readTree(in);
        }
    }
}
