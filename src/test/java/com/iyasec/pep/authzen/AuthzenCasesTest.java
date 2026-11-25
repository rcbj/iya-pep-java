// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Json;
import com.iyasec.pep.engine.Assignment;
import com.iyasec.pep.engine.Attribute;
import com.iyasec.pep.engine.AttributeValue;
import com.iyasec.pep.engine.Category;
import com.iyasec.pep.engine.Decision;
import com.iyasec.pep.engine.Names;
import com.iyasec.pep.engine.Obligation;
import com.iyasec.pep.engine.Request;
import com.iyasec.pep.engine.Response;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthzenCasesTest {
    private static final String SUPPLIED = "urn:sts:xacml:authzen:supplied";
    private static final List<String> FIXED = List.of(
            "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
            "urn:sts:xacml:authzen:subject-type",
            "urn:oasis:names:tc:xacml:1.0:action:action-id",
            "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
            "urn:sts:xacml:authzen:resource-type",
            "urn:sts:xacml:protocol",
            "urn:sts:xacml:realm",
            "urn:sts:xacml:authzen:caller",
            "urn:sts:xacml:authzen:application",
            SUPPLIED);

    @Test
    void agreesWithTheSharedAuthzenTable() throws Exception {
        JsonNode table = table();
        List<String> failures = new ArrayList<>();
        int catalogue = runCatalogue(table, failures);
        int requests = runRequests(table, failures);
        int obligations = runObligations(table, failures);
        System.err.println("authzen_cases: catalogue " + catalogue + "/" + table.get("catalogue").size()
                + ", requests " + requests + "/" + table.get("requests").size()
                + ", obligations " + obligations + "/" + table.get("obligations").size()
                + "; binding skipped (token exchange)");
        assertTrue(failures.isEmpty(), failures.size() + " mismatch(es):\n" + String.join("\n", failures));
    }

    @Test
    void handsAStepUpInTheServicesShape() throws Exception {
        Response response = new Response(Decision.PERMIT, List.of(new Obligation(
                "urn:sts:xacml:authzen:obligation:step-up",
                List.of(
                        new Assignment("urn:sts:xacml:authzen:acr_value", null, null, Names.STRING, "urn:acr:loa2"),
                        new Assignment("amr_values", null, null, Names.STRING, "pwd"),
                        new Assignment("amr_values", null, null, Names.STRING, "otp")))),
                List.of(), Names.STATUS_OK);
        Outcome got = Authzen.outcome(response, List.of("step-up"), true);
        assertTrue(got.decision);
        assertFalse(got.fault);
        assertEquals(Json.MAPPER.readTree(
                "{\"id\":\"obligation-1\",\"type\":\"step-up\",\"properties\":{\"acr_value\":\"urn:acr:loa2\",\"amr_values\":[\"pwd\",\"otp\"]}}"),
                got.handed.get(0).obligation);
        Outcome refused = Authzen.outcome(response, List.of("step-up"), false);
        assertFalse(refused.decision);
        assertTrue(refused.handed.isEmpty());
        assertEquals(List.of("urn:sts:xacml:authzen:obligation:step-up"), refused.undischargeable);
    }

    @Test
    void buildsTheRequestTheContainerBuilds() throws Exception {
        Catalogue catalogue = new Catalogue(rows(table()), false, List.of());
        JsonNode body = Json.MAPPER.readTree(
                "{\"subject\":{\"type\":\"user\",\"id\":\"alice\",\"properties\":{\"clearance\":4}},"
                        + "\"action\":{\"name\":\"read\"},\"resource\":{\"type\":\"document\",\"id\":\"doc-1\"},"
                        + "\"context\":{\"application\":\"portal\",\"source_ip\":\"192.0.2.25\"}}");
        Request request = Authzen.mapEvaluation(body, catalogue, trusted()).request;
        assertTrue(request.returnPolicyIdList);
        assertFalse(request.combinedDecision);
        List<String> order = new ArrayList<>();
        for (Category category : request.categories) {
            List<String> ids = new ArrayList<>();
            for (Attribute attribute : category.attributes) {
                ids.add(attribute.attributeId);
            }
            order.add(category.category + " " + ids);
        }
        assertEquals(List.of(
                Names.ACCESS_SUBJECT + " [urn:oasis:names:tc:xacml:1.0:subject:subject-id, urn:sts:xacml:authzen:subject-type, urn:example:clearance]",
                Names.ACTION + " [urn:oasis:names:tc:xacml:1.0:action:action-id]",
                Names.RESOURCE + " [urn:oasis:names:tc:xacml:1.0:resource:resource-id, urn:sts:xacml:authzen:resource-type]",
                Names.ENVIRONMENT + " [urn:sts:xacml:protocol, urn:sts:xacml:realm, urn:sts:xacml:authzen:caller, urn:sts:xacml:authzen:application, "
                        + SUPPLIED + ", urn:example:source-ip]"),
                order);
        List<Attribute> all = new ArrayList<>();
        for (Category category : request.categories) {
            all.addAll(category.attributes);
        }
        assertTrue(all.stream().allMatch(attribute -> attribute.includeInResult && attribute.issuer == null));
        Attribute clearance = all.stream().filter(attribute -> "urn:example:clearance".equals(attribute.attributeId)).findFirst().orElseThrow();
        assertEquals("http://www.w3.org/2001/XMLSchema#integer", clearance.values.get(0).dataType);
        assertEquals("4", clearance.values.get(0).value);

        Trusted bare = new Trusted("", "c", "", false);
        JsonNode small = Json.MAPPER.readTree(
                "{\"subject\":{\"type\":\"user\",\"id\":\"a\"},\"action\":{\"name\":\"r\"},\"resource\":{\"type\":\"d\",\"id\":\"1\"}}");
        Request bareRequest = Authzen.mapEvaluation(small, catalogue, bare).request;
        Category environment = bareRequest.categories.stream()
                .filter(category -> category.category.endsWith(":environment")).findFirst().orElseThrow();
        Attribute realm = environment.attributes.stream()
                .filter(attribute -> "urn:sts:xacml:realm".equals(attribute.attributeId)).findFirst().orElseThrow();
        assertTrue(realm.values.isEmpty());

        JsonNode other = Json.MAPPER.readTree(
                "{\"subject\":{\"type\":\"user\",\"id\":\"a\"},\"action\":{\"name\":\"r\"},"
                        + "\"resource\":{\"type\":\"d\",\"id\":\"1\"},\"context\":{\"application\":\"other\"}}");
        Refusal refusal = assertThrows(Refusal.class, () -> Authzen.mapEvaluation(other, catalogue, trusted()));
        assertEquals(403, refusal.status);
        assertEquals("STS-AUTHZEN-0025", refusal.code);
    }

    @Test
    void readsAPulledCatalogue() throws Exception {
        JsonNode body = Json.MAPPER.readTree(
                "{\"rows\":[{\"object\":\"resource\",\"property\":\"x\",\"attributeId\":\"u:1\"},"
                        + "{\"object\":\"resource\",\"property\":\"x\",\"attributeId\":\"u:2\"},"
                        + "{\"object\":\"subject\",\"property\":\"r\",\"attributeId\":\"urn:sts:xacml:role\"}],"
                        + "\"settings\":{\"obligationsProfile\":true}}");
        Catalogue catalogue = Catalogue.fromPull(body);
        assertEquals(1, catalogue.rows.size());
        assertEquals("u:1", catalogue.rows.get(0).attributeId);
        assertTrue(catalogue.obligationsProfile);
        assertFalse(Catalogue.fromPull(Json.MAPPER.readTree("{\"rows\":[]}")).obligationsProfile);
        assertThrows(Refusal.class, () -> Catalogue.fromPull(Json.object()));
    }

    @Test
    void anFgaApplicationGetsTheServicesTwoFacts() throws Exception {
        Catalogue catalogue = Catalogue.fromPull(Json.MAPPER.readTree(
                "{\"rows\":[],\"settings\":{},\"fgaApplications\":[\"portal\"]}"));
        assertEquals(List.of("portal"), catalogue.fgaApplications);
        JsonNode body = Json.MAPPER.readTree(
                "{\"subject\":{\"type\":\"user\",\"id\":\"alice\"},\"action\":{\"name\":\"read\"},\"resource\":{\"type\":\"doc\",\"id\":\"1\"}}");
        Request plain = Authzen.mapEvaluation(body, catalogue, trusted()).request;
        Request fga = Authzen.mapEvaluation(body, catalogue, new Trusted(trusted().realm, trusted().caller, trusted().application, true)).request;
        assertEquals(null, find(plain, Names.RESOURCE, "urn:sts:xacml:fga:application"));
        assertEquals(List.of("portal"), find(fga, Names.RESOURCE, "urn:sts:xacml:fga:application"));
        assertEquals(List.of("access"), find(fga, Names.ENVIRONMENT, "urn:sts:xacml:fga:stage"));
        Category resource = fga.categories.stream().filter(category -> Names.RESOURCE.equals(category.category)).findFirst().orElseThrow();
        assertEquals("urn:sts:xacml:fga:application", resource.attributes.get(resource.attributes.size() - 1).attributeId);
    }

    private static int runCatalogue(JsonNode table, List<String> failures) {
        int passed = 0;
        for (JsonNode one : table.get("catalogue")) {
            String got;
            try {
                Row.read(one.get("value"));
                got = "";
            } catch (Refusal refusal) {
                got = refusal.code;
            }
            String want = text(one, "code");
            if (got.equals(want)) {
                passed++;
            } else {
                failures.add("catalogue " + what(one) + ": code " + got + ", want " + want);
            }
        }
        return passed;
    }

    private static int runRequests(JsonNode table, List<String> failures) throws Refusal {
        Catalogue catalogue = new Catalogue(rows(table), false, List.of());
        int passed = 0;
        for (JsonNode one : table.get("requests")) {
            int before = failures.size();
            Mapped mapped = null;
            Refusal refusal = null;
            try {
                mapped = Authzen.mapEvaluation(one.get("body"), catalogue, trusted());
            } catch (Refusal caught) {
                refusal = caught;
            }
            String want = text(one, "code");
            if (mapped != null && !want.isEmpty()) {
                failures.add("request " + what(one) + ": accepted, want " + want);
            } else if (refusal != null && !refusal.code.equals(want)) {
                failures.add("request " + what(one) + ": code " + refusal.code + ", want " + want + " (" + refusal.message + ")");
            } else if (refusal != null && refusal.status != 400) {
                failures.add("request " + what(one) + ": status " + refusal.status + ", want 400");
            }
            if (mapped != null) {
                if (one.has("supplied") && !one.get("supplied").isNull()) {
                    ArrayNode got = Json.array();
                    for (String value : suppliedOf(mapped.request)) {
                        got.add(value);
                    }
                    if (!got.equals(one.get("supplied"))) {
                        failures.add("request " + what(one) + ": supplied " + got + ", want " + one.get("supplied"));
                    }
                }
                if (one.has("attributes") && !one.get("attributes").isNull()) {
                    JsonNode got = mappedOf(mapped.request);
                    if (!got.equals(one.get("attributes"))) {
                        failures.add("request " + what(one) + ": attributes " + got + ", want " + one.get("attributes"));
                    }
                }
            }
            if (failures.size() == before) {
                passed++;
            }
        }
        return passed;
    }

    private static int runObligations(JsonNode table, List<String> failures) {
        int passed = 0;
        for (JsonNode one : table.get("obligations")) {
            JsonNode said = one.get("answer");
            List<Obligation> obligations = new ArrayList<>();
            JsonNode list = said.get("obligations");
            if (list != null && list.isArray()) {
                for (JsonNode item : list) {
                    List<Assignment> assignments = new ArrayList<>();
                    JsonNode raw = item.get("assignments");
                    if (raw != null && raw.isArray()) {
                        for (JsonNode assignment : raw) {
                            assignments.add(new Assignment(text(assignment, "attributeId"), null, null, Names.STRING,
                                    text(assignment, "value")));
                        }
                    }
                    obligations.add(new Obligation(text(item, "id"), assignments));
                }
            }
            Response response = new Response(decision(text(said, "decision")), obligations, List.of(), Names.STATUS_OK);
            JsonNode supportedNode = one.get("supported");
            List<String> supported = null;
            if (supportedNode != null && supportedNode.isArray()) {
                supported = new ArrayList<>();
                for (JsonNode item : supportedNode) {
                    supported.add(item.asText());
                }
            }
            boolean profile = one.path("profile").asBoolean(false);
            Outcome got = Authzen.outcome(response, supported, profile);
            JsonNode expect = one.get("expect");
            List<String> handed = new ArrayList<>();
            for (Handed item : got.handed) {
                handed.add(item.kind);
            }
            List<String> wantHanded = new ArrayList<>();
            if (expect.get("handed") != null && expect.get("handed").isArray()) {
                for (JsonNode item : expect.get("handed")) {
                    if (item.isTextual()) {
                        wantHanded.add(item.asText());
                    }
                }
            }
            List<String> wrong = new ArrayList<>();
            if (!expect.path("decision").isBoolean() || got.decision != expect.get("decision").asBoolean()) {
                wrong.add("decision " + got.decision + ", want " + expect.get("decision"));
            }
            if (!handed.equals(wantHanded)) {
                wrong.add("handed " + handed + ", want " + wantHanded);
            }
            if (got.obligationProblems.size() != expect.path("problems").asLong()) {
                wrong.add(got.obligationProblems.size() + " problem(s), want " + expect.get("problems"));
            }
            for (int i = 0; i < got.handed.size(); i++) {
                ObjectNode obligation = got.handed.get(i).obligation;
                boolean shaped = obligation.path("id").asText().equals("obligation-" + (i + 1))
                        && obligation.path("type").asText().equals(got.handed.get(i).kind)
                        && obligation.path("properties").isObject();
                if (!shaped) {
                    wrong.add("handed object " + obligation + " is not {id, type, properties}");
                }
            }
            if (wrong.isEmpty()) {
                passed++;
            } else {
                failures.add("obligations " + what(one) + ": " + String.join("; ", wrong));
            }
        }
        return passed;
    }

    private static List<String> suppliedOf(Request request) {
        List<String> values = new ArrayList<>();
        for (Category category : request.categories) {
            for (Attribute attribute : category.attributes) {
                if (SUPPLIED.equals(attribute.attributeId)) {
                    for (AttributeValue value : attribute.values) {
                        values.add(value.value);
                    }
                }
            }
        }
        return values;
    }

    private static JsonNode mappedOf(Request request) {
        ArrayNode mapped = Json.array();
        for (Category category : request.categories) {
            for (Attribute attribute : category.attributes) {
                if (FIXED.contains(attribute.attributeId)) {
                    continue;
                }
                ObjectNode one = Json.object();
                one.put("attributeId", attribute.attributeId);
                ArrayNode values = Json.array();
                for (AttributeValue value : attribute.values) {
                    values.add(value.value);
                }
                one.set("values", values);
                mapped.add(one);
            }
        }
        return mapped;
    }

    private static List<Row> rows(JsonNode table) throws Refusal {
        List<Row> rows = new ArrayList<>();
        for (JsonNode value : table.get("rows")) {
            rows.add(Row.read(value));
        }
        return rows;
    }

    private static Trusted trusted() {
        return new Trusted("acme", "cn=pep-1,ou=users,dc=acme", "portal", false);
    }

    private static Decision decision(String name) {
        return switch (name) {
            case "Permit" -> Decision.PERMIT;
            case "Deny" -> Decision.DENY;
            case "NotApplicable" -> Decision.NOT_APPLICABLE;
            default -> Decision.INDETERMINATE;
        };
    }

    private static List<String> find(Request request, String category, String id) {
        for (Category one : request.categories) {
            if (!category.equals(one.category)) {
                continue;
            }
            for (Attribute attribute : one.attributes) {
                if (id.equals(attribute.attributeId)) {
                    List<String> values = new ArrayList<>();
                    for (AttributeValue value : attribute.values) {
                        values.add(value.value);
                    }
                    return values;
                }
            }
        }
        return null;
    }

    private static String what(JsonNode one) {
        return text(one, "what").isEmpty() ? "?" : text(one, "what");
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value != null && value.isTextual() ? value.asText() : "";
    }

    private static JsonNode table() throws Exception {
        try (InputStream in = AuthzenCasesTest.class.getResourceAsStream("/authzen/authzen_cases.json")) {
            return Json.MAPPER.readTree(in);
        }
    }
}
