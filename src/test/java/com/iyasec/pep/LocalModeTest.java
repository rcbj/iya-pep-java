// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.engine.Names;
import com.iyasec.pep.support.Keys;
import com.iyasec.pep.support.Seen;
import com.iyasec.pep.support.Stub;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalModeTest {
    private static final String ACTION = "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
    private static final String SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";

    @Test
    void nothingIsPermittedBeforeTheFirstPull() throws Exception {
        try (Stub stub = stub()) {
            Pep pep = Pep.create(config(stub, "l-before"));
            try {
                Decision decision = pep.decide(alice(null), on("read"));
                assertEquals(Decision.Kind.UNAVAILABLE, decision.kind());
                assertTrue(decision.why().contains("no policy"), decision.why());
                assertEquals(0, stub.count("/access/v1/evaluation"));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void aPermitAndADenyAreDecidedInProcessAndRecorded() throws Exception {
        try (Stub stub = stub()) {
            Pep pep = Pep.create(config(stub, "l-decide"));
            try {
                pep.start();
                Seen pull = stub.seen("/xacml/pep/policies").get(0);
                assertTrue(pull.query.contains("scope=bound-application"), pull.query);
                assertTrue(pull.query.contains("pep=" + Stub.NAME), pull.query);
                assertEquals(1, stub.seen("/oauth2/token").stream().filter(grant -> "xacml:pep".equals(grant.form("scope"))).count());
                assertTrue(pep.decide(alice(null), on("read")).isPermit());
                assertEquals(Decision.Kind.DENY, pep.decide(alice(null), on("write")).kind());
                assertEquals(0, stub.count("/access/v1/evaluation"));
                Status status = pep.status();
                assertTrue(status.holdsPolicy);
                assertEquals(1, status.policyCount);
                assertEquals("p1", status.syncToken);
            } finally {
                pep.close();
            }
            List<Seen> pushes = stub.seen("/admin-api/pep-audit");
            assertEquals(1, pushes.size());
            JsonNode events = pushes.get(0).json().get("events");
            assertEquals(2, events.size());
            assertEquals(1, events.get(0).get("seq").asInt());
            assertEquals("authzen", events.get(0).get("kind").asText());
            assertTrue(events.get(0).get("allowed").asBoolean());
            assertFalse(events.get(1).get("allowed").asBoolean());
            assertEquals(Stub.APP, events.get(0).get("application").asText());
            assertNull(pushes.get(0).form("scope"));
            assertTrue(stub.seen("/oauth2/token").stream().anyMatch(grant -> "xacml:pep-audit".equals(grant.form("scope"))));
            assertEquals(0, pep.status().recordsQueued);
        }
    }

    @Test
    void aClaimReachesThePolicyThroughTheCatalogue() throws Exception {
        try (Stub stub = stub()) {
            Pep pep = Pep.create(config(stub, "l-claim"));
            try {
                pep.pullNow();
                assertTrue(pep.decide(alice("urn:example:mfa"), on("update")).isPermit());
                assertFalse(pep.decide(alice("urn:example:pwd"), on("update")).isPermit());
                assertFalse(pep.decide(alice(null), on("update")).isPermit());
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void thePipIsAskedOnceForWhatTheRequestDoesNotCarry() throws Exception {
        try (Stub stub = stub()) {
            synchronized (stub.script) {
                stub.script.pipAnswer = "<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\"><Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\""
                        + SUBJECT + "\"><Attribute AttributeId=\"urn:example:dept\" IncludeInResult=\"false\"><AttributeValue DataType=\""
                        + Names.STRING + "\">eng</AttributeValue></Attribute></Attributes></PIPResponse>";
            }
            Pep pep = Pep.create(config(stub, "l-pip"));
            try {
                pep.pullNow();
                assertTrue(pep.decide(alice("urn:example:mfa"), on("delete")).isPermit());
                List<Seen> queries = stub.seen("/xacml/pip");
                assertEquals(1, queries.size());
                assertTrue(queries.get(0).body.contains(">alice<"), queries.get(0).body);
                assertTrue(queries.get(0).body.contains("urn:example:dept"), queries.get(0).body);
                assertFalse(queries.get(0).body.contains("AttributeId=\"urn:example:acr\" DataType"), queries.get(0).body);
                synchronized (stub.script) {
                    stub.script.pipAnswer = "";
                }
                assertFalse(pep.decide(alice(null), on("delete")).isPermit());
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void aSecondPullSendsTheTokensAndKeepsTheSetOn304() throws Exception {
        try (Stub stub = stub()) {
            Pep pep = Pep.create(config(stub, "l-304"));
            try {
                pep.pullNow();
                pep.pullNow();
                List<Seen> pulls = stub.seen("/xacml/pep/policies");
                assertEquals(2, pulls.size());
                assertNull(pulls.get(0).header("If-None-Match"));
                assertEquals("\"p1\"", pulls.get(1).header("If-None-Match"));
                assertEquals("\"c1\"", stub.seen("/xacml/pep/authzen-catalogue").get(1).header("If-None-Match"));
                assertTrue(pep.decide(alice(null), on("read")).isPermit());
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void theEventMakesThePepPullWithItsOwnToken() throws Exception {
        try (Stub stub = stub()) {
            PepConfig configuration = config(stub, "l-event");
            configuration.signals = true;
            Pep pep = Pep.create(configuration);
            try {
                pep.setEventStream(EventStream.REQUESTED);
                pep.start();
                assertTrue(pep.decide(alice(null), on("read")).isPermit());
                synchronized (stub.script) {
                    stub.script.policies.clear();
                    stub.script.policies.add(ordersPolicy(false));
                    stub.script.policyToken = "p2";
                }
                int before = stub.count("/xacml/pep/policies");
                assertFalse(pep.onPolicyEvent(Json.MAPPER.readTree(
                        "{\"pep\":\"another-pep\",\"changed\":[\"policies\"],\"sync_token\":\"p2\"}")));
                sleep(1500);
                assertEquals(before, stub.count("/xacml/pep/policies"));
                assertTrue(pep.onPolicyEvent(Json.MAPPER.readTree(
                        "{\"pep\":\"" + Stub.NAME + "\",\"changed\":[\"policies\"],\"sync_token\":\"forged-token\"}")));
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> !pep.decide(alice(null), on("read")).isPermit()));
                assertEquals("p2", pep.status().syncToken);
                Seen pull = stub.seen("/xacml/pep/policies").get(stub.count("/xacml/pep/policies") - 1);
                assertTrue(pull.header("Authorization").startsWith("DPoP tok-xacml:pep-"), pull.header("Authorization"));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void withoutASignalStreamThePepPolls() throws Exception {
        try (Stub stub = stub()) {
            PepConfig configuration = config(stub, "l-poll");
            configuration.pollIntervalMs = 1000;
            Pep pep = Pep.create(configuration);
            try {
                pep.start();
                assertTrue(pep.decide(alice(null), on("read")).isPermit());
                synchronized (stub.script) {
                    stub.script.policies.clear();
                    stub.script.policies.add(ordersPolicy(false));
                    stub.script.policyToken = "p2";
                }
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> !pep.decide(alice(null), on("read")).isPermit()));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void withAStreamItWaitsForTheEventOrAHeartbeatSayingItIsStale() throws Exception {
        try (Stub stub = stub()) {
            PepConfig configuration = config(stub, "l-stale");
            configuration.signals = true;
            configuration.pollIntervalMs = 1000;
            Pep pep = Pep.create(configuration);
            try {
                pep.setEventStream(EventStream.REQUESTED);
                pep.start();
                synchronized (stub.script) {
                    stub.script.policies.clear();
                    stub.script.policies.add(ordersPolicy(false));
                    stub.script.policyToken = "p2";
                }
                sleep(2500);
                assertTrue(pep.decide(alice(null), on("read")).isPermit());
                synchronized (stub.script) {
                    stub.script.heartbeatCurrent = false;
                }
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> !pep.decide(alice(null), on("read")).isPermit()));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void aSetThatDoesNotCompileKeepsTheOneHeld() throws Exception {
        try (Stub stub = stub()) {
            Pep pep = Pep.create(config(stub, "l-broken"));
            try {
                pep.pullNow();
                synchronized (stub.script) {
                    ObjectNode broken = (ObjectNode) ordersPolicy(false);
                    broken.put("document", "<Policy this is not xml");
                    stub.script.policies.clear();
                    stub.script.policies.add(broken);
                    stub.script.policyToken = "p3";
                }
                PepException err = assertThrows(PepException.class, pep::pullNow);
                assertEquals("policy", err.code());
                assertTrue(pep.decide(alice(null), on("read")).isPermit());
                assertEquals("p1", pep.status().syncToken);
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void theHeartbeatReportsWhatIsHeldAndTheStream() throws Exception {
        try (Stub stub = stub()) {
            PepConfig configuration = config(stub, "l-beat");
            configuration.signals = true;
            Pep pep = Pep.create(configuration);
            try {
                pep.setEventStream(EventStream.REQUESTED);
                pep.start();
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> seen.count("/xacml/pep/heartbeat") >= 1));
                JsonNode beat = stub.seen("/xacml/pep/heartbeat").get(0).json();
                assertEquals("local", beat.get("mode").asText());
                assertEquals("p1", beat.get("syncToken").asText());
                assertEquals(1, beat.get("policyCount").asInt());
                assertEquals("requested", beat.get("policyEvents").asText());
                pep.setEventStream(EventStream.EXCLUDED);
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen ->
                        "excluded".equals(seen.seen("/xacml/pep/heartbeat").get(seen.count("/xacml/pep/heartbeat") - 1).json().get("policyEvents").asText())));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void theStatusReportsTimesCountersAndWhatIsHeld() throws Exception {
        try (Stub stub = stub()) {
            PepConfig configuration = config(stub, "l-status");
            configuration.signals = true;
            configuration.fallbackPollMs = 60_000;
            Pep pep = Pep.create(configuration);
            try {
                pep.setEventStream(EventStream.REQUESTED);
                Status before = pep.status();
                assertNull(before.uptime);
                assertNull(before.sinceLastPull);
                assertNull(before.untilNextPull);
                pep.start();
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> {
                    Status status = pep.status();
                    return status.untilNextPull != null && status.sinceLastHeartbeat != null;
                }));
                pep.decide(alice(null), on("read"));
                pep.decide(alice(null), on("write"));
                pep.onPolicyEvent(Json.MAPPER.readTree("{\"pep\":\"another-pep\"}"));
                pep.onPolicyEvent(Json.MAPPER.readTree("{\"pep\":\"" + Stub.NAME + "\"}"));
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> pep.status().pulls >= 2));
                Status status = pep.status();
                assertNotNull(status.uptime);
                assertEquals(1, status.policyCount);
                assertEquals(2, status.decisions);
                assertEquals(1, status.allowed);
                assertEquals(1, status.refused);
                assertEquals(1, status.pullsChanged);
                assertEquals(0, status.pullFailures);
                assertNotNull(status.sincePolicyUpdate);
                assertNotNull(status.sinceLastPull);
                assertTrue(status.sinceLastPull <= status.sincePolicyUpdate);
                assertTrue(status.untilNextPull <= 60_000 && status.untilNextPull > 50_000, "next " + status.untilNextPull);
                assertTrue(status.untilNextHeartbeat <= 1000, "heartbeat " + status.untilNextHeartbeat);
                assertTrue(status.heartbeats >= 1);
                assertEquals(1, status.registrations);
                assertEquals(1, status.eventsReceived);
                assertEquals(1, status.eventsIgnored);
                assertNotNull(status.sinceLastEvent);
                assertEquals("c1", status.catalogueToken);
                assertEquals(1, status.catalogueSubjectProperties);
                assertEquals(EventStream.REQUESTED, status.eventStream);
                assertTrue(status.maxDecisionMicros >= status.meanDecisionMicros && status.meanDecisionMicros > 0);
                assertEquals(stub.base, status.pdpUrl);
            } finally {
                pep.close();
            }
            assertNull(pep.status().untilNextPull);
        }
    }

    @Test
    void theCallerFactIsTheDnTheRegistrationNamed() throws Exception {
        try (Stub stub = stub()) {
            synchronized (stub.script) {
                stub.script.policies.clear();
                stub.script.policies.add(callerPolicy(Stub.IDENTITY));
            }
            Pep unregistered = Pep.create(config(stub, "l-caller-name"));
            Pep pep = Pep.create(config(stub, "l-caller-dn"));
            try {
                unregistered.pullNow();
                assertFalse(unregistered.decide(alice(null), on("who")).isPermit());
                pep.start();
                assertTrue(pep.status().registered);
                assertTrue(pep.decide(alice(null), on("who")).isPermit());
                synchronized (stub.script) {
                    stub.script.policies.clear();
                    stub.script.policies.add(callerPolicy(Stub.NAME));
                    stub.script.policyToken = "p-name";
                }
                unregistered.pullNow();
                assertTrue(unregistered.decide(alice(null), on("who")).isPermit());
            } finally {
                pep.close();
                unregistered.close();
            }
        }
    }

    @Test
    void aStreamThatIsDownOrNotYetReportedMeansPolling() throws Exception {
        try (Stub stub = stub()) {
            PepConfig configuration = config(stub, "l-down");
            configuration.signals = true;
            configuration.pollIntervalMs = 1000;
            Pep pep = Pep.create(configuration);
            try {
                assertEquals(EventStream.DOWN, pep.status().eventStream);
                pep.start();
                assertTrue(pep.decide(alice(null), on("read")).isPermit());
                synchronized (stub.script) {
                    stub.script.policies.clear();
                    stub.script.policies.add(ordersPolicy(false));
                    stub.script.policyToken = "p2";
                }
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> !pep.decide(alice(null), on("read")).isPermit()));
                pep.setEventStream(EventStream.REQUESTED);
                sleep(1500);
                assertTrue(pep.status().untilNextPull > 10_000, "next " + pep.status().untilNextPull);
                pep.setEventStream(EventStream.DOWN);
                sleep(1500);
                assertTrue(pep.status().untilNextPull <= 1000, "next " + pep.status().untilNextPull);
                assertTrue(stub.seen("/xacml/pep/heartbeat").stream()
                        .anyMatch(seen -> "down".equals(seen.json().get("policyEvents").asText())));
            } finally {
                pep.close();
            }
        }
    }

    private static Stub stub() {
        Stub stub = Stub.start();
        synchronized (stub.script) {
            stub.script.policies.add(ordersPolicy(true));
            stub.script.catalogueRows.add(Json.MAPPER.createObjectNode()
                    .put("object", "subject").put("property", "acr").put("attributeId", "urn:example:acr"));
        }
        return stub;
    }

    private static PepConfig config(Stub stub, String tag) {
        PepConfig configuration = new PepConfig(Stub.NAME, Mode.LOCAL, Keys.keyFile(tag), stub.base, Stub.APP);
        configuration.heartbeatIntervalMs = 1000;
        return configuration;
    }

    private static Subject alice(String acr) {
        Map<String, JsonNode> claims = new LinkedHashMap<>();
        if (acr != null) {
            claims.put("acr", Json.text(acr));
        }
        return Subject.user("alice", claims);
    }

    private static Access on(String action) {
        return Access.of(action, "order", "42");
    }

    private static String actionIs(String name) {
        return "<Target><AnyOf><AllOf><Match MatchId=\"urn:oasis:names:tc:xacml:1.0:function:string-equal\"><AttributeValue DataType=\""
                + Names.STRING + "\">" + name + "</AttributeValue><AttributeDesignator Category=\"" + ACTION
                + "\" AttributeId=\"urn:oasis:names:tc:xacml:1.0:action:action-id\" DataType=\"" + Names.STRING
                + "\" MustBePresent=\"false\"/></Match></AllOf></AnyOf></Target>";
    }

    private static String subjectHas(String attribute, String value) {
        return "<Condition><Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:string-is-in\"><AttributeValue DataType=\""
                + Names.STRING + "\">" + value + "</AttributeValue><AttributeDesignator Category=\"" + SUBJECT
                + "\" AttributeId=\"" + attribute + "\" DataType=\"" + Names.STRING
                + "\" MustBePresent=\"false\"/></Apply></Condition>";
    }

    private static JsonNode ordersPolicy(boolean readAllowed) {
        String read = readAllowed ? "<Rule RuleId=\"read\" Effect=\"Permit\">" + actionIs("read") + "</Rule>" : "";
        String document = "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"orders\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit\"><Target/>"
                + read
                + "<Rule RuleId=\"delete\" Effect=\"Permit\">" + actionIs("delete") + subjectHas("urn:example:dept", "eng") + "</Rule>"
                + "<Rule RuleId=\"update\" Effect=\"Permit\">" + actionIs("update") + subjectHas("urn:example:acr", "urn:example:mfa") + "</Rule></Policy>";
        ObjectNode node = Json.object();
        node.put("name", "orders");
        node.put("policyId", "orders");
        node.put("kind", "Policy");
        node.put("version", "1.0");
        node.put("combiningAlgId", "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit");
        node.put("isRoot", true);
        node.put("description", "");
        node.put("document", document);
        return node;
    }

    private static JsonNode callerPolicy(String caller) {
        String environment = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment";
        String document = "<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"caller\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit\"><Target/><Rule RuleId=\"who\" Effect=\"Permit\">"
                + actionIs("who")
                + "<Condition><Apply FunctionId=\"urn:oasis:names:tc:xacml:1.0:function:string-is-in\"><AttributeValue DataType=\""
                + Names.STRING + "\">" + caller + "</AttributeValue><AttributeDesignator Category=\"" + environment
                + "\" AttributeId=\"urn:sts:xacml:authzen:caller\" DataType=\"" + Names.STRING
                + "\" MustBePresent=\"false\"/></Apply></Condition></Rule></Policy>";
        ObjectNode node = Json.object();
        node.put("name", "caller");
        node.put("policyId", "caller");
        node.put("kind", "Policy");
        node.put("version", "1.0");
        node.put("combiningAlgId", "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit");
        node.put("isRoot", true);
        node.put("description", "");
        node.put("document", document);
        return node;
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
