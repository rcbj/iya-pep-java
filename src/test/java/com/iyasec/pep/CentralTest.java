// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.key.SigningKey;
import com.iyasec.pep.support.Keys;
import com.iyasec.pep.support.Script;
import com.iyasec.pep.support.Seen;
import com.iyasec.pep.support.Stub;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CentralTest {
    @Test
    void theGrantIsADpopBoundSelfAssertionPerAudienceWithOneNonceRetry() throws Exception {
        try (Stub stub = Stub.start()) {
            synchronized (stub.script) {
                stub.script.tokenNonceFirst = true;
            }
            Pep pep = Pep.create(config(stub, "grant"));
            try {
                assertTrue(pep.decide(alice(), read42()).isPermit());
                List<Seen> grants = stub.seen("/oauth2/token");
                assertEquals(2, grants.size());
                assertNull(grants.get(0).proof().get("nonce"));
                assertEquals("n-token", grants.get(1).proof().get("nonce").asText());
                Seen grant = grants.get(1);
                assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", grant.form("grant_type"));
                assertEquals("sts-remote-pep", grant.form("client_id"));
                assertEquals("authzen:evaluate", grant.form("scope"));
                assertEquals(stub.base + "/access/v1", grant.form("resource"));
                JsonNode assertion = Seen.claims(grant.form("assertion"));
                assertEquals(Stub.NAME, assertion.get("iss").asText());
                assertEquals(Stub.NAME, assertion.get("sub").asText());
                assertEquals(stub.base + "/oauth2/token", assertion.get("aud").asText());
                assertTrue(assertion.get("exp").asLong() > assertion.get("iat").asLong());
                assertEquals(pep.keyThumbprint(), SigningKey.jwkThumbprint(grants.get(1).proofHeader().get("jwk")));
                Seen evaluation = stub.seen("/access/v1/evaluation").get(0);
                assertEquals("DPoP tok-authzen:evaluate-1", evaluation.header("Authorization"));
                JsonNode proof = evaluation.proof();
                assertEquals("POST", proof.get("htm").asText());
                assertEquals(stub.base + "/access/v1/evaluation", proof.get("htu").asText());
                assertTrue(proof.get("ath").isTextual());
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void theEvaluationCarriesTheBoundApplicationAndTheSubjectsClaims() throws Exception {
        try (Stub stub = Stub.start()) {
            PepConfig configuration = config(stub, "body");
            configuration.supportedObligations = List.of("step-up");
            synchronized (stub.script) {
                stub.script.catalogueRows.add(Json.MAPPER.readTree(
                        "{\"object\":\"subject\",\"property\":\"acr\",\"attributeId\":\"urn:example:acr\"}"));
            }
            Pep pep = Pep.create(configuration);
            try {
                pep.pullNow();
                Access access = read42();
                access.context.put("application", Json.text("another-app"));
                Subject subject = alice();
                subject.properties.put("email", Json.text("alice@example.com"));
                pep.decide(subject, access);
                JsonNode body = stub.seen("/access/v1/evaluation").get(0).json();
                assertEquals(Json.MAPPER.readTree(
                        "{\"type\":\"user\",\"id\":\"alice\",\"properties\":{\"acr\":\"urn:example:mfa\"}}"), body.get("subject"));
                String authorization = stub.seen("/xacml/pep/authzen-catalogue").get(0).header("Authorization");
                assertTrue(authorization != null && authorization.startsWith("DPoP "));
                pep.pullNow();
                assertEquals("\"c1\"", stub.seen("/xacml/pep/authzen-catalogue").get(1).header("If-None-Match"));
                assertEquals(Json.MAPPER.readTree("{\"name\":\"read\"}"), body.get("action"));
                assertEquals(Json.MAPPER.readTree("{\"type\":\"order\",\"id\":\"42\"}"), body.get("resource"));
                assertEquals(Stub.APP, body.get("context").get("application").asText());
                assertEquals(Json.strings(List.of("step-up")), body.get("context").get("supported_obligations"));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void permitDenyObligationsAndFailingClosed() throws Exception {
        try (Stub stub = Stub.start()) {
            synchronized (stub.script) {
                stub.script.evaluations.add(scripted(200, Json.MAPPER.readTree(
                        "{\"decision\":true,\"context\":{\"obligations\":[{\"id\":\"o1\",\"type\":\"step-up\",\"properties\":{\"acr_value\":\"phr\"}}]}}")));
                stub.script.evaluations.add(scripted(200, Json.MAPPER.readTree(
                        "{\"decision\":false,\"context\":{\"reason_admin\":{\"en\":\"not the owner\"}}}")));
                stub.script.evaluations.add(scripted(500, Json.MAPPER.readTree("{\"error\":\"server_error\"}")));
                stub.script.evaluations.add(scripted(400, Json.MAPPER.readTree(
                        "{\"error\":\"invalid_request\",\"error_description\":\"no resource.type\"}")));
            }
            Pep pep = Pep.create(config(stub, "answers"));
            try {
                Decision permit = pep.decide(alice(), read42());
                assertEquals(Decision.Kind.PERMIT, permit.kind());
                assertEquals(1, permit.obligations().size());
                assertEquals("step-up", permit.obligations().get(0).kind);
                assertEquals("phr", permit.obligations().get(0).properties.get("acr_value").asText());
                assertTrue(permit.advice().isEmpty());
                assertEquals(Decision.deny("not the owner"), pep.decide(alice(), read42()));
                assertEquals(Decision.Kind.UNAVAILABLE, pep.decide(alice(), read42()).kind());
                Decision refused = pep.decide(alice(), read42());
                assertEquals(Decision.Kind.DENY, refused.kind());
                assertTrue(refused.why().contains("no resource.type"), refused.why());
            } finally {
                pep.close();
            }
            PepConfig gone = config(stub, "gone");
            gone.pdpUrl = "http://127.0.0.1:9/realm/r1";
            gone.timeoutMs = 500;
            Pep missing = Pep.create(gone);
            try {
                assertEquals(Decision.Kind.UNAVAILABLE, missing.decide(alice(), read42()).kind());
                Status status = missing.status();
                assertEquals(1, status.decisions);
                assertEquals(1, status.unavailable);
            } finally {
                missing.close();
            }
        }
    }

    @Test
    void aRefusedTokenIsReplacedOnceAndOnlyOnce() throws Exception {
        try (Stub stub = Stub.start()) {
            List<String[]> invalid = List.<String[]>of(new String[] {"WWW-Authenticate", "DPoP error=\"invalid_token\""});
            synchronized (stub.script) {
                stub.script.evaluations.add(new Script.Scripted(401, Json.MAPPER.readTree("{\"error\":\"invalid_token\"}"), invalid));
            }
            Pep pep = Pep.create(config(stub, "replace"));
            try {
                assertTrue(pep.decide(alice(), read42()).isPermit());
                List<Seen> calls = stub.seen("/access/v1/evaluation");
                assertEquals(2, calls.size());
                assertNotEquals(calls.get(0).header("Authorization"), calls.get(1).header("Authorization"));
                assertEquals(2, stub.count("/oauth2/token"));
                synchronized (stub.script) {
                    stub.script.evaluations.add(new Script.Scripted(401, Json.MAPPER.readTree("{\"error\":\"invalid_token\"}"), invalid));
                    stub.script.evaluations.add(new Script.Scripted(401, Json.MAPPER.readTree("{\"error\":\"invalid_token\"}"), invalid));
                }
                assertEquals(Decision.Kind.UNAVAILABLE, pep.decide(alice(), read42()).kind());
                assertEquals(4, stub.count("/access/v1/evaluation"));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void aResourceNonceDemandIsAnsweredOnce() throws Exception {
        try (Stub stub = Stub.start()) {
            synchronized (stub.script) {
                stub.script.evaluations.add(new Script.Scripted(401, Json.MAPPER.readTree("{\"error\":\"use_dpop_nonce\"}"), List.of(
                        new String[] {"WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""},
                        new String[] {"DPoP-Nonce", "n-res"})));
            }
            Pep pep = Pep.create(config(stub, "rnonce"));
            try {
                assertTrue(pep.decide(alice(), read42()).isPermit());
                List<Seen> calls = stub.seen("/access/v1/evaluation");
                assertEquals(2, calls.size());
                assertEquals("n-res", calls.get(1).proof().get("nonce").asText());
                assertEquals(calls.get(0).header("Authorization"), calls.get(1).header("Authorization"));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void aRefusedGrantIsUnavailableAndNotAskedAgainAtOnce() throws Exception {
        try (Stub stub = Stub.start()) {
            synchronized (stub.script) {
                stub.script.tokenRefused = true;
            }
            Pep pep = Pep.create(config(stub, "refused"));
            try {
                Decision first = pep.decide(alice(), read42());
                assertEquals(Decision.Kind.UNAVAILABLE, first.kind());
                assertTrue(first.why().contains("invalid_grant"), first.why());
                assertEquals(Decision.Kind.UNAVAILABLE, pep.decide(alice(), read42()).kind());
                assertEquals(1, stub.count("/oauth2/token"));
                assertEquals(0, stub.count("/access/v1/evaluation"));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void thePermitCacheIsShortAndClearedByTheEvent() throws Exception {
        try (Stub stub = Stub.start()) {
            PepConfig configuration = config(stub, "cache");
            configuration.permitCacheMs = 30_000;
            Pep pep = Pep.create(configuration);
            try {
                assertTrue(pep.decide(alice(), read42()).isPermit());
                assertTrue(pep.decide(alice(), read42()).isPermit());
                assertEquals(1, stub.count("/access/v1/evaluation"));
                assertEquals(1, pep.status().permitCacheHits);
                assertEquals(1, pep.status().permitCacheEntries);
                assertTrue(pep.decide(alice(), Access.of("write", "order", "42")).isPermit());
                assertEquals(2, stub.count("/access/v1/evaluation"));
                assertFalse(pep.onPolicyEvent(Json.MAPPER.readTree("{\"pep\":\"someone-else\",\"changed\":[\"policies\"]}")));
                pep.decide(alice(), read42());
                assertEquals(2, stub.count("/access/v1/evaluation"));
                assertTrue(pep.onPolicyEvent(Json.MAPPER.readTree(
                        "{\"pep\":\"" + Stub.NAME + "\",\"changed\":[\"policies\"],\"sync_token\":\"t2\"}")));
                pep.decide(alice(), read42());
                assertEquals(3, stub.count("/access/v1/evaluation"));
                synchronized (stub.script) {
                    stub.script.evaluationStatus = 200;
                    stub.script.evaluationBody = Json.MAPPER.readTree("{\"decision\":false}");
                }
                pep.onPolicyEvent(Json.MAPPER.readTree("{\"pep\":\"" + Stub.NAME + "\"}"));
                assertFalse(pep.decide(alice(), read42()).isPermit());
                assertFalse(pep.decide(alice(), read42()).isPermit());
                assertEquals(5, stub.count("/access/v1/evaluation"));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void startRegistersAsEmbeddedAndTheHeartbeatReports() throws Exception {
        try (Stub stub = Stub.start()) {
            Pep pep = Pep.create(config(stub, "register"));
            try {
                pep.start();
                List<Seen> register = stub.seen("/xacml/pep/register");
                assertEquals(1, register.size());
                JsonNode body = register.get(0).json();
                assertEquals("embedded", body.get("kind").asText());
                assertEquals(Stub.APP, body.get("application").asText());
                assertEquals("central", body.get("mode").asText());
                assertEquals(Pep.PROTOCOL_VERSION, body.get("protocolVersion").asInt());
                assertEquals(Stub.NAME, body.get("name").asText());
                assertEquals("xacml:pep", stub.seen("/oauth2/token").get(0).form("scope"));
                assertTrue(pep.status().registered);
                assertTrue(stub.waitUntil(Duration.ofSeconds(5), seen -> seen.count("/xacml/pep/heartbeat") >= 1));
                JsonNode beat = stub.seen("/xacml/pep/heartbeat").get(0).json();
                assertEquals("embedded", beat.get("kind").asText());
                assertEquals("none", beat.get("policyEvents").asText());
                assertTrue(beat.get("decisions").isNumber());
                synchronized (stub.script) {
                    stub.script.heartbeatStatus = 404;
                }
                assertTrue(stub.waitUntil(Duration.ofSeconds(6), seen -> seen.count("/xacml/pep/register") >= 2));
            } finally {
                pep.close();
            }
            assertFalse(pep.status().running);
        }
    }

    @Test
    void aRegistrationTheServiceRefusesIsRetriedAndOnTheStatus() throws Exception {
        try (Stub stub = Stub.start()) {
            synchronized (stub.script) {
                stub.script.registerStatus = 403;
            }
            Pep pep = Pep.create(config(stub, "regfail"));
            try {
                pep.start();
                assertFalse(pep.status().registered);
                assertTrue(pep.status().lastError.contains("403"), pep.status().lastError);
                sleep(3500);
                int tries = stub.count("/xacml/pep/register");
                assertTrue(tries >= 2 && tries <= 3, "tries " + tries);
                synchronized (stub.script) {
                    stub.script.registerStatus = 201;
                }
                assertTrue(stub.waitUntil(Duration.ofSeconds(6), seen -> pep.status().registered));
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void aChangedKeyFileDropsTheTokensAndABadOneIsRefusedAtStart() throws Exception {
        try (Stub stub = Stub.start()) {
            PepConfig configuration = config(stub, "rekey");
            Pep pep = Pep.create(configuration);
            try {
                String before = pep.keyThumbprint();
                pep.decide(alice(), read42());
                sleep(20);
                Files.writeString(Path.of(configuration.assertionKey), Keys.ecPem((byte) 3));
                assertTrue(pep.reloadKey());
                assertNotEquals(before, pep.keyThumbprint());
                pep.decide(alice(), read42());
                List<Seen> grants = stub.seen("/oauth2/token");
                assertEquals(2, grants.size());
                assertEquals(pep.keyThumbprint(), SigningKey.jwkThumbprint(grants.get(1).proofHeader().get("jwk")));
                assertFalse(pep.reloadKey());
            } finally {
                pep.close();
            }
            Path bad = Path.of(System.getProperty("java.io.tmpdir"), "iya-pep-bad-" + ProcessHandle.current().pid() + ".pem");
            Files.writeString(bad, "not a key");
            PepConfig refused = config(stub, "bad-unused");
            refused.assertionKey = bad.toString();
            PepException err = assertThrows(PepException.class, () -> Pep.create(refused));
            assertEquals("config", err.code());
        }
    }

    @Test
    void aConfigurationFromJsonRuns() throws Exception {
        try (Stub stub = Stub.start()) {
            ObjectNode section = Json.object();
            section.put("name", Stub.NAME);
            section.put("assertionKey", Keys.keyFile("json"));
            section.put("mode", "central");
            section.put("permitCacheMs", 1000);
            Pep pep = Pep.create(PepConfig.fromJson(section, stub.base, Stub.APP));
            try {
                assertTrue(pep.decide(alice(), read42()).isPermit());
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void adviceInTheAnswersContextIsHandedAsLocalHandsIt() throws Exception {
        try (Stub stub = Stub.start()) {
            synchronized (stub.script) {
                stub.script.evaluations.add(scripted(200, Json.MAPPER.readTree(
                        "{\"decision\":true,\"context\":{\"xacml_decision\":\"Permit\",\"advice\":[{\"id\":\"urn:example:advice:banner\",\"attributes\":["
                                + "{\"id\":\"urn:example:text\",\"value\":\"be careful\"},"
                                + "{\"id\":\"urn:example:tag\",\"value\":\"a\"},"
                                + "{\"id\":\"urn:example:tag\",\"value\":\"b\"},"
                                + "{\"id\":\"urn:example:count\",\"value\":3}]}]}}")));
            }
            Pep pep = Pep.create(config(stub, "advice"));
            try {
                Decision permit = pep.decide(alice(), read42());
                assertEquals(Decision.Kind.PERMIT, permit.kind());
                assertTrue(permit.obligations().isEmpty());
                assertEquals(1, permit.advice().size());
                Obligation advice = permit.advice().get(0);
                assertEquals("urn:example:advice:banner", advice.id);
                assertEquals("urn:example:advice:banner", advice.kind);
                assertEquals("be careful", advice.properties.get("urn:example:text").asText());
                assertEquals(Json.MAPPER.readTree("[\"a\",\"b\"]"), advice.properties.get("urn:example:tag"));
                assertEquals("3", advice.properties.get("urn:example:count").asText());
            } finally {
                pep.close();
            }
        }
    }

    @Test
    void localIsTheDefaultMode() throws Exception {
        try (Stub stub = Stub.start()) {
            ObjectNode section = Json.object();
            section.put("name", Stub.NAME);
            section.put("assertionKey", Keys.keyFile("json-default"));
            PepConfig read = PepConfig.fromJson(section, stub.base, Stub.APP);
            assertEquals(Mode.LOCAL, read.mode);
            Pep.create(read).close();
        }
    }

    @Test
    void aFailingServiceDropsTheCachedPermits() throws Exception {
        try (Stub stub = Stub.start()) {
            PepConfig configuration = config(stub, "cache-outage");
            configuration.permitCacheMs = 30_000;
            Pep pep = Pep.create(configuration);
            try {
                assertTrue(pep.decide(alice(), read42()).isPermit());
                assertTrue(pep.decide(alice(), read42()).isPermit());
                assertEquals(1, stub.count("/access/v1/evaluation"));
                synchronized (stub.script) {
                    stub.script.evaluationStatus = 503;
                    stub.script.evaluationBody = Json.object();
                }
                Decision down = pep.decide(alice(), Access.of("write", "order", "42"));
                assertEquals(Decision.Kind.UNAVAILABLE, down.kind());
                assertEquals(403, down.httpStatus());
                assertEquals(0, pep.status().permitCacheEntries);
                Decision again = pep.decide(alice(), read42());
                assertEquals(Decision.Kind.UNAVAILABLE, again.kind());
                assertEquals(3, stub.count("/access/v1/evaluation"));
                synchronized (stub.script) {
                    stub.script.evaluationStatus = 200;
                    stub.script.evaluationBody = Json.MAPPER.readTree("{\"decision\":true}");
                }
                assertTrue(pep.decide(alice(), read42()).isPermit());
                assertTrue(pep.decide(alice(), read42()).isPermit());
                assertEquals(4, stub.count("/access/v1/evaluation"));
                synchronized (stub.script) {
                    stub.script.heartbeatStatus = 503;
                }
                pep.start();
                long before = pep.status().heartbeatFailures;
                assertTrue(stub.waitUntil(Duration.ofSeconds(10), seen -> pep.status().heartbeatFailures > before));
                assertEquals(0, pep.status().permitCacheEntries);
                assertTrue(pep.decide(alice(), read42()).isPermit());
                assertEquals(5, stub.count("/access/v1/evaluation"));
            } finally {
                pep.close();
            }
        }
    }

    private static Script.Scripted scripted(int status, JsonNode body) {
        return new Script.Scripted(status, body, List.of());
    }

    private static PepConfig config(Stub stub, String tag) {
        PepConfig configuration = new PepConfig(Stub.NAME, Mode.CENTRAL, Keys.keyFile(tag), stub.base, Stub.APP);
        configuration.heartbeatIntervalMs = 1000;
        return configuration;
    }

    private static Subject alice() {
        Map<String, JsonNode> claims = new LinkedHashMap<>();
        claims.put("acr", Json.text("urn:example:mfa"));
        return Subject.user("alice", claims);
    }

    private static Access read42() {
        return Access.of("read", "order", "42");
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
