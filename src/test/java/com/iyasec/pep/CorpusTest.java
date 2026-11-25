// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iyasec.pep.engine.Assignment;
import com.iyasec.pep.engine.Attribute;
import com.iyasec.pep.engine.AttributeValue;
import com.iyasec.pep.engine.Category;
import com.iyasec.pep.engine.CompileException;
import com.iyasec.pep.engine.Decision;
import com.iyasec.pep.engine.NoResolver;
import com.iyasec.pep.engine.Obligation;
import com.iyasec.pep.engine.Policies;
import com.iyasec.pep.engine.PolicyDocument;
import com.iyasec.pep.engine.Request;
import com.iyasec.pep.engine.Response;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiPredicate;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The pinned conformance corpus: every OASIS case must get the reference answer.
 * Assignment values are compared by their canonical lexical form.
 */
class CorpusTest {
    private static final int CORPUS_VERSION = 1;
    private static final String CORPUS_SHA256 = "d28672aefda0f4c4d6135afce21ac32030b66f4502043d5ebc6f17351d31cc91";

    private static final ObjectMapper JSON = new ObjectMapper();

    private static Path corpus() throws URISyntaxException {
        URL url = CorpusTest.class.getClassLoader().getResource("corpus/MANIFEST.json");
        if (url != null && "file".equals(url.getProtocol())) {
            return Path.of(url.toURI()).getParent();
        }
        Path fallback = Path.of("src/test/resources/corpus");
        if (Files.isRegularFile(fallback.resolve("MANIFEST.json"))) {
            return fallback;
        }
        throw new IllegalStateException("corpus/MANIFEST.json is not on the classpath");
    }

    private static JsonNode readJson(Path path) throws Exception {
        return JSON.readTree(Files.readString(path));
    }

    private static JsonNode manifest() throws Exception {
        return readJson(corpus().resolve("MANIFEST.json"));
    }

    private static List<Path> caseFiles() throws Exception {
        try (Stream<Path> stream = Files.list(corpus().resolve("oasis"))) {
            return stream.filter(path -> path.getFileName().toString().endsWith(".json"))
                    .sorted()
                    .toList();
        }
    }

    private static String string(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || !value.isTextual()) {
            throw new IllegalStateException("missing string " + key);
        }
        return value.asText();
    }

    private static String optional(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || value.isNull() || !value.isTextual()) {
            return null;
        }
        return value.asText();
    }

    private static List<JsonNode> array(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || !value.isArray()) {
            return List.of();
        }
        List<JsonNode> out = new ArrayList<>();
        value.forEach(out::add);
        return out;
    }

    private static boolean bool(JsonNode node, String key) {
        JsonNode value = node.get(key);
        return value != null && value.asBoolean(false);
    }

    private static List<PolicyDocument> policies(JsonNode caseNode) {
        List<PolicyDocument> rows = new ArrayList<>();
        for (JsonNode policy : array(caseNode, "policies")) {
            rows.add(new PolicyDocument(
                    string(policy, "policyId"),
                    string(policy, "kind"),
                    string(policy, "version"),
                    bool(policy, "isRoot"),
                    string(policy, "document")));
        }
        return rows;
    }

    private static Request request(JsonNode caseNode) {
        JsonNode body = caseNode.get("request");
        List<Category> categories = new ArrayList<>();
        for (JsonNode category : array(body, "categories")) {
            List<Attribute> attributes = new ArrayList<>();
            for (JsonNode attribute : array(category, "attributes")) {
                List<AttributeValue> values = new ArrayList<>();
                for (JsonNode value : array(attribute, "values")) {
                    values.add(new AttributeValue(string(value, "dataType"), string(value, "value")));
                }
                attributes.add(new Attribute(
                        string(attribute, "attributeId"),
                        optional(attribute, "issuer"),
                        bool(attribute, "includeInResult"),
                        values));
            }
            categories.add(new Category(string(category, "category"), bool(category, "hasContent"), attributes));
        }
        return new Request(bool(body, "returnPolicyIdList"), bool(body, "combinedDecision"), categories);
    }

    private static List<Obligation> obligations(JsonNode list) {
        List<Obligation> out = new ArrayList<>();
        if (list == null || !list.isArray()) {
            return out;
        }
        for (JsonNode obligation : list) {
            List<Assignment> assignments = new ArrayList<>();
            for (JsonNode assignment : array(obligation, "assignments")) {
                assignments.add(new Assignment(
                        string(assignment, "attributeId"),
                        optional(assignment, "category"),
                        optional(assignment, "issuer"),
                        string(assignment, "dataType"),
                        string(assignment, "value")));
            }
            out.add(new Obligation(string(obligation, "id"), assignments));
        }
        return out;
    }

    private static <T> boolean sameMultiset(List<T> expected, List<T> got, BiPredicate<T, T> same) {
        if (expected.size() != got.size()) {
            return false;
        }
        boolean[] used = new boolean[got.size()];
        for (T item : expected) {
            boolean found = false;
            for (int i = 0; i < got.size(); i++) {
                if (!used[i] && same.test(item, got.get(i))) {
                    used[i] = true;
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    private static boolean sameObligation(Obligation left, Obligation right) {
        return left.id.equals(right.id)
                && sameMultiset(left.assignments, right.assignments, Assignment::equals);
    }

    private static Decision decision(String text) {
        return switch (text) {
            case "Permit" -> Decision.PERMIT;
            case "Deny" -> Decision.DENY;
            case "NotApplicable" -> Decision.NOT_APPLICABLE;
            case "Indeterminate" -> Decision.INDETERMINATE;
            default -> throw new IllegalStateException("not a decision: " + text);
        };
    }

    private static String show(List<Obligation> obligations) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < obligations.size(); i++) {
            if (i > 0) {
                out.append(", ");
            }
            Obligation obligation = obligations.get(i);
            out.append(obligation.id).append('{');
            for (int j = 0; j < obligation.assignments.size(); j++) {
                if (j > 0) {
                    out.append(", ");
                }
                Assignment assignment = obligation.assignments.get(j);
                out.append(assignment.attributeId)
                        .append('@')
                        .append(assignment.category)
                        .append('/')
                        .append(assignment.issuer)
                        .append(' ')
                        .append(assignment.dataType)
                        .append('=')
                        .append(assignment.value);
            }
            out.append('}');
        }
        return out.append(']').toString();
    }

    @Test
    void theManifestIsThePinnedCorpus() throws Exception {
        JsonNode manifest = manifest();
        assertEquals(CORPUS_VERSION, manifest.get("version").asInt(), "the corpus version");
        assertEquals(CORPUS_SHA256, manifest.get("sha256").asText(), "the corpus digest");
    }

    @Test
    void everyCaseFileIsPresent() throws Exception {
        long wanted = manifest().get("cases").get("oasis").asLong();
        assertEquals(wanted, caseFiles().size());
    }

    @Test
    void everyOasisCaseGetsTheReferenceAnswer() throws Exception {
        JsonNode manifest = manifest();
        Instant now = Instant.parse(manifest.get("now").asText());
        List<Path> files = caseFiles();
        List<String> mismatches = new ArrayList<>();
        for (Path path : files) {
            JsonNode caseNode = readJson(path);
            String name = string(caseNode, "name");
            Policies compiled;
            try {
                compiled = Policies.compile(policies(caseNode));
            } catch (CompileException error) {
                mismatches.add(name + ": does not compile: " + error.getMessage());
                continue;
            } catch (RuntimeException error) {
                mismatches.add(name + ": does not compile: " + error);
                continue;
            }
            Response response;
            try {
                response = compiled.evaluate(request(caseNode), now, new NoResolver());
            } catch (RuntimeException error) {
                mismatches.add(name + ": evaluation failed: " + error);
                continue;
            }
            JsonNode expected = caseNode.get("expected");
            Decision want = decision(expected.get("decision").asText(""));
            if (response.decision != want) {
                mismatches.add(name + ": decision " + want.asString() + ", got " + response.decision.asString());
            }
            for (String key : new String[] {"obligations", "advice"}) {
                List<Obligation> wantObligations = obligations(expected.get(key));
                List<Obligation> got = "obligations".equals(key) ? response.obligations : response.advice;
                if (!sameMultiset(wantObligations, got, CorpusTest::sameObligation)) {
                    mismatches.add(name + ": " + key + " " + show(wantObligations) + ", got " + show(got));
                }
            }
        }
        if (!mismatches.isEmpty()) {
            fail(mismatches.size()
                    + " of "
                    + files.size()
                    + " cases differ from the reference:\n"
                    + String.join("\n", mismatches));
        }
        assertTrue(files.size() > 0);
    }
}
