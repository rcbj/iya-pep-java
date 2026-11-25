// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.local;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Decision;
import com.iyasec.pep.Json;
import com.iyasec.pep.Obligation;
import com.iyasec.pep.PepException;
import com.iyasec.pep.authzen.Authzen;
import com.iyasec.pep.authzen.Catalogue;
import com.iyasec.pep.authzen.Outcome;
import com.iyasec.pep.authzen.Refusal;
import com.iyasec.pep.authzen.Trusted;
import com.iyasec.pep.credential.Audience;
import com.iyasec.pep.credential.Credential;
import com.iyasec.pep.engine.AttributeValue;
import com.iyasec.pep.engine.CompileException;
import com.iyasec.pep.engine.Designator;
import com.iyasec.pep.engine.Names;
import com.iyasec.pep.engine.Policies;
import com.iyasec.pep.engine.PolicyDocument;
import com.iyasec.pep.engine.Request;
import com.iyasec.pep.engine.Resolver;
import com.iyasec.pep.engine.Response;
import com.iyasec.pep.http.Answer;
import com.iyasec.pep.http.Body;
import com.iyasec.pep.http.Field;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code local} mode: the bound application's policies, pulled and compiled,
 * and the decision made in process.
 */
public final class Local {
    private static final String PIP_NS = "urn:sts:xacml:pip:1.0";
    private static final String XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
    private static final String SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
    private static final String SUBJECT_KIND = "urn:sts:xacml:subject-kind";
    /** The service refuses more designators than this in one PIP query. */
    public static final int MAX_DESIGNATORS = 50;

    private Local() {}

    /** What a {@code local} PEP holds. */
    public static final class Held {
        public final Policies policies;
        public final Catalogue catalogue;
        public final String policyToken;
        public final String catalogueToken;
        public final List<Designator> subjectDesignators;

        public Held(Policies policies, Catalogue catalogue, String policyToken, String catalogueToken,
                    List<Designator> subjectDesignators) {
            this.policies = policies;
            this.catalogue = catalogue;
            this.policyToken = policyToken;
            this.catalogueToken = catalogueToken;
            this.subjectDesignators = subjectDesignators;
        }
    }

    /** What one pull did. {@code held} is null when both answers were {@code 304}. */
    public static final class Pull {
        public final boolean changed;
        public final Held held;

        public Pull(boolean changed, Held held) {
            this.changed = changed;
            this.held = held;
        }
    }

    /** What one local decision was, for the record. {@code outcome} is null when the evaluation was refused. */
    public static final class Made {
        public final Decision decision;
        public final Outcome outcome;

        public Made(Decision decision, Outcome outcome) {
            this.decision = decision;
            this.outcome = outcome;
        }
    }

    /**
     * Pulls the policies and the catalogue, and compiles. {@code held} is what
     * is held now, whose tokens are sent and whose parts are kept on {@code 304}.
     */
    public static Pull pull(Credential credential, String base, String name, Held held) throws PepException {
        String policiesUrl = base + "/xacml/pep/policies?scope=bound-application&pep=" + form(name);
        String catalogueUrl = base + "/xacml/pep/authzen-catalogue";
        Answer policiesAnswer = credential.call(Audience.PEP, "GET", policiesUrl, "application/json",
                etag(held == null ? null : held.policyToken), null);
        List<PolicyDocument> policyRows = null;
        String policyToken = null;
        if (policiesAnswer.status == 304 && held != null) {
            policyRows = null;
        } else if (policiesAnswer.status == 200) {
            JsonNode json = policiesAnswer.json();
            if (json == null) {
                throw new PepException("policy", "the policy pull is not JSON");
            }
            policyToken = json.path("syncToken").isTextual() ? json.get("syncToken").asText() : unquote(policiesAnswer.etag);
            policyRows = rows(json);
        } else {
            throw refusal("the policy pull", policiesAnswer);
        }

        Answer catalogueAnswer = credential.call(Audience.PEP, "GET", catalogueUrl, "application/json",
                etag(held == null ? null : held.catalogueToken), null);
        Catalogue catalogue = null;
        String catalogueToken = null;
        if (catalogueAnswer.status == 304 && held != null) {
            catalogue = null;
        } else if (catalogueAnswer.status == 200) {
            JsonNode json = catalogueAnswer.json();
            if (json == null) {
                throw new PepException("policy", "the catalogue pull is not JSON");
            }
            catalogueToken = json.path("syncToken").isTextual() ? json.get("syncToken").asText() : unquote(catalogueAnswer.etag);
            try {
                catalogue = Catalogue.fromPull(json);
            } catch (Refusal r) {
                throw new PepException("policy", "the catalogue was refused: " + r.code + " " + r.message);
            }
        } else {
            throw refusal("the catalogue pull", catalogueAnswer);
        }

        if (policyRows == null && catalogue == null) {
            return new Pull(false, null);
        }
        Policies compiled;
        String keptPolicyToken;
        if (policyRows != null) {
            try {
                compiled = Policies.compile(policyRows);
            } catch (CompileException e) {
                throw new PepException("policy", "the pulled set does not compile: " + e.getMessage());
            }
            keptPolicyToken = policyToken;
        } else {
            compiled = held.policies;
            keptPolicyToken = held.policyToken;
        }
        Catalogue keptCatalogue;
        String keptCatalogueToken;
        if (catalogue != null) {
            keptCatalogue = catalogue;
            keptCatalogueToken = catalogueToken;
        } else {
            keptCatalogue = held.catalogue;
            keptCatalogueToken = held.catalogueToken;
        }
        return new Pull(true, new Held(compiled, keptCatalogue, keptPolicyToken, keptCatalogueToken,
                compiled.designators(Names.ACCESS_SUBJECT)));
    }

    /** Decides one evaluation body in process. */
    public static Made decide(Credential credential, String base, Held held, JsonNode body, Trusted trusted,
                              String subjectId, boolean applicationSubject, Instant now) {
        com.iyasec.pep.authzen.Mapped mapped;
        try {
            mapped = Authzen.mapEvaluation(body, held.catalogue, trusted);
        } catch (Refusal refusal) {
            return new Made(Decision.deny("the evaluation was refused (" + refusal.code + "): " + refusal.message), null);
        }
        PipAnswers pip = resolveSubject(credential, base, held, mapped.request, subjectId, applicationSubject);
        Response response = held.policies.evaluate(mapped.request, now, pip);
        Outcome outcome = Authzen.outcome(response, mapped.supportedObligations, held.catalogue.obligationsProfile);
        Decision decision;
        if (outcome.fault) {
            decision = Decision.unavailable(outcome.why);
        } else if (outcome.decision) {
            List<Obligation> obligations = new ArrayList<>();
            for (com.iyasec.pep.authzen.Handed handed : outcome.handed) {
                Obligation obligation = com.iyasec.pep.Bodies.obligationFrom(handed.obligation);
                if (obligation != null) {
                    obligations.add(obligation);
                }
            }
            List<Obligation> advice = new ArrayList<>();
            if (response.advice != null) {
                for (com.iyasec.pep.engine.Obligation item : response.advice) {
                    advice.add(adviceOf(item));
                }
            }
            decision = Decision.permit(obligations, advice);
        } else {
            decision = Decision.deny(outcome.why);
        }
        return new Made(decision, outcome);
    }

    /** The PIP query: the subject, and what to resolve for it. */
    public static String pipQuery(String subjectId, boolean applicationSubject, List<Designator> designators) {
        StringBuilder out = new StringBuilder();
        out.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.append("<PIPRequest xmlns=\"").append(PIP_NS).append("\">\n");
        out.append("  <Request xmlns=\"").append(XACML_NS).append("\" CombinedDecision=\"false\" ReturnPolicyIdList=\"false\">\n");
        out.append("    <Attributes Category=\"").append(Names.ACCESS_SUBJECT).append("\">\n");
        out.append("      <Attribute AttributeId=\"").append(SUBJECT_ID).append("\" IncludeInResult=\"true\">\n");
        out.append("        <AttributeValue DataType=\"").append(Names.STRING).append("\">")
                .append(escape(subjectId)).append("</AttributeValue>\n");
        out.append("      </Attribute>\n");
        if (applicationSubject) {
            out.append("      <Attribute AttributeId=\"").append(SUBJECT_KIND).append("\" IncludeInResult=\"false\">\n");
            out.append("        <AttributeValue DataType=\"").append(Names.STRING).append("\">application</AttributeValue>\n");
            out.append("      </Attribute>\n");
        }
        out.append("    </Attributes>\n  </Request>\n");
        if (designators != null) {
            for (Designator designator : designators) {
                out.append("  <AttributeDesignator xmlns=\"").append(XACML_NS).append("\" Category=\"")
                        .append(escape(designator.category)).append("\" AttributeId=\"")
                        .append(escape(designator.attributeId)).append("\" DataType=\"")
                        .append(escape(designator.dataType)).append("\" MustBePresent=\"false\"/>\n");
            }
        }
        out.append("</PIPRequest>\n");
        return out.toString();
    }

    /** Reads a {@code PIPResponse}. An answer that cannot be read is no answers. */
    public static PipAnswers readPipAnswer(String text) {
        PipAnswers out = new PipAnswers();
        Document document;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            document = builder.parse(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return out;
        }
        Element root = document.getDocumentElement();
        if (root == null || !"PIPResponse".equals(localName(root))) {
            return out;
        }
        for (Element attributes : descendants(root, "Attributes")) {
            String category = attributes.getAttribute("Category");
            for (Element attribute : children(attributes, "Attribute")) {
                String id = attribute.getAttribute("AttributeId");
                for (Element value : children(attribute, "AttributeValue")) {
                    String dataType = value.hasAttribute("DataType") ? value.getAttribute("DataType") : Names.STRING;
                    String lexical = value.getTextContent() == null ? "" : value.getTextContent().trim();
                    out.answers.computeIfAbsent(key(category, id, dataType), k -> new ArrayList<>())
                            .add(new AttributeValue(dataType, lexical));
                }
            }
        }
        return out;
    }

    /** What the PIP answered, by category, attribute id and datatype. */
    public static final class PipAnswers implements Resolver {
        private final Map<String, List<AttributeValue>> answers = new HashMap<>();

        @Override
        public List<AttributeValue> resolve(Designator designator) {
            List<AttributeValue> found = answers.get(key(designator.category, designator.attributeId, designator.dataType));
            return found == null ? null : List.copyOf(found);
        }
    }

    private static PipAnswers resolveSubject(Credential credential, String base, Held held, Request request,
                                             String subjectId, boolean applicationSubject) {
        List<String> carried = new ArrayList<>();
        for (com.iyasec.pep.engine.Category category : request.categories) {
            if (!Names.ACCESS_SUBJECT.equals(category.category)) {
                continue;
            }
            for (com.iyasec.pep.engine.Attribute attribute : category.attributes) {
                carried.add(category.category + "\n" + attribute.attributeId);
            }
        }
        List<Designator> wanted = new ArrayList<>();
        for (Designator designator : held.subjectDesignators) {
            if (wanted.size() >= MAX_DESIGNATORS) {
                break;
            }
            if (!carried.contains(designator.category + "\n" + designator.attributeId)) {
                wanted.add(designator);
            }
        }
        if (wanted.isEmpty() || subjectId == null || subjectId.isEmpty()) {
            return new PipAnswers();
        }
        String url = base + "/xacml/pip";
        String query = pipQuery(subjectId, applicationSubject, wanted);
        try {
            Answer answer = credential.call(Audience.PEP, "POST", url, "application/xml", List.of(), Body.xml(query));
            if (answer.status == 200) {
                return readPipAnswer(answer.body);
            }
        } catch (PepException ignored) {
            return new PipAnswers();
        }
        return new PipAnswers();
    }

    private static Obligation adviceOf(com.iyasec.pep.engine.Obligation advice) {
        ObjectNode properties = Json.object();
        if (advice.assignments != null) {
            for (com.iyasec.pep.engine.Assignment assignment : advice.assignments) {
                JsonNode existing = properties.get(assignment.attributeId);
                if (existing == null) {
                    properties.put(assignment.attributeId, assignment.value);
                } else if (existing.isArray()) {
                    ((ArrayNode) existing).add(assignment.value);
                } else {
                    ArrayNode values = Json.array();
                    values.add(existing.deepCopy());
                    values.add(assignment.value);
                    properties.set(assignment.attributeId, values);
                }
            }
        }
        String id = advice.id == null ? "" : advice.id;
        return new Obligation(id, id, properties);
    }

    private static List<PolicyDocument> rows(JsonNode json) throws PepException {
        JsonNode list = json.get("policies");
        if (list == null || !list.isArray()) {
            throw new PepException("policy", "the policy pull has no policies array");
        }
        List<PolicyDocument> rows = new ArrayList<>();
        for (JsonNode row : list) {
            rows.add(new PolicyDocument(
                    text(row, "policyId"),
                    text(row, "kind"),
                    text(row, "version"),
                    row.path("isRoot").isBoolean() && row.get("isRoot").booleanValue(),
                    text(row, "document")));
        }
        int roots = 0;
        for (PolicyDocument row : rows) {
            if (row.isRoot) {
                roots++;
            }
        }
        if (roots != 1) {
            String note = text(json, "rootNote");
            String message = ("the pulled set has no single root policy " + note).stripTrailing();
            throw new PepException("policy", message);
        }
        return rows;
    }

    private static PepException refusal(String what, Answer answer) {
        JsonNode json = answer.json();
        String error = "";
        String description = "";
        if (json != null) {
            if (json.path("error").isTextual()) {
                error = json.get("error").asText();
            }
            if (json.path("error_description").isTextual()) {
                description = json.get("error_description").asText();
            }
        }
        return new PepException("refused", (what + " answered " + answer.status + " " + error + " " + description).stripTrailing());
    }

    private static List<Field> etag(String token) {
        if (token == null || token.isEmpty()) {
            return List.of();
        }
        return List.of(new Field("If-None-Match", "\"" + token + "\""));
    }

    private static String unquote(String etag) {
        if (etag == null) {
            return "";
        }
        String text = etag.trim();
        if (text.startsWith("W/")) {
            text = text.substring(2).trim();
        }
        int start = 0;
        int end = text.length();
        while (start < end && text.charAt(start) == '"') {
            start++;
        }
        while (end > start && text.charAt(end - 1) == '"') {
            end--;
        }
        return text.substring(start, end);
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value != null && value.isTextual() ? value.asText() : "";
    }

    private static String form(String name) {
        return java.net.URLEncoder.encode(name == null ? "" : name, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String key(String category, String attributeId, String dataType) {
        return category + "\n" + attributeId + "\n" + dataType;
    }

    private static String localName(Node node) {
        String local = node.getLocalName();
        return local == null || local.isEmpty() ? node.getNodeName() : local;
    }

    private static List<Element> descendants(Element root, String name) {
        List<Element> found = new ArrayList<>();
        collect(root, name, found);
        return found;
    }

    private static void collect(Node node, String name, List<Element> found) {
        Node child = node.getFirstChild();
        while (child != null) {
            if (child instanceof Element element) {
                if (name.equals(localName(element))) {
                    found.add(element);
                }
                collect(element, name, found);
            }
            child = child.getNextSibling();
        }
    }

    private static List<Element> children(Element parent, String name) {
        List<Element> found = new ArrayList<>();
        Node child = parent.getFirstChild();
        while (child != null) {
            if (child instanceof Element element && name.equals(localName(element))) {
                found.add(element);
            }
            child = child.getNextSibling();
        }
        return found;
    }
}
