// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.credential.Audience;
import com.iyasec.pep.credential.Credential;
import com.iyasec.pep.http.Answer;
import com.iyasec.pep.http.Field;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** The AuthZEN evaluation body both modes decide, and the objects read back. */
public final class Bodies {
    private Bodies() {}

    /** A dotted property path's first segment. */
    public static String rootOf(String property) {
        if (property == null || property.isEmpty()) {
            return "";
        }
        int dot = property.indexOf('.');
        return dot < 0 ? property : property.substring(0, dot);
    }

    /**
     * The AuthZEN evaluation body both modes decide: {@code central} sends
     * it, and {@code local} maps it through the catalogue as the service would.
     */
    public static ObjectNode evaluationBody(Subject subject, Access access, String application, List<String> supported) {
        ObjectNode subjectJson = Json.object();
        subjectJson.put("type", subject.kind);
        subjectJson.put("id", subject.id);
        if (subject.properties != null && !subject.properties.isEmpty()) {
            subjectJson.set("properties", objectOf(subject.properties));
        }
        ObjectNode action = Json.object();
        action.put("name", access.action);
        if (access.actionProperties != null && !access.actionProperties.isEmpty()) {
            action.set("properties", objectOf(access.actionProperties));
        }
        ObjectNode resource = Json.object();
        resource.put("type", access.resourceType);
        resource.put("id", access.resourceId);
        if (access.resourceProperties != null && !access.resourceProperties.isEmpty()) {
            resource.set("properties", objectOf(access.resourceProperties));
        }
        ObjectNode context = Json.object();
        if (access.context != null) {
            for (Map.Entry<String, JsonNode> entry : access.context.entrySet()) {
                context.set(entry.getKey(), entry.getValue());
            }
        }
        context.put("application", application == null ? "" : application);
        context.remove("supported_obligations");
        if (supported != null && !supported.isEmpty()) {
            context.set("supported_obligations", Json.strings(supported));
        }
        ObjectNode body = Json.object();
        body.set("subject", subjectJson);
        body.set("action", action);
        body.set("resource", resource);
        body.set("context", context);
        return body;
    }

    /** An AuthZEN obligation object ({@code id}, {@code type}, {@code properties}). */
    public static Obligation obligationFrom(JsonNode value) {
        if (value == null || !value.path("id").isTextual()) {
            return null;
        }
        String id = value.get("id").asText();
        String kind = "custom";
        JsonNode type = value.get("type");
        if (type != null && type.isTextual()) {
            kind = type.asText();
        }
        ObjectNode properties = Json.object();
        JsonNode raw = value.get("properties");
        if (raw instanceof ObjectNode object) {
            properties = object.deepCopy();
        }
        return new Obligation(id, kind, properties);
    }

    /**
     * Advice as the service's AuthZEN {@code context.advice} carries it
     * ({@code id}, {@code attributes: [{id, value}]}). The kind is the id.
     * Each attribute is a property named by its id, its value the lexical
     * form, and a repeated id an array, in order.
     */
    public static Obligation adviceFrom(JsonNode value) {
        if (value == null || !value.path("id").isTextual()) {
            return null;
        }
        String id = value.get("id").asText();
        ObjectNode properties = Json.object();
        JsonNode attributes = value.get("attributes");
        if (attributes != null && attributes.isArray()) {
            for (JsonNode attribute : attributes) {
                JsonNode nameNode = attribute.get("id");
                if (nameNode == null || !nameNode.isTextual()) {
                    continue;
                }
                String name = nameNode.asText();
                JsonNode raw = attribute.get("value");
                if (raw == null || raw.isNull()) {
                    continue;
                }
                String text = raw.isTextual() ? raw.asText() : raw.toString();
                JsonNode existing = properties.get(name);
                if (existing == null) {
                    properties.put(name, text);
                } else if (existing.isArray()) {
                    ((ArrayNode) existing).add(text);
                } else {
                    ArrayNode values = Json.array();
                    values.add(existing.deepCopy());
                    values.add(text);
                    properties.set(name, values);
                }
            }
        }
        return new Obligation(id, id, properties);
    }

    /**
     * {@code central}: the catalogue's subject-property roots, or null on
     * {@code 304}. Only these of a subject's claims are sent.
     */
    static Fresh pullSubjectRoots(Credential credential, String base, String token) throws PepException {
        String url = base + "/xacml/pep/authzen-catalogue";
        List<Field> extra = new ArrayList<>();
        if (token != null && !token.isEmpty()) {
            extra.add(new Field("If-None-Match", "\"" + token + "\""));
        }
        Answer answer = credential.call(Audience.PEP, "GET", url, "application/json", extra, null);
        if (answer.status == 304 && token != null && !token.isEmpty()) {
            return null;
        }
        if (answer.status != 200) {
            throw new PepException("refused", "the catalogue pull answered " + answer.status);
        }
        JsonNode json = answer.json();
        if (json == null) {
            throw new PepException("policy", "the catalogue pull is not JSON");
        }
        JsonNode rows = json.get("rows");
        if (rows == null || !rows.isArray()) {
            throw new PepException("policy", "the catalogue pull has no rows array");
        }
        Set<String> roots = new HashSet<>();
        for (JsonNode row : rows) {
            JsonNode object = row.get("object");
            if (object != null && object.isTextual() && "subject".equals(object.asText())) {
                JsonNode property = row.get("property");
                if (property != null && property.isTextual()) {
                    roots.add(rootOf(property.asText()));
                }
            }
        }
        JsonNode sync = json.get("syncToken");
        String freshToken = sync != null && sync.isTextual() ? sync.asText() : "";
        return new Fresh(freshToken, roots);
    }

    static final class Fresh {
        final String token;
        final Set<String> roots;

        Fresh(String token, Set<String> roots) {
            this.token = token;
            this.roots = roots;
        }
    }

    private static ObjectNode objectOf(Map<String, JsonNode> map) {
        ObjectNode object = Json.object();
        for (Map.Entry<String, JsonNode> entry : map.entrySet()) {
            object.set(entry.getKey(), entry.getValue());
        }
        return object;
    }
}
