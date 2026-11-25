// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

/** Shared JSON mapper. Object key order is insertion order. */
public final class Json {
    public static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {}

    public static ObjectNode object() {
        return MAPPER.createObjectNode();
    }

    public static ArrayNode array() {
        return MAPPER.createArrayNode();
    }

    public static JsonNode text(String value) {
        return TextNode.valueOf(value);
    }

    public static ArrayNode strings(Iterable<String> values) {
        ArrayNode array = array();
        if (values != null) {
            for (String value : values) {
                array.add(value);
            }
        }
        return array;
    }

    /** A textual field, or {@code ""} when it is absent or not a string. */
    public static String text(JsonNode node, String field) {
        if (node == null) {
            return "";
        }
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : "";
    }

    public static ObjectNode objectCopy(JsonNode node) {
        if (node instanceof ObjectNode object) {
            return object.deepCopy();
        }
        return object();
    }

    public static JsonNode parse(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            return MAPPER.readTree(body);
        } catch (Exception e) {
            return null;
        }
    }

    public static JsonNodeFactory factory() {
        return MAPPER.getNodeFactory();
    }
}
