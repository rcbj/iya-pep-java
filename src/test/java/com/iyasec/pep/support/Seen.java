// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.iyasec.pep.Json;
import com.iyasec.pep.key.SigningKey;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** One request the stub was sent. */
public final class Seen {
    public final String method;
    public final String path;
    public final String query;
    public final List<String[]> headers;
    public final String body;

    public Seen(String method, String path, String query, List<String[]> headers, String body) {
        this.method = method;
        this.path = path;
        this.query = query == null ? "" : query;
        this.headers = headers;
        this.body = body == null ? "" : body;
    }

    public String header(String name) {
        for (String[] header : headers) {
            if (header[0].equalsIgnoreCase(name)) {
                return header[1];
            }
        }
        return null;
    }

    public JsonNode json() {
        JsonNode parsed = Json.parse(body);
        return parsed == null ? Json.MAPPER.nullNode() : parsed;
    }

    public String form(String key) {
        if (body.isEmpty()) {
            return null;
        }
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            String rawKey = eq < 0 ? pair : pair.substring(0, eq);
            String rawValue = eq < 0 ? "" : pair.substring(eq + 1);
            String decoded = URLDecoder.decode(rawKey, StandardCharsets.UTF_8);
            if (decoded.equals(key)) {
                return URLDecoder.decode(rawValue, StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /** The claims of the DPoP proof. */
    public JsonNode proof() {
        return claims(header("DPoP") == null ? "" : header("DPoP"));
    }

    public JsonNode proofHeader() {
        return part(header("DPoP") == null ? "" : header("DPoP"), 0);
    }

    /** The claims of a compact JWS. */
    public static JsonNode claims(String jws) {
        return part(jws, 1);
    }

    public static JsonNode part(String jws, int index) {
        String[] pieces = jws.split("\\.", -1);
        if (index >= pieces.length || pieces[index].isEmpty()) {
            return Json.MAPPER.nullNode();
        }
        try {
            return Json.MAPPER.readTree(SigningKey.b64UrlDecode(pieces[index]));
        } catch (Exception e) {
            return Json.MAPPER.nullNode();
        }
    }
}
