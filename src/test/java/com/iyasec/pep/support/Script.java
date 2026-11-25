// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Json;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/** What the stub answers. Tests change it while the PEP runs; synchronize on this object. */
public final class Script {
    /** The token endpoint asks for a nonce on the first grant. */
    public boolean tokenNonceFirst;
    /** The token endpoint refuses every grant. */
    public boolean tokenRefused;
    /** Answers for {@code POST /access/v1/evaluation}, taken in order. */
    public final ArrayDeque<Scripted> evaluations = new ArrayDeque<>();
    public int evaluationStatus = 200;
    public JsonNode evaluationBody = Json.MAPPER.createObjectNode().put("decision", true);
    /** The heartbeat's status and {@code current}. */
    public int heartbeatStatus = 200;
    public boolean heartbeatCurrent = true;
    public final List<JsonNode> policies = new ArrayList<>();
    public String policyToken = "p1";
    public final List<JsonNode> catalogueRows = new ArrayList<>();
    public String catalogueToken = "c1";
    public boolean obligationsProfile;
    /** The PIP's answer body. */
    public String pipAnswer = "";
    public int registerStatus = 201;

    /** One scripted evaluation answer: status, body, extra headers. */
    public static final class Scripted {
        public final int status;
        public final JsonNode body;
        public final List<String[]> headers;

        public Scripted(int status, JsonNode body, List<String[]> headers) {
            this.status = status;
            this.body = body;
            this.headers = headers == null ? List.of() : headers;
        }
    }

    static final class Reply {
        final int status;
        final String body;
        final List<String[]> headers;

        Reply(int status, String body, List<String[]> headers) {
            this.status = status;
            this.body = body;
            this.headers = headers;
        }
    }

    Reply answer(String base, Seen request, int[] tokens, boolean[] nonceAsked) {
        String prefix = "/realm/" + Stub.REALM;
        String path = request.path.startsWith(prefix) ? request.path.substring(prefix.length()) : request.path;
        boolean authorized = request.header("Authorization") != null
                && request.header("Authorization").startsWith("DPoP ")
                && request.header("DPoP") != null;
        if ("POST".equals(request.method) && "/oauth2/token".equals(path)) {
            if (tokenRefused) {
                return json(400, Json.MAPPER.createObjectNode()
                        .put("error", "invalid_grant")
                        .put("error_description", "no key is registered for the PEP"));
            }
            if (tokenNonceFirst && !nonceAsked[0]) {
                nonceAsked[0] = true;
                Reply reply = json(400, Json.MAPPER.createObjectNode().put("error", "use_dpop_nonce"));
                reply.headers.add(new String[] {"DPoP-Nonce", "n-token"});
                return reply;
            }
            tokens[0]++;
            String scope = request.form("scope");
            if (scope == null) {
                scope = "";
            }
            ObjectNode token = Json.object();
            token.put("access_token", "tok-" + scope + "-" + tokens[0]);
            token.put("token_type", "DPoP");
            token.put("expires_in", 300);
            return json(200, token);
        }
        if (!authorized) {
            Reply reply = json(401, Json.MAPPER.createObjectNode().put("error", "invalid_token"));
            reply.headers.add(new String[] {"WWW-Authenticate", "DPoP error=\"invalid_token\""});
            return reply;
        }
        if ("POST".equals(request.method) && "/xacml/pep/register".equals(path)) {
            ObjectNode body = Json.object();
            body.put("registered", true);
            body.put("name", Stub.NAME);
            body.put("created", true);
            body.put("identity", Stub.IDENTITY);
            return json(registerStatus, body);
        }
        if ("POST".equals(request.method) && "/xacml/pep/heartbeat".equals(path)) {
            ObjectNode body = Json.object();
            body.put("acknowledged", true);
            body.put("name", Stub.NAME);
            body.put("syncToken", policyToken);
            body.put("current", heartbeatCurrent);
            body.put("action", "");
            return json(heartbeatStatus, body);
        }
        if ("GET".equals(request.method) && "/xacml/pep/policies".equals(path)) {
            String etag = "\"" + policyToken + "\"";
            if (etag.equals(request.header("If-None-Match"))) {
                return new Reply(304, "", new ArrayList<>(List.<String[]>of(new String[] {"ETag", etag})));
            }
            ObjectNode body = Json.object();
            body.put("syncToken", policyToken);
            body.put("root", "root");
            ArrayNode policiesNode = Json.array();
            for (JsonNode policy : policies) {
                policiesNode.add(policy);
            }
            body.set("policies", policiesNode);
            body.set("withheld", Json.array());
            body.put("note", "");
            Reply reply = json(200, body);
            reply.headers.add(new String[] {"ETag", etag});
            return reply;
        }
        if ("GET".equals(request.method) && "/xacml/pep/authzen-catalogue".equals(path)) {
            String etag = "\"" + catalogueToken + "\"";
            if (etag.equals(request.header("If-None-Match"))) {
                return new Reply(304, "", new ArrayList<>(List.<String[]>of(new String[] {"ETag", etag})));
            }
            ObjectNode body = Json.object();
            body.put("syncToken", catalogueToken);
            body.put("realm", Stub.REALM);
            body.putNull("apiObject");
            ArrayNode rows = Json.array();
            for (JsonNode row : catalogueRows) {
                rows.add(row);
            }
            body.set("rows", rows);
            body.put("leftOut", 0);
            ObjectNode settings = Json.object();
            settings.put("enabled", true);
            ArrayNode types = Json.array();
            types.add("user");
            settings.set("resolveSubjectTypes", types);
            settings.put("batchEnabled", true);
            settings.put("maxEvaluations", 100);
            settings.put("maxBodyBytes", 65536);
            settings.put("returnReasons", false);
            settings.put("obligationsProfile", obligationsProfile);
            settings.put("tokenExchange", false);
            settings.set("tokenExchangeDetailTypes", Json.array());
            settings.set("tokenExchangeTokenTypes", Json.array());
            body.set("settings", settings);
            body.put("note", "");
            Reply reply = json(200, body);
            reply.headers.add(new String[] {"ETag", etag});
            return reply;
        }
        if ("POST".equals(request.method) && "/xacml/pip".equals(path)) {
            return new Reply(200, pipAnswer, new ArrayList<>(List.<String[]>of(new String[] {"Content-Type", "application/xml"})));
        }
        if ("POST".equals(request.method) && "/access/v1/evaluation".equals(path)) {
            Scripted scripted = evaluations.pollFirst();
            int status = scripted == null ? evaluationStatus : scripted.status;
            JsonNode value = scripted == null ? evaluationBody : scripted.body;
            Reply reply = json(status, value);
            if (scripted != null) {
                reply.headers.addAll(scripted.headers);
            }
            return reply;
        }
        if ("POST".equals(request.method) && "/admin-api/pep-audit".equals(path)) {
            JsonNode events = request.json().path("events");
            long last = 0;
            if (events.isArray() && !events.isEmpty()) {
                JsonNode seq = events.get(events.size() - 1).get("seq");
                if (seq != null && seq.canConvertToLong()) {
                    last = seq.longValue();
                }
            }
            ObjectNode body = Json.object();
            body.put("acknowledged", last);
            body.put("recorded", 1);
            body.put("duplicates", 0);
            body.put("ignored", 0);
            body.put("recording", true);
            return json(200, body);
        }
        return json(404, Json.MAPPER.createObjectNode().put("error", "not_found"));
    }

    private static Reply json(int status, JsonNode value) {
        List<String[]> headers = new ArrayList<>();
        headers.add(new String[] {"Content-Type", "application/json"});
        String body = value == null ? "null" : value.toString();
        return new Reply(status, body, headers);
    }
}
