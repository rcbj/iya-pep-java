// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The {@code pep} section of a library's configuration, read by the library
 * and handed over. JSON members are camelCase. An unknown member is refused.
 */
public final class PepConfig {
    /** The client the PEP's self-assertion is presented through. */
    public static final String DEFAULT_CLIENT_ID = "sts-remote-pep";
    /** {@code local} with no signal stream: how often the policy is pulled. */
    public static final long DEFAULT_POLL_INTERVAL_MS = 15_000L;
    /** {@code local} with a signal stream: the pull that runs if an event is lost. */
    public static final long DEFAULT_FALLBACK_POLL_MS = 300_000L;
    public static final long DEFAULT_HEARTBEAT_INTERVAL_MS = 30_000L;
    public static final long DEFAULT_TIMEOUT_MS = 10_000L;
    /** The longest a cached Permit may live ({@code central}). */
    public static final long MAX_PERMIT_CACHE_MS = 60_000L;

    private static final Set<String> KNOWN = Set.of(
            "name", "mode", "assertionKey", "clientId", "pdpUrl", "application",
            "pollIntervalMs", "fallbackPollMs", "heartbeatIntervalMs", "decisionRecords",
            "permitCacheMs", "signals", "supportedObligations", "tlsCa", "timeoutMs");

    /** The PEP's name: its service-account username, and {@code iss} and {@code sub}. */
    public String name;
    public Mode mode;
    /** Path of the PEM private key. Read again when the file changes. */
    public String assertionKey;
    public String clientId;
    /** The service, with {@code /realm/<id>} for a realm. */
    public String pdpUrl;
    /** The application the PEP is bound to. */
    public String application;
    public long pollIntervalMs;
    public long fallbackPollMs;
    public long heartbeatIntervalMs;
    /** Send each local decision's record to the service's audit log. */
    public boolean decisionRecords;
    /**
     * {@code central} only: how long a Permit is reused for one
     * (subject, action, resource). 0, the default, is off.
     */
    public long permitCacheMs;
    /**
     * The host has a signal stream and hands over {@code pep-policies-changed}
     * events. Without one, {@code local} polls at {@code pollIntervalMs}.
     */
    public boolean signals;
    /** Obligation types the host discharges, sent as {@code context.supported_obligations}. */
    public List<String> supportedObligations;
    /** PEM trust anchors for the service's TLS, added to the platform's. */
    public String tlsCa;
    public long timeoutMs;

    /**
     * The defaults around the four values nothing can default.
     * Does not validate; {@link #validate()} and {@link Pep#create} do.
     */
    public PepConfig(String name, Mode mode, String assertionKey, String pdpUrl, String application) {
        this.name = name == null ? "" : name;
        this.mode = mode == null ? Mode.LOCAL : mode;
        this.assertionKey = assertionKey == null ? "" : assertionKey;
        this.clientId = DEFAULT_CLIENT_ID;
        this.pdpUrl = pdpUrl == null ? "" : pdpUrl;
        this.application = application == null ? "" : application;
        this.pollIntervalMs = DEFAULT_POLL_INTERVAL_MS;
        this.fallbackPollMs = DEFAULT_FALLBACK_POLL_MS;
        this.heartbeatIntervalMs = DEFAULT_HEARTBEAT_INTERVAL_MS;
        this.decisionRecords = true;
        this.permitCacheMs = 0;
        this.signals = false;
        this.supportedObligations = new ArrayList<>();
        this.tlsCa = "";
        this.timeoutMs = DEFAULT_TIMEOUT_MS;
    }

    /**
     * Reads a {@code pep} JSON section. {@code pdpUrl} and {@code application}
     * may be absent when the library supplies them. A missing {@code mode}
     * is {@code local}. An unknown member is refused.
     */
    public static PepConfig fromJson(JsonNode section, String defaultPdpUrl, String defaultApplication) throws PepException {
        if (section == null || !section.isObject()) {
            throw new PepException("config", "pep must be an object");
        }
        var fields = section.fieldNames();
        while (fields.hasNext()) {
            String key = fields.next();
            if (!KNOWN.contains(key)) {
                throw new PepException("config", "pep." + key + " is not a setting");
            }
        }
        String modeText = text(section, "mode", "local");
        Mode mode = Mode.parse(modeText);
        List<String> obligations = obligations(section.get("supportedObligations"));
        PepConfig config = new PepConfig(
                text(section, "name", ""),
                mode,
                text(section, "assertionKey", ""),
                text(section, "pdpUrl", defaultPdpUrl == null ? "" : defaultPdpUrl),
                text(section, "application", defaultApplication == null ? "" : defaultApplication));
        config.clientId = text(section, "clientId", DEFAULT_CLIENT_ID);
        config.pollIntervalMs = number(section, "pollIntervalMs", DEFAULT_POLL_INTERVAL_MS);
        config.fallbackPollMs = number(section, "fallbackPollMs", DEFAULT_FALLBACK_POLL_MS);
        config.heartbeatIntervalMs = number(section, "heartbeatIntervalMs", DEFAULT_HEARTBEAT_INTERVAL_MS);
        config.decisionRecords = flag(section, "decisionRecords", true);
        config.permitCacheMs = number(section, "permitCacheMs", 0);
        config.signals = flag(section, "signals", false);
        config.supportedObligations = obligations;
        config.tlsCa = text(section, "tlsCa", "");
        config.timeoutMs = number(section, "timeoutMs", DEFAULT_TIMEOUT_MS);
        config.validate();
        return config;
    }

    /**
     * Refuses a configuration the PEP cannot run with. {@code local} is
     * accepted: this package always includes the engine.
     */
    public void validate() throws PepException {
        if (name == null || name.isEmpty() || name.length() > 128 || !nameChars(name)) {
            throw new PepException("config", "pep.name must be 1 to 128 characters of [A-Za-z0-9._-]");
        }
        if (assertionKey == null || assertionKey.isEmpty()) {
            throw new PepException("config", "pep.assertionKey must name the PEP's private key file");
        }
        if (clientId == null || clientId.isEmpty()) {
            throw new PepException("config", "pep.clientId must not be empty");
        }
        if (!httpUrl(pdpUrl)) {
            throw new PepException("config", "pep.pdpUrl \"" + pdpUrl + "\" is not an http(s) URL without a query");
        }
        if (application == null || application.isEmpty()) {
            throw new PepException("config", "pep.application must name the application the PEP is bound to");
        }
        checkInterval("pollIntervalMs", pollIntervalMs, 1000);
        checkInterval("fallbackPollMs", fallbackPollMs, 1000);
        checkInterval("heartbeatIntervalMs", heartbeatIntervalMs, 1000);
        checkInterval("timeoutMs", timeoutMs, 100);
        if (permitCacheMs > MAX_PERMIT_CACHE_MS) {
            throw new PepException("config", "pep.permitCacheMs must be at most " + MAX_PERMIT_CACHE_MS);
        }
        if (permitCacheMs > 0 && mode == Mode.LOCAL) {
            throw new PepException("config", "pep.permitCacheMs is for central mode; a local PEP decides in process");
        }
    }

    /** The service's base URL, without a trailing slash. */
    public String base() {
        String url = pdpUrl == null ? "" : pdpUrl;
        while (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }

    /** The realm's id from {@code /realm/<id>}, or empty for the default realm. */
    public String realm() {
        try {
            URI uri = new URI(pdpUrl);
            String path = uri.getPath();
            if (path == null || path.isEmpty()) {
                return "";
            }
            String[] segments = path.split("/");
            List<String> parts = new ArrayList<>();
            for (String segment : segments) {
                if (!segment.isEmpty()) {
                    parts.add(segment);
                }
            }
            for (int i = 0; i < parts.size(); i++) {
                if ("realm".equals(parts.get(i))) {
                    return i + 1 < parts.size() ? parts.get(i + 1) : "";
                }
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }

    private void checkInterval(String key, long value, long min) throws PepException {
        if (value < min || value > 86_400_000L) {
            throw new PepException("config", "pep." + key + " must be from " + min + " to 86400000");
        }
    }

    private static boolean nameChars(String name) {
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean httpUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (!"https".equals(scheme) && !"http".equals(scheme)) {
                return false;
            }
            return uri.getHost() != null && uri.getRawQuery() == null && uri.getRawFragment() == null;
        } catch (Exception e) {
            return false;
        }
    }

    private static String text(JsonNode section, String key, String fallback) throws PepException {
        JsonNode value = section.get(key);
        if (value == null || value.isNull()) {
            return fallback;
        }
        if (!value.isTextual()) {
            throw new PepException("config", "pep." + key + " must be a string");
        }
        return value.asText();
    }

    private static long number(JsonNode section, String key, long fallback) throws PepException {
        JsonNode value = section.get(key);
        if (value == null || value.isNull()) {
            return fallback;
        }
        if (!value.isNumber()) {
            throw new PepException("config", "pep." + key + " must be a non-negative integer");
        }
        if (value.isIntegralNumber()) {
            if (!value.canConvertToLong()) {
                throw new PepException("config", "pep." + key + " must be a non-negative integer");
            }
            long n = value.longValue();
            if (n < 0) {
                throw new PepException("config", "pep." + key + " must be a non-negative integer");
            }
            return n;
        }
        double d = value.doubleValue();
        if (!Double.isFinite(d) || d < 0 || d > Long.MAX_VALUE || d != Math.rint(d)) {
            throw new PepException("config", "pep." + key + " must be a non-negative integer");
        }
        return (long) d;
    }

    private static boolean flag(JsonNode section, String key, boolean fallback) throws PepException {
        JsonNode value = section.get(key);
        if (value == null || value.isNull()) {
            return fallback;
        }
        if (!value.isBoolean()) {
            throw new PepException("config", "pep." + key + " must be true or false");
        }
        return value.asBoolean();
    }

    private static List<String> obligations(JsonNode value) throws PepException {
        if (value == null || value.isNull()) {
            return new ArrayList<>();
        }
        if (!(value instanceof ArrayNode array)) {
            throw new PepException("config", "pep.supportedObligations must be an array");
        }
        List<String> out = new ArrayList<>();
        for (JsonNode item : array) {
            if (!item.isTextual()) {
                throw new PepException("config", "pep.supportedObligations must be strings");
            }
            out.add(item.asText());
        }
        return out;
    }
}
