// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Who is asking. The host builds the claims map from its own sign-in.
 * This package reads no HTTP header.
 */
public final class Subject {
    /** The AuthZEN subject type. {@code user} for a person. */
    public String kind = "";
    /** XACML {@code subject-id}, and what the service's PIP resolves. */
    public String id = "";
    /**
     * Claims ({@code acr}, {@code amr}, {@code auth_time}, and the rest).
     * They reach a policy only through the realm's attribute catalogue.
     */
    public Map<String, JsonNode> properties = new LinkedHashMap<>();

    public Subject() {}

    /** A person, with their claims. */
    public static Subject user(String id, Map<String, JsonNode> properties) {
        Subject subject = new Subject();
        subject.kind = "user";
        subject.id = id == null ? "" : id;
        if (properties != null) {
            subject.properties = properties;
        }
        return subject;
    }
}
