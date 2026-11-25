// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.Map;

/** What the subject wants to do, to what. */
public final class Access {
    /** The AuthZEN action name ({@code read}, {@code GET}, {@code documents.delete}). */
    public String action = "";
    public String resourceType = "";
    public String resourceId = "";
    public Map<String, JsonNode> actionProperties = new LinkedHashMap<>();
    public Map<String, JsonNode> resourceProperties = new LinkedHashMap<>();
    /**
     * Further AuthZEN context. {@code application} and
     * {@code supported_obligations} are the PEP's and are overwritten.
     */
    public Map<String, JsonNode> context = new LinkedHashMap<>();

    public Access() {}

    public Access(String action, String resourceType, String resourceId) {
        this.action = action == null ? "" : action;
        this.resourceType = resourceType == null ? "" : resourceType;
        this.resourceId = resourceId == null ? "" : resourceId;
    }

    public static Access of(String action, String resourceType, String resourceId) {
        return new Access(action, resourceType, resourceId);
    }
}
