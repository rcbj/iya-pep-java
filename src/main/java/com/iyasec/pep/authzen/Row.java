// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * One row of the attribute catalogue, read and checked.
 */
public final class Row {
    /** {@code subject}, {@code resource}, {@code action} or {@code context}. */
    public final String object;
    /** A dotted path into the object's {@code properties} (or into {@code context}). */
    public final String property;
    public final String attributeId;
    /** The full category URI. */
    public final String category;
    /** The full datatype URI. */
    public final String dataType;
    /** {@code bag} rather than {@code single}. */
    public final boolean bag;

    public Row(String object, String property, String attributeId, String category, String dataType, boolean bag) {
        this.object = object;
        this.property = property;
        this.attributeId = attributeId;
        this.category = category;
        this.dataType = dataType;
        this.bag = bag;
    }

    /**
     * Reads one catalogue row: a JSON object, or a string holding one.
     * Short category and datatype names are expanded and defaults applied.
     */
    public static Row read(JsonNode value) throws Refusal {
        return Authzen.readRow(value);
    }
}
