// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Objects;

/** An obligation or a piece of advice the host application must act on. */
public final class Obligation {
    public final String id;
    /**
     * The Obligations Profile type ({@code step-up}, {@code notification}),
     * or {@code custom}. For XACML advice, the advice id.
     */
    public final String kind;
    public final ObjectNode properties;

    public Obligation(String id, String kind, ObjectNode properties) {
        this.id = id == null ? "" : id;
        this.kind = kind == null ? "" : kind;
        this.properties = properties == null ? Json.object() : properties;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Obligation obligation)) {
            return false;
        }
        return id.equals(obligation.id) && kind.equals(obligation.kind) && properties.equals(obligation.properties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, kind, properties);
    }

    @Override
    public String toString() {
        return "Obligation{id=" + id + ", kind=" + kind + ", properties=" + properties + "}";
    }
}
