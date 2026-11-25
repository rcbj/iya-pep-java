// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.Objects;

/** What an attribute designator asks for, for the PIP. */
public final class Designator implements Comparable<Designator> {
    public final String category;
    public final String attributeId;
    public final String dataType;
    public final String issuer;

    public Designator(String category, String attributeId, String dataType, String issuer) {
        this.category = category;
        this.attributeId = attributeId;
        this.dataType = dataType;
        this.issuer = issuer;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Designator other)) {
            return false;
        }
        return category.equals(other.category)
                && attributeId.equals(other.attributeId)
                && dataType.equals(other.dataType)
                && Objects.equals(issuer, other.issuer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(category, attributeId, dataType, issuer);
    }

    /** Order is category, attribute id, datatype, then issuer with an absent issuer first. */
    @Override
    public int compareTo(Designator other) {
        int c = category.compareTo(other.category);
        if (c != 0) {
            return c;
        }
        c = attributeId.compareTo(other.attributeId);
        if (c != 0) {
            return c;
        }
        c = dataType.compareTo(other.dataType);
        if (c != 0) {
            return c;
        }
        if (issuer == null && other.issuer == null) {
            return 0;
        }
        if (issuer == null) {
            return -1;
        }
        if (other.issuer == null) {
            return 1;
        }
        return issuer.compareTo(other.issuer);
    }

    @Override
    public String toString() {
        return category + " " + attributeId;
    }
}
