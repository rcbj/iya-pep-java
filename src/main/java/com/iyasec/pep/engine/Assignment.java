// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.Objects;

/**
 * One attribute assignment of an obligation or advice. {@code value} is in the
 * datatype's canonical lexical form.
 */
public final class Assignment {
    public final String attributeId;
    public final String category;
    public final String issuer;
    public final String dataType;
    public final String value;

    public Assignment(String attributeId, String category, String issuer, String dataType, String value) {
        this.attributeId = attributeId;
        this.category = category;
        this.issuer = issuer;
        this.dataType = dataType;
        this.value = value;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Assignment other)) {
            return false;
        }
        return attributeId.equals(other.attributeId)
                && Objects.equals(category, other.category)
                && Objects.equals(issuer, other.issuer)
                && dataType.equals(other.dataType)
                && value.equals(other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(attributeId, category, issuer, dataType, value);
    }

    @Override
    public String toString() {
        return attributeId + "=" + value;
    }
}
