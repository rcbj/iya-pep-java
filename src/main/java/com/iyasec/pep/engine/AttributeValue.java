// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.Objects;

/** A typed value as a request carries it: the datatype URI and its lexical form. */
public final class AttributeValue {
    public final String dataType;
    public final String value;

    public AttributeValue(String dataType, String value) {
        this.dataType = dataType;
        this.value = value;
    }

    /** An {@code xs:string} value. */
    public static AttributeValue string(String value) {
        return new AttributeValue(Names.STRING, value);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof AttributeValue other)) {
            return false;
        }
        return dataType.equals(other.dataType) && value.equals(other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(dataType, value);
    }

    @Override
    public String toString() {
        return value;
    }
}
