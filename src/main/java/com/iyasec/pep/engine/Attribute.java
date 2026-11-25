// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/** One attribute of a request category. */
public final class Attribute {
    public final String attributeId;
    public final String issuer;
    public final boolean includeInResult;
    public final List<AttributeValue> values;

    public Attribute(String attributeId, String issuer, boolean includeInResult, List<AttributeValue> values) {
        this.attributeId = attributeId;
        this.issuer = issuer;
        this.includeInResult = includeInResult;
        this.values = values;
    }
}
