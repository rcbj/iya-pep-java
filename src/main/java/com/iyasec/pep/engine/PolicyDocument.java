// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

/** One policy row of a pull, and of a corpus case. */
public final class PolicyDocument {
    public final String policyId;
    /** {@code Policy} or {@code PolicySet}. */
    public final String kind;
    public final String version;
    /** Exactly one row of a set is the root, and it is the one evaluated. */
    public final boolean isRoot;
    /** The XACML 3.0 Policy or PolicySet, as XML. */
    public final String document;

    public PolicyDocument(String policyId, String kind, String version, boolean isRoot, String document) {
        this.policyId = policyId;
        this.kind = kind;
        this.version = version;
        this.isRoot = isRoot;
        this.document = document;
    }
}
