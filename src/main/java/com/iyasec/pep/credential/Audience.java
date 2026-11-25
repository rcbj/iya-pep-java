// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.credential;

/** The three audiences a token is asked for. */
public enum Audience {
    /** {@code /xacml/pep/*} and {@code POST /xacml/pip}: {@code xacml:pep}. */
    PEP,
    /** {@code POST /admin-api/pep-audit}: {@code xacml:pep-audit}. */
    AUDIT,
    /** {@code POST /access/v1/evaluation}: {@code authzen:evaluate}. */
    ACCESS;

    public static final Audience[] ALL = {PEP, AUDIT, ACCESS};

    int index() {
        return ordinal();
    }

    /** The resource indicator's path under the PDP URL. */
    public String path() {
        return switch (this) {
            case PEP -> "/xacml/pep";
            case AUDIT -> "/admin-api";
            case ACCESS -> "/access/v1";
        };
    }

    public String scope() {
        return switch (this) {
            case PEP -> "xacml:pep";
            case AUDIT -> "xacml:pep-audit";
            case ACCESS -> "authzen:evaluate";
        };
    }
}
