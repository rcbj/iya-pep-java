// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

/** The decision. Extended Indeterminates are folded into {@link #INDETERMINATE}. */
public enum Decision {
    PERMIT,
    DENY,
    NOT_APPLICABLE,
    INDETERMINATE;

    public String asString() {
        return switch (this) {
            case PERMIT -> "Permit";
            case DENY -> "Deny";
            case NOT_APPLICABLE -> "NotApplicable";
            case INDETERMINATE -> "Indeterminate";
        };
    }

    @Override
    public String toString() {
        return asString();
    }
}
