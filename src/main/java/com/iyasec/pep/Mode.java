// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

/** Who decides. */
public enum Mode {
    /** Every decision is an AuthZEN evaluation at the service. */
    CENTRAL,
    /** The engine decides in process over the bound application's policies. */
    LOCAL;

    public String asString() {
        return this == CENTRAL ? "central" : "local";
    }

    public static Mode parse(String text) throws PepException {
        if ("central".equals(text)) {
            return CENTRAL;
        }
        if ("local".equals(text)) {
            return LOCAL;
        }
        throw new PepException("config",
                "pep.mode is \"" + text + "\"; it must be central or local");
    }
}
