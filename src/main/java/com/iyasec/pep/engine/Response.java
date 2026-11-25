// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/** The answer to one request. */
public final class Response {
    public final Decision decision;
    public final List<Obligation> obligations;
    public final List<Obligation> advice;
    /**
     * The XACML status code of the decision: {@code urn:oasis:names:tc:xacml:1.0:status:ok},
     * or for an Indeterminate the one that caused it.
     */
    public final String statusCode;

    public Response(Decision decision, List<Obligation> obligations, List<Obligation> advice, String statusCode) {
        this.decision = decision;
        this.obligations = obligations;
        this.advice = advice;
        this.statusCode = statusCode;
    }

    @Override
    public String toString() {
        return decision.asString() + " " + statusCode;
    }
}
