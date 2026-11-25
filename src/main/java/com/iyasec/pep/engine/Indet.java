// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

/** An evaluation failure: the expression is Indeterminate. */
final class Indet extends RuntimeException {
    final Status status;
    final String detail;

    private Indet(Status status, String detail) {
        super(detail);
        this.status = status;
        this.detail = detail;
    }

    /** Indeterminate is a result, not a defect; skip the trace. */
    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }

    static Indet processing(String message) {
        return new Indet(Status.PROCESSING_ERROR, message);
    }

    static Indet syntax(String message) {
        return new Indet(Status.SYNTAX_ERROR, message);
    }

    static Indet missing(String message) {
        return new Indet(Status.MISSING_ATTRIBUTE, message);
    }
}
