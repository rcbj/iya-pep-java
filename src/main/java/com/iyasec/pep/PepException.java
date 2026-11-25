// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

/**
 * An error the package reports. {@code code} is a short, stable category:
 * {@code config}, {@code transport}, {@code refused}, or {@code policy}.
 */
public final class PepException extends Exception {
    private final String code;
    private final String detail;

    public PepException(String code, String detail) {
        super(code + ": " + detail);
        this.code = code;
        this.detail = detail;
    }

    public String code() {
        return code;
    }

    /** The message without the code, as the Rust {@code PepError.message}. */
    public String detail() {
        return detail;
    }
}
