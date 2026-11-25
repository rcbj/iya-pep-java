// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

/**
 * A refusal of a catalogue row or of an evaluation: the HTTP status the
 * service would answer, its {@code STS-AUTHZEN-*} code, and the sentence.
 */
public final class Refusal extends Exception {
    public final int status;
    public final String code;
    public final String message;

    public Refusal(int status, String code, String message) {
        super(code + ": " + message);
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
