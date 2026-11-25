// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

/** Why a set of policies could not be compiled. The PEP keeps the set it held before. */
public final class CompileException extends Exception {
    public final String policyId;
    public final String message;

    public CompileException(String policyId, String message) {
        super("policy " + policyId + ": " + message);
        this.policyId = policyId;
        this.message = message;
    }
}
