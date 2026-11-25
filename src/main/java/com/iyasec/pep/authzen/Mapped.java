// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.iyasec.pep.engine.Request;

import java.util.List;

/** One evaluation, mapped. */
public final class Mapped {
    public final Request request;
    /** {@code context.supported_obligations}, when the evaluation carried it. Null when absent. */
    public final List<String> supportedObligations;

    public Mapped(Request request, List<String> supportedObligations) {
        this.request = request;
        this.supportedObligations = supportedObligations;
    }
}
