// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.fasterxml.jackson.databind.node.ObjectNode;

/** An obligation handed to the caller under the Obligations Profile. */
public final class Handed {
    /** The registered type ({@code step-up}, ...) or {@code custom}. */
    public final String kind;
    /** The AuthZEN obligation object, as the service would hand it. */
    public final ObjectNode obligation;

    public Handed(String kind, ObjectNode obligation) {
        this.kind = kind;
        this.obligation = obligation;
    }
}
