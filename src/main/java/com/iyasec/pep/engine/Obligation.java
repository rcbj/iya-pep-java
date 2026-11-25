// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/** An obligation or an advice. */
public final class Obligation {
    public final String id;
    public final List<Assignment> assignments;

    public Obligation(String id, List<Assignment> assignments) {
        this.id = id;
        this.assignments = assignments;
    }

    @Override
    public String toString() {
        return id + assignments;
    }
}
