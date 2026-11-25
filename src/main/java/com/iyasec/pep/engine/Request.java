// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.ArrayList;
import java.util.List;

/** A request, built in code. */
public final class Request {
    public final boolean returnPolicyIdList;
    public final boolean combinedDecision;
    public final List<Category> categories;

    public Request(boolean returnPolicyIdList, boolean combinedDecision, List<Category> categories) {
        this.returnPolicyIdList = returnPolicyIdList;
        this.combinedDecision = combinedDecision;
        this.categories = categories;
    }

    public Request() {
        this(false, false, new ArrayList<>());
    }
}
