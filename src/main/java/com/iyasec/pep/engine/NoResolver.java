// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/** No resolver: every designator the request does not satisfy is an empty bag. */
public final class NoResolver implements Resolver {
    @Override
    public List<AttributeValue> resolve(Designator designator) {
        return null;
    }
}
