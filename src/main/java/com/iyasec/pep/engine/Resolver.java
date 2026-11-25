// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/**
 * Answers a designator the request does not satisfy. {@code null} is an empty bag.
 * The PEP fetches every access-subject designator before evaluation, so this is synchronous.
 */
public interface Resolver {
    List<AttributeValue> resolve(Designator designator);
}
