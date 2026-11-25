// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/** One category of a request. A category may appear more than once. */
public final class Category {
    public final String category;
    /** The category carried a Content element. No XPath is evaluated over it. */
    public final boolean hasContent;
    public final List<Attribute> attributes;

    public Category(String category, boolean hasContent, List<Attribute> attributes) {
        this.category = category;
        this.hasContent = hasContent;
        this.attributes = attributes;
    }
}
