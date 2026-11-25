// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

/** The category, datatype and status URNs the engine shares with its callers. */
public final class Names {
    private Names() {}

    /** The canonical XACML 3.0 category of the access subject. */
    public static final String ACCESS_SUBJECT =
            "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
    /** The resource category. */
    public static final String RESOURCE = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource";
    /** The action category. */
    public static final String ACTION = "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
    /** The environment category. */
    public static final String ENVIRONMENT = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment";
    /** The status code of every decision that is not Indeterminate. */
    public static final String STATUS_OK = "urn:oasis:names:tc:xacml:1.0:status:ok";
    /** {@code http://www.w3.org/2001/XMLSchema#string}. */
    public static final String STRING = "http://www.w3.org/2001/XMLSchema#string";
}
