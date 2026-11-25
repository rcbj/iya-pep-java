// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

/** Why an Indeterminate is one: the XACML status code it reports. */
enum Status {
    MISSING_ATTRIBUTE("urn:oasis:names:tc:xacml:1.0:status:missing-attribute"),
    SYNTAX_ERROR("urn:oasis:names:tc:xacml:1.0:status:syntax-error"),
    PROCESSING_ERROR("urn:oasis:names:tc:xacml:1.0:status:processing-error");

    private final String uri;

    Status(String uri) {
        this.uri = uri;
    }

    String uri() {
        return uri;
    }
}
