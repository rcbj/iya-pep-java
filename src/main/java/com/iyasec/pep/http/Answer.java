// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.iyasec.pep.Json;

/** One HTTP answer. Any status is an answer; only a transport failure is an error. */
public final class Answer {
    public int status;
    public String contentType = "";
    public String body = "";
    /** {@code DPoP-Nonce}, or empty. */
    public String dpopNonce = "";
    /** {@code WWW-Authenticate}, every value joined, or empty. */
    public String wwwAuthenticate = "";
    /** {@code ETag}, or empty. */
    public String etag = "";

    public JsonNode json() {
        return Json.parse(body);
    }
}
