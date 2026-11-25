// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.http;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/** A request body. */
public final class Body {
    public enum Kind { JSON, FORM, XML }

    public final Kind kind;
    public final JsonNode json;
    public final List<Field> form;
    public final String xml;

    private Body(Kind kind, JsonNode json, List<Field> form, String xml) {
        this.kind = kind;
        this.json = json;
        this.form = form;
        this.xml = xml;
    }

    public static Body json(JsonNode json) {
        return new Body(Kind.JSON, json, null, null);
    }

    public static Body form(List<Field> form) {
        return new Body(Kind.FORM, null, form, null);
    }

    public static Body xml(String xml) {
        return new Body(Kind.XML, null, null, xml);
    }
}
