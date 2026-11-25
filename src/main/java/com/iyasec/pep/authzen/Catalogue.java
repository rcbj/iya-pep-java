// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/** The realm's catalogue as the PEP holds it. */
public final class Catalogue {
    public final List<Row> rows;
    /** The realm's {@code authzen.obligationsProfile}. Absent is off. */
    public final boolean obligationsProfile;
    /**
     * {@code fgaApplications}: the applications that enforce fine-grained
     * authorization.
     */
    public final List<String> fgaApplications;

    public Catalogue(List<Row> rows, boolean obligationsProfile, List<String> fgaApplications) {
        this.rows = rows == null ? new ArrayList<>() : rows;
        this.obligationsProfile = obligationsProfile;
        this.fgaApplications = fgaApplications == null ? new ArrayList<>() : fgaApplications;
    }

    public Catalogue() {
        this(new ArrayList<>(), false, new ArrayList<>());
    }

    /**
     * Reads the catalogue pull's body. A row the grammar refuses, and a second
     * row for an object and property already held, is left out. A body that is
     * not a catalogue at all is refused whole.
     */
    public static Catalogue fromPull(JsonNode body) throws Refusal {
        if (body == null || body.get("rows") == null || !body.get("rows").isArray()) {
            throw new Refusal(500, "STS-AUTHZEN-0010",
                    "The catalogue pull's answer is not an AuthZEN catalogue: it has no rows array.");
        }
        List<Row> rows = new ArrayList<>();
        for (JsonNode value : body.get("rows")) {
            try {
                Row row = Row.read(value);
                boolean duplicate = false;
                for (Row held : rows) {
                    if (held.object.equals(row.object) && held.property.equals(row.property)) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    rows.add(row);
                }
            } catch (Refusal ignored) {
                // An undeclared property is then refused on a request that names it.
            }
        }
        JsonNode profile = body.at("/settings/obligationsProfile");
        boolean obligationsProfile = profile != null && profile.isBoolean() && profile.booleanValue();
        List<String> fga = new ArrayList<>();
        JsonNode applications = body.get("fgaApplications");
        if (applications != null && applications.isArray()) {
            for (JsonNode item : applications) {
                if (item.isTextual()) {
                    fga.add(item.asText());
                }
            }
        }
        return new Catalogue(rows, obligationsProfile, fga);
    }
}
