// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The decision. A Permit is the only yes. A Deny and an Unavailable are
 * both a no: an enforcement point that cannot say yes says no.
 */
public final class Decision {
    public enum Kind {
        PERMIT,
        DENY,
        UNAVAILABLE
    }

    private final Kind kind;
    private final String why;
    private final List<Obligation> obligations;
    private final List<Obligation> advice;

    private Decision(Kind kind, String why, List<Obligation> obligations, List<Obligation> advice) {
        this.kind = kind;
        this.why = why == null ? "" : why;
        this.obligations = obligations == null ? List.of() : List.copyOf(obligations);
        this.advice = advice == null ? List.of() : List.copyOf(advice);
    }

    /**
     * Allowed. Every obligation is of a type the host declared, and must be
     * discharged before the access is given. Advice may be ignored.
     */
    public static Decision permit(List<Obligation> obligations, List<Obligation> advice) {
        return new Decision(Kind.PERMIT, "", obligations, advice);
    }

    /** Refused by policy, or a request the service would refuse. */
    public static Decision deny(String why) {
        return new Decision(Kind.DENY, why, List.of(), List.of());
    }

    /** No decision could be made. Fail closed. */
    public static Decision unavailable(String why) {
        return new Decision(Kind.UNAVAILABLE, why, List.of(), List.of());
    }

    public Kind kind() {
        return kind;
    }

    public String why() {
        return why;
    }

    public List<Obligation> obligations() {
        return obligations;
    }

    public List<Obligation> advice() {
        return advice;
    }

    /** {@code true} only for a Permit. */
    public boolean isPermit() {
        return kind == Kind.PERMIT;
    }

    /**
     * The HTTP status a host answers with: 200 for a Permit and 403 for
     * everything else. A failure is never a 5xx a client might retry into
     * a different answer. Whether the user was signed in (401) is the
     * host's question, asked before the PEP is.
     */
    public int httpStatus() {
        return isPermit() ? 200 : 403;
    }

    /** A copy, so a cached Permit is not changed by a caller. */
    public Decision copy() {
        if (kind != Kind.PERMIT) {
            return this;
        }
        return permit(copyAll(obligations), copyAll(advice));
    }

    private static List<Obligation> copyAll(List<Obligation> obligations) {
        List<Obligation> copy = new ArrayList<>(obligations.size());
        for (Obligation obligation : obligations) {
            copy.add(new Obligation(obligation.id, obligation.kind, obligation.properties.deepCopy()));
        }
        return Collections.unmodifiableList(copy);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Decision decision)) {
            return false;
        }
        return kind == decision.kind
                && why.equals(decision.why)
                && obligations.equals(decision.obligations)
                && advice.equals(decision.advice);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, why, obligations, advice);
    }

    @Override
    public String toString() {
        if (kind == Kind.PERMIT) {
            return "Permit{obligations=" + obligations + ", advice=" + advice + "}";
        }
        return kind + "{why=" + why + "}";
    }
}
