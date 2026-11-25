// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.iyasec.pep.engine.Decision;

import java.util.ArrayList;
import java.util.List;

/** A decision mapped back, fail-closed. */
public final class Outcome {
    /** {@code true} only on a Permit carrying nothing that cannot be discharged or handed. */
    public final boolean decision;
    /** An Indeterminate from a processing or syntax error: not a denial. */
    public final boolean fault;
    /** The XACML decision, for the record. */
    public final Decision xacmlDecision;
    /** Why, in a sentence. */
    public final String why;
    /** {@code urn:sts:xacml:obligation:log} and the like: discharged here. */
    public final List<String> discharged;
    /** Obligation ids that stopped a Permit. */
    public final List<String> undischargeable;
    /** Handed to the caller (the Obligations Profile). */
    public final List<Handed> handed;
    /**
     * Why an obligation could not be built for the Obligations Profile.
     * Any one means nothing is handed.
     */
    public final List<String> obligationProblems;

    public Outcome(boolean decision, boolean fault, Decision xacmlDecision, String why,
                   List<String> discharged, List<String> undischargeable, List<Handed> handed,
                   List<String> obligationProblems) {
        this.decision = decision;
        this.fault = fault;
        this.xacmlDecision = xacmlDecision;
        this.why = why;
        this.discharged = discharged;
        this.undischargeable = undischargeable;
        this.handed = handed;
        this.obligationProblems = obligationProblems == null ? new ArrayList<>() : obligationProblems;
    }
}
