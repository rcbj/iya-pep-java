// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** A compiled set of policies: the root and everything it references. */
public final class Policies {
    final Tree tree;
    private final int documents;

    private Policies(Tree tree, int documents) {
        this.tree = tree;
        this.documents = documents;
    }

    /**
     * Parses and compiles a pulled set. Exactly one row is the root; a reference
     * resolves to another row of the set by {@code policyId}.
     */
    public static Policies compile(List<PolicyDocument> rows) throws CompileException {
        return new Policies(Compiler.compile(rows), rows.size());
    }

    /**
     * Evaluates the root against {@code request}. {@code now} is the instant
     * {@code current-time}, {@code current-date} and {@code current-dateTime} come from.
     */
    public Response evaluate(Request request, Instant now, Resolver resolver) {
        return Eval.evaluate(tree, request, unixSeconds(now), resolver);
    }

    /**
     * Every designator in {@code category} the compiled set could ask for, found
     * statically. Over-fetches; never misses one.
     */
    public List<Designator> designators(String category) {
        List<Designator> found = new ArrayList<>();
        for (Designator designator : tree.designators) {
            if (designator.category.equals(category)) {
                found.add(designator);
            }
        }
        Collections.sort(found);
        return found;
    }

    /** How many Policy and PolicySet documents were compiled. */
    public int size() {
        return documents;
    }

    public boolean isEmpty() {
        return size() == 0;
    }

    /**
     * Signed unix seconds, sub-second part dropped toward zero, matching a
     * duration measured from the epoch.
     */
    static long unixSeconds(Instant now) {
        long epoch = now.getEpochSecond();
        if (epoch >= 0) {
            return epoch;
        }
        long abs = now.getNano() == 0 ? -epoch : -epoch - 1;
        return -abs;
    }
}
