// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.ArrayList;
import java.util.List;

/** A bag: its type and its values. Every value the engine handles is a bag. */
final class Bag {
    final Type ty;
    final List<Values.Value> values;

    private Bag(Type ty, List<Values.Value> values) {
        this.ty = ty;
        this.values = values;
    }

    static Bag empty(Type ty) {
        return new Bag(ty, List.of());
    }

    static Bag one(Type ty, Values.Value value) {
        return new Bag(ty, List.of(value));
    }

    static Bag bool(boolean value) {
        return one(Type.BOOLEAN, new Values.Value.Bool(value));
    }

    static Bag fromList(Type ty, List<Values.Value> values) {
        if (values.isEmpty()) {
            return empty(ty);
        }
        if (values.size() == 1) {
            return one(ty, values.get(0));
        }
        return new Bag(ty, List.copyOf(values));
    }

    int len() {
        return values.size();
    }

    /** The bag's one value, or Indeterminate. */
    Values.Value single() {
        if (values.size() != 1) {
            throw Indet.processing("a single-value argument was given a bag of zero or several");
        }
        return values.get(0);
    }

    /** Exactly one boolean. */
    boolean asBoolean() {
        if (ty == Type.BOOLEAN && values.size() == 1 && values.get(0) instanceof Values.Value.Bool b) {
            return b.value();
        }
        throw Indet.processing("expected exactly one boolean");
    }
}
