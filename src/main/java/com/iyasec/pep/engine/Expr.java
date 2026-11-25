// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/** A compiled expression. A literal that does not parse stays, and is Indeterminate when evaluated. */
interface Expr {
    final class Literal implements Expr {
        final Bag bag;

        Literal(Bag bag) {
            this.bag = bag;
        }
    }

    final class BadLiteral implements Expr {
        static final BadLiteral INSTANCE = new BadLiteral();

        private BadLiteral() {}
    }

    final class DesignatorExpr implements Expr {
        final int id;
        final boolean mustBePresent;

        DesignatorExpr(int id, boolean mustBePresent) {
            this.id = id;
            this.mustBePresent = mustBePresent;
        }
    }

    /** An AttributeSelector. No XPath is evaluated, so it is Indeterminate. */
    final class Selector implements Expr {
        static final Selector INSTANCE = new Selector();

        private Selector() {}
    }

    final class Variable implements Expr {
        final int index;

        Variable(int index) {
            this.index = index;
        }
    }

    final class Apply implements Expr {
        final Func func;
        final List<Expr> args;

        Apply(Func func, List<Expr> args) {
            this.func = func;
            this.args = args;
        }
    }

    /** A function passed to a higher-order function. */
    final class FunctionRef implements Expr {
        final Func func;

        FunctionRef(Func func) {
            this.func = func;
        }
    }
}
