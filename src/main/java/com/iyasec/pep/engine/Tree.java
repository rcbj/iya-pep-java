// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.List;

/** A rule's effect, and the decision an obligation or advice fires on. */
enum Effect {
    PERMIT,
    DENY;

    static Effect parse(String text) {
        return switch (text) {
            case "Permit" -> PERMIT;
            case "Deny" -> DENY;
            default -> null;
        };
    }
}

/** A combining algorithm. Legacy algorithms carry the overriding effect. */
final class Alg {
    enum Kind {
        DENY_OVERRIDES,
        PERMIT_OVERRIDES,
        DENY_UNLESS_PERMIT,
        PERMIT_UNLESS_DENY,
        FIRST_APPLICABLE,
        ONLY_ONE_APPLICABLE,
        LEGACY_RULE_OVERRIDES,
        LEGACY_POLICY_OVERRIDES
    }

    final Kind kind;
    final Effect effect;

    private Alg(Kind kind, Effect effect) {
        this.kind = kind;
        this.effect = effect;
    }

    static Alg of(Kind kind) {
        return new Alg(kind, null);
    }

    static Alg legacyRule(Effect effect) {
        return new Alg(Kind.LEGACY_RULE_OVERRIDES, effect);
    }

    static Alg legacyPolicy(Effect effect) {
        return new Alg(Kind.LEGACY_POLICY_OVERRIDES, effect);
    }
}

/** One Match: the function, the literal, and the attribute. */
final class Match {
    final Func func;
    final Expr literal;
    final Expr attribute;

    Match(Func func, Expr literal, Expr attribute) {
        this.func = func;
        this.literal = literal;
        this.attribute = attribute;
    }
}

/** An AttributeAssignmentExpression, compiled. */
final class AssignmentExpr {
    final String attributeId;
    final String category;
    final String issuer;
    final Expr expr;

    AssignmentExpr(String attributeId, String category, String issuer, Expr expr) {
        this.attributeId = attributeId;
        this.category = category;
        this.issuer = issuer;
        this.expr = expr;
    }
}

/** An ObligationExpression or AdviceExpression. {@code on} neither Permit nor Deny never fires. */
final class Holder {
    final String id;
    final Effect on;
    final List<AssignmentExpr> assignments;

    Holder(String id, Effect on, List<AssignmentExpr> assignments) {
        this.id = id;
        this.on = on;
        this.assignments = assignments;
    }
}

/** A rule. */
final class Rule {
    final Effect effect;
    final List<List<List<Match>>> target;
    final Expr condition;
    final List<Holder> obligations;
    final List<Holder> advice;

    Rule(Effect effect, List<List<List<Match>>> target, Expr condition, List<Holder> obligations, List<Holder> advice) {
        this.effect = effect;
        this.target = target;
        this.condition = condition;
        this.obligations = obligations;
        this.advice = advice;
    }
}

/** A policy's rules, or a policy set's children (arena indices). */
interface Body {
    final class Rules implements Body {
        final List<Rule> rules;

        Rules(List<Rule> rules) {
            this.rules = rules;
        }
    }

    final class Children implements Body {
        final List<Integer> children;

        Children(List<Integer> children) {
            this.children = children;
        }
    }
}

/** A Policy or PolicySet. */
final class Node {
    final String id;
    final List<List<List<Match>>> target;
    final Alg alg;
    final Body body;
    /** Skips children whose target cannot match. Null when fewer than two children are keyed. */
    TargetIndex index;
    final List<Holder> obligations;
    final List<Holder> advice;

    Node(
            String id,
            List<List<List<Match>>> target,
            Alg alg,
            Body body,
            List<Holder> obligations,
            List<Holder> advice) {
        this.id = id;
        this.target = target;
        this.alg = alg;
        this.body = body;
        this.obligations = obligations;
        this.advice = advice;
    }
}

/** The compiled set. */
final class Tree {
    final List<Node> nodes;
    final int root;
    final List<Expr> variables;
    final List<Designator> designators;
    final List<Type> designatorTypes;

    Tree(List<Node> nodes, int root, List<Expr> variables, List<Designator> designators, List<Type> designatorTypes) {
        this.nodes = nodes;
        this.root = root;
        this.variables = variables;
        this.designators = designators;
        this.designatorTypes = designatorTypes;
    }
}
