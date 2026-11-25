// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import com.iyasec.pep.engine.Values.Value;
import java.util.ArrayList;
import java.util.List;

/** Evaluation of one request against the compiled tree. */
final class Eval {
    private static final String CURRENT_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-time";
    private static final String CURRENT_DATE = "urn:oasis:names:tc:xacml:1.0:environment:current-date";
    private static final String CURRENT_DATE_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";

    /** The seven decisions. A plain Indeterminate behaves as {DP}. */
    private enum Ext {
        PERMIT,
        DENY,
        NOT_APPLICABLE,
        IND_D,
        IND_P,
        IND_DP;

        boolean indeterminate() {
            return this == IND_D || this == IND_P || this == IND_DP;
        }

        static Ext of(Effect effect) {
            return effect == Effect.PERMIT ? PERMIT : DENY;
        }

        /** A rule that cannot be evaluated could only have produced its effect. */
        static Ext failed(Effect effect) {
            return effect == Effect.PERMIT ? IND_P : IND_D;
        }
    }

    private enum MatchResult {
        MATCH,
        NO_MATCH,
        INDETERMINATE
    }

    private static final class Outcome {
        final Ext decision;
        final Status status;
        final List<Obligation> obligations;
        final List<Obligation> advice;

        Outcome(Ext decision, Status status, List<Obligation> obligations, List<Obligation> advice) {
            this.decision = decision;
            this.status = status;
            this.obligations = obligations;
            this.advice = advice;
        }

        static Outcome of(Ext decision) {
            return new Outcome(decision, null, new ArrayList<>(), new ArrayList<>());
        }

        static Outcome failed(Ext decision, Indet error) {
            return new Outcome(decision, error.status, new ArrayList<>(), new ArrayList<>());
        }
    }

    private static final class TargetResult {
        final MatchResult result;
        final Indet error;

        TargetResult(MatchResult result, Indet error) {
            this.result = result;
            this.error = error;
        }
    }

    private static final class Slot {
        Bag bag;
        Indet error;
    }

    private static final class Gathered {
        Status status;
        final List<Obligation> permitObligations = new ArrayList<>();
        final List<Obligation> permitAdvice = new ArrayList<>();
        final List<Obligation> denyObligations = new ArrayList<>();
        final List<Obligation> denyAdvice = new ArrayList<>();

        Ext add(Outcome outcome) {
            if (status == null) {
                status = outcome.status;
            }
            if (outcome.decision == Ext.PERMIT) {
                permitObligations.addAll(outcome.obligations);
                permitAdvice.addAll(outcome.advice);
            } else if (outcome.decision == Ext.DENY) {
                denyObligations.addAll(outcome.obligations);
                denyAdvice.addAll(outcome.advice);
            }
            return outcome.decision;
        }

        Outcome finish(Ext decision) {
            List<Obligation> obligations;
            List<Obligation> advice;
            if (decision == Ext.PERMIT) {
                obligations = permitObligations;
                advice = permitAdvice;
            } else if (decision == Ext.DENY) {
                obligations = denyObligations;
                advice = denyAdvice;
            } else {
                obligations = new ArrayList<>();
                advice = new ArrayList<>();
            }
            return new Outcome(decision, status, obligations, advice);
        }
    }

    private static final class Picked {
        final Outcome outcome;
        final boolean refusal;

        Picked(Outcome outcome, boolean refusal) {
            this.outcome = outcome;
            this.refusal = refusal;
        }
    }

    @FunctionalInterface
    private interface Child {
        Outcome at(int index);
    }

    private final Tree tree;
    private final Request request;
    private final Resolver resolver;
    private final long now;
    private final Slot[] bags;
    private final Slot[] variables;

    private Eval(Tree tree, Request request, long now, Resolver resolver) {
        this.tree = tree;
        this.request = request;
        this.resolver = resolver;
        this.now = now;
        this.bags = new Slot[tree.designators.size()];
        this.variables = new Slot[tree.variables.size()];
    }

    static Response evaluate(Tree tree, Request request, long now, Resolver resolver) {
        Eval eval = new Eval(tree, request, now, resolver);
        Outcome outcome;
        try {
            outcome = eval.node(tree.root);
        } catch (Indet error) {
            outcome = Outcome.failed(Ext.IND_DP, error);
        }
        Decision decision = switch (outcome.decision) {
            case PERMIT -> Decision.PERMIT;
            case DENY -> Decision.DENY;
            case NOT_APPLICABLE -> Decision.NOT_APPLICABLE;
            case IND_D, IND_P, IND_DP -> Decision.INDETERMINATE;
        };
        String statusCode = decision == Decision.INDETERMINATE && outcome.status != null
                ? outcome.status.uri()
                : Names.STATUS_OK;
        return new Response(decision, outcome.obligations, outcome.advice, statusCode);
    }

    private Bag designator(int id) {
        Slot slot = id >= 0 && id < bags.length ? bags[id] : null;
        if (slot != null) {
            if (slot.error != null) {
                throw slot.error;
            }
            return slot.bag;
        }
        Bag bag = null;
        Indet error = null;
        try {
            bag = resolve(id);
        } catch (Indet caught) {
            error = caught;
        }
        if (id >= 0 && id < bags.length) {
            Slot filled = new Slot();
            filled.bag = bag;
            filled.error = error;
            bags[id] = filled;
        }
        if (error != null) {
            throw error;
        }
        return bag;
    }

    private Bag resolve(int id) {
        Designator designator = tree.designators.get(id);
        Type type = tree.designatorTypes.get(id);
        List<Value> values = new ArrayList<>();
        if (request.categories != null) {
            for (Category category : request.categories) {
                if (category == null || !designator.category.equals(category.category) || category.attributes == null) {
                    continue;
                }
                for (Attribute attribute : category.attributes) {
                    if (attribute == null || !designator.attributeId.equals(attribute.attributeId)) {
                        continue;
                    }
                    if (designator.issuer != null && !designator.issuer.equals(attribute.issuer)) {
                        continue;
                    }
                    if (attribute.values == null) {
                        continue;
                    }
                    for (AttributeValue value : attribute.values) {
                        take(type, designator.dataType, value, values);
                    }
                }
            }
        }
        if (values.isEmpty()) {
            List<AttributeValue> resolved = resolver.resolve(designator);
            if (resolved != null) {
                for (AttributeValue value : resolved) {
                    take(type, designator.dataType, value, values);
                }
            }
        }
        if (values.isEmpty() && Names.ENVIRONMENT.equals(designator.category)) {
            Values.Shape shape = null;
            if (CURRENT_DATE_TIME.equals(designator.attributeId) && type == Type.DATE_TIME) {
                shape = Values.Shape.DATE_TIME;
            } else if (CURRENT_DATE.equals(designator.attributeId) && type == Type.DATE) {
                shape = Values.Shape.DATE;
            } else if (CURRENT_TIME.equals(designator.attributeId) && type == Type.TIME) {
                shape = Values.Shape.TIME;
            }
            if (shape != null) {
                values.add(new Value.TemporalVal(Values.nowTemporal(now, shape)));
            }
        }
        return Bag.fromList(type, values);
    }

    private static void take(Type type, String dataType, AttributeValue value, List<Value> values) {
        if (value == null || !Values.canonicalUri(value.dataType).equals(dataType)) {
            return;
        }
        Value parsed = Values.parse(type, value.value);
        if (parsed == null) {
            throw Indet.syntax("a request value is not a valid lexical form of its type");
        }
        values.add(parsed);
    }

    private Bag variable(int index) {
        if (index < 0 || index >= variables.length) {
            throw Indet.syntax("an unknown variable");
        }
        Slot slot = variables[index];
        if (slot != null) {
            if (slot.error != null) {
                throw slot.error;
            }
            return slot.bag;
        }
        Bag bag = null;
        Indet error = null;
        try {
            Expr expr = tree.variables.get(index);
            bag = expr == null ? null : expr(expr);
            if (bag == null) {
                throw Indet.syntax("an unknown variable");
            }
        } catch (Indet caught) {
            error = caught;
        }
        Slot filled = new Slot();
        filled.bag = bag;
        filled.error = error;
        variables[index] = filled;
        if (error != null) {
            throw error;
        }
        return bag;
    }

    private Bag expr(Expr expr) {
        if (expr instanceof Expr.Literal literal) {
            return literal.bag;
        }
        if (expr instanceof Expr.BadLiteral) {
            throw Indet.syntax("a literal is not a valid lexical form of its type");
        }
        if (expr instanceof Expr.DesignatorExpr designator) {
            Bag bag = designator(designator.id);
            if (designator.mustBePresent && bag.len() == 0) {
                throw Indet.missing("a MustBePresent attribute is absent");
            }
            return bag;
        }
        if (expr instanceof Expr.Selector) {
            throw Indet.processing("AttributeSelector needs XPath, which this engine does not evaluate");
        }
        if (expr instanceof Expr.Variable variable) {
            return variable(variable.index);
        }
        if (expr instanceof Expr.FunctionRef) {
            throw Indet.syntax("a <Function> is only an argument of a higher-order function");
        }
        if (expr instanceof Expr.Apply apply) {
            if (apply.func.isLazy()) {
                return Functions.callLazy(apply.func, apply.args, this::expr);
            }
            List<Bag> args = new ArrayList<>(apply.args.size());
            for (Expr arg : apply.args) {
                args.add(expr(arg));
            }
            return Functions.call(apply.func, args);
        }
        throw Indet.processing("an expression could not be evaluated");
    }

    private boolean matches(Match match) {
        Bag bag = expr(match.attribute);
        Bag literal = expr(match.literal);
        Indet first = null;
        for (Value value : bag.values) {
            try {
                Bag result = Functions.call(match.func, List.of(literal, Bag.one(bag.ty, value)));
                if (result.values.size() == 1 && result.values.get(0) instanceof Value.Bool bool && bool.value()) {
                    return true;
                }
            } catch (Indet error) {
                if (first == null) {
                    first = error;
                }
            }
        }
        if (first != null) {
            throw first;
        }
        return false;
    }

    /** A false Match settles its AllOf, and a No-match AnyOf settles the target, errors included. */
    private TargetResult target(List<List<List<Match>>> target) {
        Indet error = null;
        for (List<List<Match>> anyOf : target) {
            Indet anyError = null;
            boolean indeterminate = false;
            boolean matched = false;
            for (List<Match> allOf : anyOf) {
                Indet allError = null;
                boolean noMatch = false;
                for (Match match : allOf) {
                    try {
                        if (!matches(match)) {
                            noMatch = true;
                            break;
                        }
                    } catch (Indet caught) {
                        if (allError == null) {
                            allError = caught;
                        }
                    }
                }
                if (noMatch) {
                    continue;
                }
                if (allError == null) {
                    matched = true;
                    break;
                }
                indeterminate = true;
                if (anyError == null) {
                    anyError = allError;
                }
            }
            if (matched) {
                continue;
            }
            if (!indeterminate) {
                return new TargetResult(MatchResult.NO_MATCH, null);
            }
            if (error == null) {
                error = anyError != null ? anyError : Indet.processing("a Target could not be evaluated");
            }
        }
        if (error != null) {
            return new TargetResult(MatchResult.INDETERMINATE, error);
        }
        return new TargetResult(MatchResult.MATCH, null);
    }

    private Outcome rule(Rule rule) {
        Ext failed = Ext.failed(rule.effect);
        TargetResult matched = target(rule.target);
        if (matched.result == MatchResult.NO_MATCH) {
            return Outcome.of(Ext.NOT_APPLICABLE);
        }
        if (matched.result == MatchResult.INDETERMINATE) {
            Indet error = matched.error != null ? matched.error : Indet.processing("a Target could not be evaluated");
            return Outcome.failed(failed, error);
        }
        if (rule.condition != null) {
            Bag bag;
            try {
                bag = expr(rule.condition);
            } catch (Indet error) {
                return Outcome.failed(failed, error);
            }
            boolean holds;
            try {
                holds = bag.asBoolean();
            } catch (Indet error) {
                return Outcome.failed(failed, Indet.processing("a Condition must evaluate to exactly one boolean"));
            }
            if (!holds) {
                return Outcome.of(Ext.NOT_APPLICABLE);
            }
        }
        Ext decision = Ext.of(rule.effect);
        try {
            List<Obligation> obligations = collect(rule.obligations, decision);
            List<Obligation> advice = collect(rule.advice, decision);
            return new Outcome(decision, null, obligations, advice);
        } catch (Indet error) {
            return Outcome.failed(failed, error);
        }
    }

    private Outcome node(int index) {
        Node current = tree.nodes.get(index);
        TargetResult matched = target(current.target);
        if (matched.result == MatchResult.NO_MATCH) {
            return Outcome.of(Ext.NOT_APPLICABLE);
        }
        if (matched.result == MatchResult.INDETERMINATE) {
            Indet error = matched.error != null ? matched.error : Indet.processing("a Target could not be evaluated");
            return Outcome.failed(Ext.IND_DP, error);
        }
        boolean[] candidates = current.index == null ? null : current.index.candidates(this::designator);
        if (current.body instanceof Body.Rules rules) {
            return attach(current, combine(current, rules.rules.size(), i -> {
                if (skip(candidates, i)) {
                    return Outcome.of(Ext.NOT_APPLICABLE);
                }
                return rule(rules.rules.get(i));
            }));
        }
        Body.Children children = (Body.Children) current.body;
        if (current.alg.kind == Alg.Kind.ONLY_ONE_APPLICABLE) {
            Picked picked = onlyOne(children.children, candidates);
            if (picked.refusal) {
                return picked.outcome;
            }
            return attach(current, picked.outcome);
        }
        return attach(current, combine(current, children.children.size(), i -> {
            if (skip(candidates, i)) {
                return Outcome.of(Ext.NOT_APPLICABLE);
            }
            return node(children.children.get(i));
        }));
    }

    /** Which children apply is settled before any is evaluated: two applying is the error. */
    private Picked onlyOne(List<Integer> children, boolean[] candidates) {
        Integer selected = null;
        for (int i = 0; i < children.size(); i++) {
            if (skip(candidates, i)) {
                continue;
            }
            int child = children.get(i);
            TargetResult matched = target(tree.nodes.get(child).target);
            if (matched.result == MatchResult.INDETERMINATE) {
                Indet error = matched.error != null ? matched.error : Indet.processing("a Target could not be evaluated");
                return new Picked(Outcome.failed(Ext.IND_DP, error), true);
            }
            if (matched.result == MatchResult.MATCH) {
                if (selected != null) {
                    return new Picked(
                            Outcome.failed(
                                    Ext.IND_DP,
                                    Indet.processing("more than one policy of an only-one-applicable set applies")),
                            true);
                }
                selected = child;
            }
        }
        if (selected == null) {
            return new Picked(Outcome.of(Ext.NOT_APPLICABLE), false);
        }
        return new Picked(node(selected), false);
    }

    /** The node's own obligations and advice, when the decision is Permit or Deny. */
    private Outcome attach(Node node, Outcome outcome) {
        if (outcome.decision == Ext.PERMIT || outcome.decision == Ext.DENY) {
            outcome.obligations.addAll(collect(node.obligations, outcome.decision));
            outcome.advice.addAll(collect(node.advice, outcome.decision));
        }
        return outcome;
    }

    private List<Obligation> collect(List<Holder> holders, Ext decision) {
        List<Obligation> resolved = new ArrayList<>();
        for (Holder holder : holders) {
            if (holder.on == null || Ext.of(holder.on) != decision) {
                continue;
            }
            List<Assignment> assignments = new ArrayList<>();
            for (AssignmentExpr assignment : holder.assignments) {
                assign(assignment, assignments);
            }
            resolved.add(new Obligation(holder.id, assignments));
        }
        return resolved;
    }

    /** One assignment per value of the bag. An empty bag still emits the obligation. */
    private void assign(AssignmentExpr assignment, List<Assignment> out) {
        Bag bag = expr(assignment.expr);
        String dataType = bag.ty.uri();
        if (dataType == null) {
            throw Indet.syntax("an assignment's datatype is unknown");
        }
        for (Value value : bag.values) {
            String written = Values.write(bag.ty, value);
            if (written == null) {
                throw Indet.syntax("an assignment's value cannot be written");
            }
            out.add(new Assignment(assignment.attributeId, assignment.category, assignment.issuer, dataType, written));
        }
    }

    private static boolean skip(boolean[] candidates, int index) {
        return candidates != null && (index >= candidates.length || !candidates[index]);
    }

    private Outcome combine(Node node, int count, Child child) {
        Gathered gathered = new Gathered();
        Ext decision;
        Alg.Kind kind = node.alg.kind;
        if (kind == Alg.Kind.DENY_OVERRIDES || kind == Alg.Kind.PERMIT_OVERRIDES) {
            boolean denyWins = kind == Alg.Kind.DENY_OVERRIDES;
            Ext wins = denyWins ? Ext.DENY : Ext.PERMIT;
            Ext loses = denyWins ? Ext.PERMIT : Ext.DENY;
            boolean seenD = false;
            boolean seenP = false;
            boolean seenDp = false;
            boolean sawLoser = false;
            for (int i = 0; i < count; i++) {
                Ext found = gathered.add(child.at(i));
                if (found == wins) {
                    return gathered.finish(wins);
                }
                if (found == loses) {
                    sawLoser = true;
                }
                if (found == Ext.IND_D) {
                    seenD = true;
                } else if (found == Ext.IND_P) {
                    seenP = true;
                } else if (found == Ext.IND_DP) {
                    seenDp = true;
                }
            }
            boolean winInd = denyWins ? seenD : seenP;
            boolean loseInd = denyWins ? seenP : seenD;
            Ext winExt = denyWins ? Ext.IND_D : Ext.IND_P;
            Ext loseExt = denyWins ? Ext.IND_P : Ext.IND_D;
            if (seenDp || (winInd && (loseInd || sawLoser))) {
                decision = Ext.IND_DP;
            } else if (winInd) {
                decision = winExt;
            } else if (sawLoser) {
                decision = loses;
            } else if (loseInd) {
                decision = loseExt;
            } else {
                decision = Ext.NOT_APPLICABLE;
            }
        } else if (kind == Alg.Kind.DENY_UNLESS_PERMIT || kind == Alg.Kind.PERMIT_UNLESS_DENY) {
            boolean permitWins = kind == Alg.Kind.DENY_UNLESS_PERMIT;
            Ext wins = permitWins ? Ext.PERMIT : Ext.DENY;
            for (int i = 0; i < count; i++) {
                if (gathered.add(child.at(i)) == wins) {
                    return gathered.finish(wins);
                }
            }
            decision = permitWins ? Ext.DENY : Ext.PERMIT;
        } else if (kind == Alg.Kind.FIRST_APPLICABLE) {
            for (int i = 0; i < count; i++) {
                Ext found = gathered.add(child.at(i));
                if (found == Ext.NOT_APPLICABLE) {
                    continue;
                }
                if (found.indeterminate()) {
                    return gathered.finish(Ext.IND_DP);
                }
                return gathered.finish(found);
            }
            decision = Ext.NOT_APPLICABLE;
        } else if (kind == Alg.Kind.LEGACY_RULE_OVERRIDES || kind == Alg.Kind.LEGACY_POLICY_OVERRIDES) {
            Effect effect = node.alg.effect;
            Ext overriding = Ext.of(effect);
            Ext other = effect == Effect.DENY ? Ext.PERMIT : Ext.DENY;
            Ext couldOverride = effect == Effect.DENY ? Ext.IND_D : Ext.IND_P;
            boolean error = false;
            boolean potential = false;
            boolean sawOther = false;
            for (int i = 0; i < count; i++) {
                Ext found = gathered.add(child.at(i));
                if (found == overriding) {
                    return gathered.finish(overriding);
                }
                if (found == other) {
                    sawOther = true;
                } else if (found.indeterminate()) {
                    error = true;
                    if (found == couldOverride || found == Ext.IND_DP) {
                        potential = true;
                    }
                }
            }
            if (kind == Alg.Kind.LEGACY_RULE_OVERRIDES) {
                if (potential) {
                    decision = Ext.IND_DP;
                } else if (sawOther) {
                    decision = other;
                } else if (error) {
                    decision = Ext.IND_DP;
                } else {
                    decision = Ext.NOT_APPLICABLE;
                }
            } else if (error) {
                decision = overriding;
            } else if (sawOther) {
                decision = other;
            } else {
                decision = Ext.NOT_APPLICABLE;
            }
        } else {
            throw Indet.syntax("only-one-applicable combines policies, not rules");
        }
        return gathered.finish(decision);
    }
}
