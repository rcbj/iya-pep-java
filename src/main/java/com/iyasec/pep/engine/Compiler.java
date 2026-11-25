// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/** XACML 3.0 Policy and PolicySet XML into the compiled tree. */
final class Compiler {
    /** How deep an expression, a target or a policy tree may nest. Evaluation recurses. */
    static final int MAX_DEPTH = 200;

    /**
     * How deep a document's elements may nest. A deeper document is refused before it is parsed.
     * The scan over-counts: a {@code <tag />} whose {@code >} is not immediately preceded by {@code /} counts.
     */
    static final int MAX_XML_DEPTH = 256;

    private static final class Fault extends Exception {
        Fault(String message) {
            super(message);
        }
    }

    private static final class Pending {
        final int node;
        final int slot;
        final String target;
        final int row;

        Pending(int node, int slot, String target, int row) {
            this.node = node;
            this.slot = slot;
            this.target = target;
            this.row = row;
        }
    }

    private final List<Node> nodes = new ArrayList<>();
    private final List<Expr> variables = new ArrayList<>();
    private final List<Designator> designators = new ArrayList<>();
    private final List<Type> designatorTypes = new ArrayList<>();
    private final Map<Designator, Integer> interned = new HashMap<>();
    private final List<Pending> pending = new ArrayList<>();
    private final DocumentBuilderFactory factory;
    private int row;

    private Compiler(DocumentBuilderFactory factory) {
        this.factory = factory;
    }

    static Tree compile(List<PolicyDocument> rows) throws CompileException {
        List<PolicyDocument> roots = new ArrayList<>();
        for (PolicyDocument row : rows) {
            if (row.isRoot) {
                roots.add(row);
            }
        }
        if (roots.size() != 1) {
            StringBuilder ids = new StringBuilder();
            for (int i = 0; i < roots.size(); i++) {
                if (i > 0) {
                    ids.append(", ");
                }
                ids.append(roots.get(i).policyId);
            }
            throw new CompileException(
                    ids.toString(), "a set needs exactly one root row, and this one has " + roots.size());
        }
        Compiler compiler = new Compiler(factory());
        Map<String, Integer> byId = new HashMap<>();
        int root = 0;
        for (int i = 0; i < rows.size(); i++) {
            PolicyDocument rowDocument = rows.get(i);
            compiler.row = i;
            int node;
            try {
                node = compiler.document(rowDocument.document);
            } catch (Fault fault) {
                throw new CompileException(rowDocument.policyId, fault.getMessage());
            }
            if (byId.put(rowDocument.policyId, node) != null) {
                throw new CompileException(rowDocument.policyId, "two rows of the set carry this policy id");
            }
            if (rowDocument.isRoot) {
                root = node;
            }
        }
        for (Pending reference : compiler.pending) {
            PolicyDocument rowDocument = rows.get(reference.row);
            Integer target = byId.get(reference.target);
            if (target == null) {
                throw new CompileException(
                        rowDocument.policyId, "the reference to \"" + reference.target + "\" names no row of the set");
            }
            Body body = compiler.nodes.get(reference.node).body;
            if (body instanceof Body.Children children) {
                children.children.set(reference.slot, target);
            }
        }
        Tree tree = new Tree(compiler.nodes, root, compiler.variables, compiler.designators, compiler.designatorTypes);
        Integer cycle = checkAcyclic(tree);
        if (cycle != null) {
            throw new CompileException(
                    tree.nodes.get(cycle).id, "the policy references itself, directly or through others");
        }
        Integer deep = tooDeep(tree);
        if (deep != null) {
            String id = tree.nodes.get(deep).id;
            for (Map.Entry<String, Integer> entry : byId.entrySet()) {
                if (entry.getValue() == deep.intValue()) {
                    id = entry.getKey();
                    break;
                }
            }
            throw new CompileException(id, "policies nest more than " + MAX_DEPTH + " deep");
        }
        buildIndexes(tree);
        return tree;
    }

    /** A cycle through references; the node where it closes. */
    private static Integer checkAcyclic(Tree tree) {
        int[] marks = new int[tree.nodes.size()];
        for (int start = 0; start < tree.nodes.size(); start++) {
            if (marks[start] != 0) {
                continue;
            }
            marks[start] = 1;
            int[] stackNode = new int[tree.nodes.size() * 2 + 2];
            int[] stackNext = new int[stackNode.length];
            int top = 0;
            stackNode[0] = start;
            stackNext[0] = 0;
            while (top >= 0) {
                int node = stackNode[top];
                int next = stackNext[top];
                top--;
                List<Integer> children = List.of();
                if (tree.nodes.get(node).body instanceof Body.Children body) {
                    children = body.children;
                }
                if (next < children.size()) {
                    top++;
                    stackNode[top] = node;
                    stackNext[top] = next + 1;
                    int child = children.get(next);
                    if (marks[child] == 1) {
                        return node;
                    }
                    if (marks[child] == 0) {
                        marks[child] = 1;
                        top++;
                        if (top >= stackNode.length) {
                            return node;
                        }
                        stackNode[top] = child;
                        stackNext[top] = 0;
                    }
                } else {
                    marks[node] = 2;
                }
            }
        }
        return null;
    }

    /** A node from which the tree is more than {@link #MAX_DEPTH} deep. */
    private static Integer tooDeep(Tree tree) {
        int[] depth = new int[tree.nodes.size()];
        for (int i = 0; i < depth.length; i++) {
            depth[i] = 1;
        }
        for (int pass = 0; pass <= MAX_DEPTH; pass++) {
            boolean changed = false;
            for (int i = 0; i < tree.nodes.size(); i++) {
                if (tree.nodes.get(i).body instanceof Body.Children children) {
                    int deepest = 0;
                    for (int child : children.children) {
                        deepest = Math.max(deepest, depth[child]);
                    }
                    deepest += 1;
                    if (deepest > depth[i]) {
                        depth[i] = deepest;
                        changed = true;
                    }
                    if (depth[i] > MAX_DEPTH) {
                        return i;
                    }
                }
            }
            if (!changed) {
                return null;
            }
        }
        return null;
    }

    private static void buildIndexes(Tree tree) {
        for (Node node : tree.nodes) {
            List<List<List<List<Match>>>> targets = new ArrayList<>();
            if (node.body instanceof Body.Rules rules) {
                for (Rule rule : rules.rules) {
                    targets.add(rule.target);
                }
            } else if (node.body instanceof Body.Children children) {
                for (int child : children.children) {
                    targets.add(tree.nodes.get(child).target);
                }
            }
            node.index = TargetIndex.build(targets);
        }
    }

    /**
     * Whether elements nest deeper than {@code limit}. Every {@code <} that does not open a comment,
     * CDATA section, processing instruction, declaration or end tag counts as an element.
     */
    static boolean nestsDeeperThan(String xml, int limit) {
        int i = 0;
        int depth = 0;
        int length = xml.length();
        while (i < length) {
            int at = xml.indexOf('<', i);
            if (at < 0) {
                break;
            }
            i = at;
            if (xml.startsWith("<!--", i)) {
                i = skipPast(xml, i, "-->");
            } else if (xml.startsWith("<![CDATA[", i)) {
                i = skipPast(xml, i, "]]>");
            } else if (xml.startsWith("<?", i)) {
                i = skipPast(xml, i, "?>");
            } else if (xml.startsWith("<!", i)) {
                i = skipPast(xml, i, ">");
            } else if (xml.startsWith("</", i)) {
                depth = Math.max(0, depth - 1);
                i = skipPast(xml, i, ">");
            } else {
                Character quote = null;
                int j = i + 1;
                while (j < length) {
                    char c = xml.charAt(j);
                    if (quote == null && (c == '"' || c == '\'')) {
                        quote = c;
                    } else if (quote != null && c == quote) {
                        quote = null;
                    } else if (quote == null && c == '>') {
                        break;
                    }
                    j++;
                }
                boolean prevSlash = j > 0 && j - 1 < length && xml.charAt(j - 1) == '/';
                if (!prevSlash || j == i + 1) {
                    depth++;
                    if (depth > limit) {
                        return true;
                    }
                }
                i = Math.min(j + 1, length);
            }
        }
        return false;
    }

    private static int skipPast(String xml, int from, String end) {
        int at = xml.indexOf(end, from);
        return at < 0 ? xml.length() : at + end.length();
    }

    private static DocumentBuilderFactory factory() throws CompileException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setCoalescing(false);
        factory.setExpandEntityReferences(false);
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (ParserConfigurationException e) {
            throw new CompileException("", "the document is not well-formed XML: " + e.getMessage());
        }
        // The parser's default element-depth cap is below the expression limit.
        try {
            factory.setAttribute("jdk.xml.maxElementDepth", 10000);
        } catch (IllegalArgumentException ignored) {
            // A parser without the limit still has the scan above.
        }
        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) {
            // External access is already refused with secure processing.
        }
        return factory;
    }

    private int document(String xml) throws Fault {
        if (nestsDeeperThan(xml, MAX_XML_DEPTH)) {
            throw new Fault("the document's elements nest more than " + MAX_XML_DEPTH + " deep");
        }
        Document parsed;
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            parsed = builder.parse(new InputSource(new StringReader(xml)));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new Fault("the document is not well-formed XML: " + e.getMessage());
        }
        Element root = parsed.getDocumentElement();
        if (root == null) {
            throw new Fault("the document is not well-formed XML: it has no root element");
        }
        return switch (local(root)) {
            case "Policy" -> policy(root, 1);
            case "PolicySet" -> policySet(root, 1);
            default -> throw new Fault(
                    "a policy document's root must be <Policy> or <PolicySet>, not <" + local(root) + ">");
        };
    }

    private int push(Node node) {
        nodes.add(node);
        return nodes.size() - 1;
    }

    private int policySet(Element node, int depth) throws Fault {
        if (depth > MAX_DEPTH) {
            throw new Fault("policies nest more than " + MAX_DEPTH + " deep");
        }
        String id = required(node, "PolicySetId");
        String algId = required(node, "PolicyCombiningAlgId");
        Alg alg = algorithm(algId, true);
        if (alg == null) {
            throw new Fault("unknown policy-combining algorithm \"" + algId + "\"");
        }
        List<List<List<Match>>> target = target(first(node, "Target"));
        List<Integer> children = new ArrayList<>();
        List<Pending> references = new ArrayList<>();
        for (Element child : elements(node)) {
            switch (local(child)) {
                case "Policy" -> children.add(policy(child, depth + 1));
                case "PolicySet" -> children.add(policySet(child, depth + 1));
                case "PolicyIdReference", "PolicySetIdReference" -> {
                    references.add(new Pending(0, children.size(), Values.trimUnicode(textOf(child)), row));
                    children.add(-1);
                }
                default -> {
                }
            }
        }
        List<Holder> obligations =
                holders(node, "ObligationExpressions", "ObligationExpression", "ObligationId", "FulfillOn", null);
        List<Holder> advice = holders(node, "AdviceExpressions", "AdviceExpression", "AdviceId", "AppliesTo", null);
        int index = push(new Node(id, target, alg, new Body.Children(children), obligations, advice));
        for (Pending reference : references) {
            pending.add(new Pending(index, reference.slot, reference.target, reference.row));
        }
        return index;
    }

    private int policy(Element node, int depth) throws Fault {
        if (depth > MAX_DEPTH) {
            throw new Fault("policies nest more than " + MAX_DEPTH + " deep");
        }
        String id = required(node, "PolicyId");
        String algId = required(node, "RuleCombiningAlgId");
        Alg alg = algorithm(algId, false);
        if (alg == null) {
            throw new Fault("unknown rule-combining algorithm \"" + algId + "\"");
        }
        Map<String, Integer> scope = new HashMap<>();
        List<Element> definitions = named(node, "VariableDefinition");
        int base = variables.size();
        for (int i = 0; i < definitions.size(); i++) {
            String variable = required(definitions.get(i), "VariableId");
            if (scope.containsKey(variable)) {
                throw new Fault("VariableId \"" + variable + "\" is defined twice");
            }
            scope.put(variable, base + i);
            variables.add(Expr.BadLiteral.INSTANCE);
        }
        for (int i = 0; i < definitions.size(); i++) {
            variables.set(base + i, expression(onlyChild(definitions.get(i)), scope, 0));
        }
        checkVariables(base, definitions.size());
        List<List<List<Match>>> target = target(first(node, "Target"));
        List<Rule> rules = new ArrayList<>();
        HashSet<String> ruleIds = new HashSet<>();
        for (Element rule : named(node, "Rule")) {
            String ruleId = required(rule, "RuleId");
            if (!ruleIds.add(ruleId)) {
                throw new Fault("RuleId \"" + ruleId + "\" appears twice");
            }
            rules.add(rule(rule, scope));
        }
        List<Holder> obligations =
                holders(node, "ObligationExpressions", "ObligationExpression", "ObligationId", "FulfillOn", scope);
        List<Holder> advice = holders(node, "AdviceExpressions", "AdviceExpression", "AdviceId", "AppliesTo", scope);
        return push(new Node(id, target, alg, new Body.Rules(rules), obligations, advice));
    }

    private void checkVariables(int base, int count) throws Fault {
        List<List<Integer>> depends = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            List<Integer> found = new ArrayList<>();
            references(variables.get(base + i), found);
            List<Integer> local = new ArrayList<>();
            for (int variable : found) {
                int relative = variable - base;
                if (relative >= 0 && relative < count) {
                    local.add(relative);
                }
            }
            depends.add(local);
        }
        int[] marks = new int[count];
        for (int start = 0; start < count; start++) {
            if (marks[start] != 0) {
                continue;
            }
            marks[start] = 1;
            int[] stackVar = new int[count * 2 + 2];
            int[] stackNext = new int[stackVar.length];
            int top = 0;
            stackVar[0] = start;
            stackNext[0] = 0;
            while (top >= 0) {
                int variable = stackVar[top];
                int next = stackNext[top];
                top--;
                List<Integer> edges = depends.get(variable);
                if (next < edges.size()) {
                    top++;
                    stackVar[top] = variable;
                    stackNext[top] = next + 1;
                    int other = edges.get(next);
                    if (marks[other] == 1) {
                        throw new Fault("a VariableDefinition refers to itself, directly or through another");
                    }
                    if (marks[other] == 0) {
                        marks[other] = 1;
                        top++;
                        stackVar[top] = other;
                        stackNext[top] = 0;
                    }
                } else {
                    marks[variable] = 2;
                }
            }
        }
    }

    private static void references(Expr expr, List<Integer> out) {
        if (expr instanceof Expr.Variable variable) {
            out.add(variable.index);
        } else if (expr instanceof Expr.Apply apply) {
            for (Expr arg : apply.args) {
                references(arg, out);
            }
        }
    }

    private Rule rule(Element node, Map<String, Integer> scope) throws Fault {
        String effectText = required(node, "Effect");
        Effect effect = Effect.parse(effectText);
        if (effect == null) {
            throw new Fault("a Rule's Effect cannot be \"" + effectText + "\"");
        }
        Element condition = first(node, "Condition");
        Expr conditionExpr = condition == null ? null : expression(onlyChild(condition), scope, 0);
        return new Rule(
                effect,
                target(first(node, "Target")),
                conditionExpr,
                holders(node, "ObligationExpressions", "ObligationExpression", "ObligationId", "FulfillOn", scope),
                holders(node, "AdviceExpressions", "AdviceExpression", "AdviceId", "AppliesTo", scope));
    }

    private List<Holder> holders(
            Element parent,
            String wrapper,
            String item,
            String idAttribute,
            String onAttribute,
            Map<String, Integer> scope)
            throws Fault {
        Element container = first(parent, wrapper);
        if (container == null) {
            return List.of();
        }
        List<Holder> holders = new ArrayList<>();
        for (Element node : named(container, item)) {
            List<AssignmentExpr> assignments = new ArrayList<>();
            for (Element assignment : named(node, "AttributeAssignmentExpression")) {
                assignments.add(new AssignmentExpr(
                        required(assignment, "AttributeId"),
                        attribute(assignment, "Category"),
                        attribute(assignment, "Issuer"),
                        expression(onlyChild(assignment), scope, 0)));
            }
            holders.add(new Holder(required(node, idAttribute), Effect.parse(required(node, onAttribute)), assignments));
        }
        return holders;
    }

    private List<List<List<Match>>> target(Element node) throws Fault {
        if (node == null) {
            return List.of();
        }
        List<List<List<Match>>> target = new ArrayList<>();
        for (Element anyOf : named(node, "AnyOf")) {
            List<List<Match>> alls = new ArrayList<>();
            for (Element allOf : named(anyOf, "AllOf")) {
                List<Match> matches = new ArrayList<>();
                for (Element match : named(allOf, "Match")) {
                    matches.add(matchElement(match));
                }
                if (matches.isEmpty()) {
                    throw new Fault("<AllOf> must hold at least one <Match>");
                }
                alls.add(matches);
            }
            if (alls.isEmpty()) {
                throw new Fault("<AnyOf> must hold at least one <AllOf>");
            }
            target.add(alls);
        }
        return target;
    }

    private Match matchElement(Element node) throws Fault {
        String matchId = required(node, "MatchId");
        Func func = Functions.lookup(matchId);
        if (func == null) {
            throw new Fault("unknown function \"" + matchId + "\"");
        }
        Element literal = first(node, "AttributeValue");
        if (literal == null) {
            throw new Fault("<Match> must hold an <AttributeValue>");
        }
        Element attribute = first(node, "AttributeDesignator");
        if (attribute == null) {
            attribute = first(node, "AttributeSelector");
        }
        if (attribute == null) {
            throw new Fault("<Match> must hold an <AttributeDesignator> or an <AttributeSelector>");
        }
        Expr literalExpr = expression(literal, null, 0);
        return new Match(Functions.precompile(func, literalExpr), literalExpr, expression(attribute, null, 0));
    }

    private int intern(Designator designator) {
        Integer existing = interned.get(designator);
        if (existing != null) {
            return existing;
        }
        int id = designators.size();
        designatorTypes.add(Type.fromUri(designator.dataType));
        designators.add(designator);
        interned.put(designator, id);
        return id;
    }

    private Expr expression(Element node, Map<String, Integer> scope, int depth) throws Fault {
        if (depth > MAX_DEPTH) {
            throw new Fault("an expression nests more than " + MAX_DEPTH + " deep");
        }
        switch (local(node)) {
            case "AttributeValue" -> {
                Type type = Type.fromUri(required(node, "DataType"));
                Values.Value parsed = Values.parse(type, textOf(node));
                if (parsed == null) {
                    return Expr.BadLiteral.INSTANCE;
                }
                return new Expr.Literal(Bag.one(type, parsed));
            }
            case "AttributeDesignator" -> {
                Designator designator = new Designator(
                        required(node, "Category"),
                        required(node, "AttributeId"),
                        Values.canonicalUri(required(node, "DataType")),
                        attribute(node, "Issuer"));
                return new Expr.DesignatorExpr(intern(designator), flag(node, "MustBePresent"));
            }
            case "AttributeSelector" -> {
                required(node, "Category");
                required(node, "Path");
                required(node, "DataType");
                return Expr.Selector.INSTANCE;
            }
            case "Apply" -> {
                String functionId = required(node, "FunctionId");
                Func func = Functions.lookup(functionId);
                if (func == null) {
                    throw new Fault("unknown function \"" + functionId + "\"");
                }
                List<Expr> args = new ArrayList<>();
                for (Element child : elements(node)) {
                    if (!"Description".equals(local(child))) {
                        args.add(expression(child, scope, depth + 1));
                    }
                }
                Expr first = args.isEmpty() ? null : args.get(0);
                return new Expr.Apply(Functions.precompile(func, first), args);
            }
            case "Function" -> {
                String functionId = required(node, "FunctionId");
                Func func = Functions.lookup(functionId);
                if (func == null) {
                    throw new Fault("unknown function \"" + functionId + "\"");
                }
                return new Expr.FunctionRef(func);
            }
            case "VariableReference" -> {
                String variable = required(node, "VariableId");
                Integer index = scope == null ? null : scope.get(variable);
                if (index == null) {
                    throw new Fault(
                            "VariableReference names \""
                                    + variable
                                    + "\", which no VariableDefinition of the Policy defines");
                }
                return new Expr.Variable(index);
            }
            default -> throw new Fault("<" + local(node) + "> is not a XACML expression");
        }
    }

    /** Either level's identifiers are accepted at either level. only-one-applicable is policy sets only. */
    private static Alg algorithm(String uri, boolean inPolicySet) {
        String prefix = "urn:oasis:names:tc:xacml:";
        if (!uri.startsWith(prefix)) {
            return null;
        }
        String rest = uri.substring(prefix.length());
        int colon = rest.indexOf(':');
        if (colon < 0) {
            return null;
        }
        String version = rest.substring(0, colon);
        String after = rest.substring(colon + 1);
        String name = null;
        if (inPolicySet) {
            name = strip(after, "policy-combining-algorithm:");
        } else {
            name = strip(after, "rule-combining-algorithm:");
        }
        if (name == null) {
            name = strip(after, "policy-combining-algorithm:");
        }
        if (name == null) {
            name = strip(after, "rule-combining-algorithm:");
        }
        if (name == null) {
            return null;
        }
        boolean policyLevel = after.startsWith("policy-");
        return switch (version + " " + name) {
            case "3.0 deny-overrides", "3.0 ordered-deny-overrides" -> Alg.of(Alg.Kind.DENY_OVERRIDES);
            case "3.0 permit-overrides", "3.0 ordered-permit-overrides" -> Alg.of(Alg.Kind.PERMIT_OVERRIDES);
            case "3.0 deny-unless-permit" -> Alg.of(Alg.Kind.DENY_UNLESS_PERMIT);
            case "3.0 permit-unless-deny" -> Alg.of(Alg.Kind.PERMIT_UNLESS_DENY);
            case "1.0 first-applicable" -> Alg.of(Alg.Kind.FIRST_APPLICABLE);
            case "1.0 only-one-applicable" -> policyLevel && inPolicySet ? Alg.of(Alg.Kind.ONLY_ONE_APPLICABLE) : null;
            case "1.0 deny-overrides", "1.1 ordered-deny-overrides" -> legacy(policyLevel, Effect.DENY);
            case "1.0 permit-overrides", "1.1 ordered-permit-overrides" -> legacy(policyLevel, Effect.PERMIT);
            default -> null;
        };
    }

    private static Alg legacy(boolean policyLevel, Effect effect) {
        return policyLevel ? Alg.legacyPolicy(effect) : Alg.legacyRule(effect);
    }

    private static String strip(String text, String prefix) {
        return text.startsWith(prefix) ? text.substring(prefix.length()) : null;
    }

    private static List<Element> elements(Element node) {
        List<Element> out = new ArrayList<>();
        var list = node.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            org.w3c.dom.Node child = list.item(i);
            if (child.getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
                out.add((Element) child);
            }
        }
        return out;
    }

    private static List<Element> named(Element node, String name) {
        List<Element> out = new ArrayList<>();
        for (Element child : elements(node)) {
            if (name.equals(local(child))) {
                out.add(child);
            }
        }
        return out;
    }

    private static Element first(Element node, String name) {
        for (Element child : elements(node)) {
            if (name.equals(local(child))) {
                return child;
            }
        }
        return null;
    }

    private static Element onlyChild(Element node) throws Fault {
        List<Element> children = elements(node);
        if (children.size() != 1) {
            throw new Fault("<" + local(node) + "> must hold exactly one expression");
        }
        return children.get(0);
    }

    /** An empty attribute counts as absent. */
    private static String attribute(Element node, String name) {
        if (!node.hasAttribute(name)) {
            return null;
        }
        String value = node.getAttribute(name);
        return value.isEmpty() ? null : value;
    }

    private static String required(Element node, String name) throws Fault {
        String value = attribute(node, name);
        if (value == null) {
            throw new Fault("<" + local(node) + "> lacks its " + name + " attribute");
        }
        return value;
    }

    private static boolean flag(Element node, String name) {
        String value = node.getAttribute(name);
        return "true".equals(value) || "1".equals(value);
    }

    /** Descendant text nodes. CDATA is not text. */
    private static String textOf(Element node) {
        StringBuilder out = new StringBuilder();
        appendText(node, out);
        return out.toString();
    }

    private static void appendText(org.w3c.dom.Node node, StringBuilder out) {
        var list = node.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            org.w3c.dom.Node child = list.item(i);
            if (child.getNodeType() == org.w3c.dom.Node.TEXT_NODE) {
                out.append(child.getNodeValue());
            } else if (child.getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
                appendText(child, out);
            }
        }
    }

    private static String local(org.w3c.dom.Node node) {
        String name = node.getLocalName();
        if (name != null && !name.isEmpty()) {
            return name;
        }
        String nodeName = node.getNodeName();
        int colon = nodeName.indexOf(':');
        return colon < 0 ? nodeName : nodeName.substring(colon + 1);
    }
}
