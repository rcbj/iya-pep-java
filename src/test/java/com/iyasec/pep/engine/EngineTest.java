// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** What the corpus does not pin down: designators, compile errors, the status code, the target index. */
class EngineTest {
    private static final String NS = "xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\"";
    private static final String F = "urn:oasis:names:tc:xacml:1.0:function:";
    private static final String INTEGER = "http://www.w3.org/2001/XMLSchema#integer";

    private static PolicyDocument row(String id, boolean isRoot, String document) {
        String kind = document.stripLeading().startsWith("<PolicySet") ? "PolicySet" : "Policy";
        return new PolicyDocument(id, kind, "1.0", isRoot, document);
    }

    private static String designator(String category, String id, String dataType, boolean must) {
        return "<AttributeDesignator Category=\""
                + category
                + "\" AttributeId=\""
                + id
                + "\" DataType=\""
                + dataType
                + "\" MustBePresent=\""
                + must
                + "\"/>";
    }

    /** A Policy for subject-id equal to who, with one Permit rule. */
    private static String permitFor(String id, String who) {
        return "<Policy "
                + NS
                + " PolicyId=\""
                + id
                + "\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\">"
                + "<Target><AnyOf><AllOf>"
                + "<Match MatchId=\""
                + F
                + "string-equal\"><AttributeValue DataType=\""
                + Names.STRING
                + "\">"
                + who
                + "</AttributeValue>"
                + designator(Names.ACCESS_SUBJECT, "subject-id", Names.STRING, false)
                + "</Match>"
                + "</AllOf></AnyOf></Target>"
                + "<Rule RuleId=\"r\" Effect=\"Permit\"/>"
                + "</Policy>";
    }

    private static Request subject(String id) {
        List<AttributeValue> values = new ArrayList<>();
        values.add(AttributeValue.string(id));
        List<Attribute> attributes = new ArrayList<>();
        attributes.add(new Attribute("subject-id", null, false, values));
        List<Category> categories = new ArrayList<>();
        categories.add(new Category(Names.ACCESS_SUBJECT, false, attributes));
        return new Request(false, false, categories);
    }

    private static String setOf(String id, String alg, String children) {
        return "<PolicySet "
                + NS
                + " PolicySetId=\""
                + id
                + "\" PolicyCombiningAlgId=\"urn:oasis:names:tc:xacml:"
                + alg
                + "\"><Target/>"
                + children
                + "</PolicySet>";
    }

    @Test
    void designatorsCoverReferencedPoliciesConditionsVariablesAndObligations() throws Exception {
        String referenced = "<Policy "
                + NS
                + " PolicyId=\"p\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable\">"
                + "<VariableDefinition VariableId=\"age\">"
                + "<Apply FunctionId=\""
                + F
                + "integer-one-and-only\">"
                + designator(Names.ACCESS_SUBJECT, "age", INTEGER, true)
                + "</Apply>"
                + "</VariableDefinition>"
                + "<Rule RuleId=\"r\" Effect=\"Permit\">"
                + "<Condition><Apply FunctionId=\""
                + F
                + "integer-greater-than\"><VariableReference VariableId=\"age\"/>"
                + "<AttributeValue DataType=\""
                + INTEGER
                + "\">17</AttributeValue></Apply></Condition>"
                + "<ObligationExpressions><ObligationExpression ObligationId=\"o\" FulfillOn=\"Permit\">"
                + "<AttributeAssignmentExpression AttributeId=\"mail\">"
                + designator(Names.ACCESS_SUBJECT, "mail", Names.STRING, false)
                + "</AttributeAssignmentExpression>"
                + "</ObligationExpression></ObligationExpressions>"
                + "</Rule>"
                + "</Policy>";
        String root = setOf(
                "root",
                "3.0:policy-combining-algorithm:deny-overrides",
                "<PolicyIdReference>p</PolicyIdReference>" + permitFor("inline", "alice"));
        Policies policies = Policies.compile(List.of(row("root", true, root), row("p", false, referenced)));
        assertEquals(2, policies.size());
        List<String> ids = new ArrayList<>();
        for (Designator found : policies.designators(Names.ACCESS_SUBJECT)) {
            ids.add(found.attributeId);
        }
        assertEquals(List.of("age", "mail", "subject-id"), ids);
        assertTrue(policies.designators(Names.RESOURCE).isEmpty());

        Request request = subject("bob");
        request.categories
                .get(0)
                .attributes
                .add(new Attribute(
                        "age", null, false, new ArrayList<>(List.of(new AttributeValue(INTEGER, "42")))));
        Response response = policies.evaluate(request, Instant.EPOCH, new NoResolver());
        assertEquals(Decision.PERMIT, response.decision);
        assertEquals(1, response.obligations.size());
        assertTrue(response.obligations.get(0).assignments.isEmpty(), "mail is absent, so no assignment");
        assertEquals(Names.STATUS_OK, response.statusCode);
    }

    @Test
    void aCompileErrorNamesItsPolicy() {
        String bad = permitFor("broken", "x").replace("string-equal", "string-equal-ish");
        String root = setOf(
                "root",
                "3.0:policy-combining-algorithm:deny-overrides",
                "<PolicyIdReference>broken</PolicyIdReference>");
        CompileException error = assertThrows(
                CompileException.class,
                () -> Policies.compile(List.of(row("root", true, root), row("broken", false, bad))));
        assertEquals("broken", error.policyId);
        assertTrue(error.message.contains("string-equal-ish"), error.message);

        String missing = root;
        error = assertThrows(CompileException.class, () -> Policies.compile(List.of(row("root", true, missing))));
        assertEquals("root", error.policyId);
        assertTrue(error.message.contains("broken"), error.message);

        String looped = setOf(
                "a", "3.0:policy-combining-algorithm:deny-overrides", "<PolicySetIdReference>a</PolicySetIdReference>");
        assertEquals("a", assertThrows(CompileException.class, () -> Policies.compile(List.of(row("a", true, looped)))).policyId);

        error = assertThrows(CompileException.class, () -> Policies.compile(List.of(row("x", true, "<Policy"))));
        assertEquals("x", error.policyId);

        String cyclic = "<Policy "
                + NS
                + " PolicyId=\"v\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\">"
                + "<VariableDefinition VariableId=\"a\"><VariableReference VariableId=\"b\"/></VariableDefinition>"
                + "<VariableDefinition VariableId=\"b\"><Apply FunctionId=\""
                + F
                + "not\"><VariableReference VariableId=\"a\"/></Apply></VariableDefinition>"
                + "</Policy>";
        error = assertThrows(CompileException.class, () -> Policies.compile(List.of(row("v", true, cyclic))));
        assertTrue(error.message.contains("VariableDefinition"), error.message);
    }

    @Test
    void aMissingMustBePresentAttributeIsMissingAttribute() throws Exception {
        String policy = "<Policy "
                + NS
                + " PolicyId=\"p\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\">"
                + "<Rule RuleId=\"r\" Effect=\"Permit\"><Condition>"
                + "<Apply FunctionId=\""
                + F
                + "string-is-in\"><AttributeValue DataType=\""
                + Names.STRING
                + "\">a</AttributeValue>"
                + designator(Names.RESOURCE, "owner", Names.STRING, true)
                + "</Apply>"
                + "</Condition></Rule></Policy>";
        Policies policies = Policies.compile(List.of(row("p", true, policy)));
        Response response = policies.evaluate(subject("alice"), Instant.EPOCH, new NoResolver());
        assertEquals(Decision.INDETERMINATE, response.decision);
        assertEquals("urn:oasis:names:tc:xacml:1.0:status:missing-attribute", response.statusCode);

        Resolver owner = designator -> "owner".equals(designator.attributeId) ? List.of(AttributeValue.string("a")) : null;
        response = policies.evaluate(subject("alice"), Instant.EPOCH, owner);
        assertEquals(Decision.PERMIT, response.decision);
    }

    @Test
    void theTargetIndexSkipsOnlyWhatCannotMatch() throws Exception {
        StringBuilder children = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            children.append(permitFor("p" + i, "user" + i));
        }
        children.append(permitFor("catch", "user7").replace("Effect=\"Permit\"", "Effect=\"Deny\""));
        String root = setOf("root", "1.0:policy-combining-algorithm:first-applicable", children.toString());
        Policies policies = Policies.compile(List.of(row("root", true, root)));
        assertNotNull(policies.tree.nodes.get(policies.tree.root).index);
        assertEquals(Decision.PERMIT, policies.evaluate(subject("user3"), Instant.EPOCH, new NoResolver()).decision);
        assertEquals(Decision.PERMIT, policies.evaluate(subject("user19"), Instant.EPOCH, new NoResolver()).decision);
        assertEquals(Decision.NOT_APPLICABLE, policies.evaluate(subject("nobody"), Instant.EPOCH, new NoResolver()).decision);

        String integerPolicy = permitFor("q", "1").replace(Names.STRING, INTEGER).replace("string-equal", "integer-equal");
        String integerSet = setOf(
                "root",
                "3.0:policy-combining-algorithm:deny-overrides",
                integerPolicy + integerPolicy.replace("PolicyId=\"q\"", "PolicyId=\"r\""));
        Policies integers = Policies.compile(List.of(row("root", true, integerSet)));
        Request request = subject("x");
        List<AttributeValue> values = request.categories.get(0).attributes.get(0).values;
        values.clear();
        values.add(new AttributeValue(INTEGER, "one"));
        Response response = integers.evaluate(request, Instant.EPOCH, new NoResolver());
        assertEquals(Decision.INDETERMINATE, response.decision);
        assertEquals("urn:oasis:names:tc:xacml:1.0:status:syntax-error", response.statusCode);
    }

    @Test
    void garbageDoesNotPanic() throws Exception {
        String[] documents = {
            "",
            "not xml",
            "<Policy/>",
            "<PolicySet PolicySetId='x' PolicyCombiningAlgId='nope'/>",
            "<!DOCTYPE x [<!ENTITY a 'b'>]><Policy/>",
            "<Apply>".repeat(100_000),
            "<Policy>" + "<a>".repeat(300) + "</a>".repeat(300) + "</Policy>"
        };
        for (String document : documents) {
            assertThrows(CompileException.class, () -> Policies.compile(List.of(row("x", true, document))));
        }

        String deep = "<Policy "
                + NS
                + " PolicyId=\"p\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\">"
                + "<Rule RuleId=\"r\" Effect=\"Permit\"><Condition>"
                + ("<Apply FunctionId=\"" + F + "not\">").repeat(150)
                + "<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#boolean\">true</AttributeValue>"
                + "</Apply>".repeat(150)
                + "</Condition></Rule></Policy>";
        Policies policies = Policies.compile(List.of(row("p", true, deep)));
        assertEquals(Decision.PERMIT, policies.evaluate(subject("x"), Instant.EPOCH, new NoResolver()).decision);
        assertThrows(CompileException.class, () -> Policies.compile(List.of()));

        String[][] odd = {
            {"integer", "170141183460469231731687303715884105727"},
            {"integer", "-170141183460469231731687303715884105728"},
            {"double", "NaN"},
            {"double", "-INF"},
            {"string", "\uD83D\uDE00\u0000"},
            {"dateTime", "999999999-12-31T24:59:60.999Z"},
            {"dateTime", "-999999999-01-01T00:00:00+99:99"},
            {"date", "0000-02-29"},
            {"dayTimeDuration", "P99999999999DT1S"},
            {"yearMonthDuration", "-P9999999999Y"},
            {"hexBinary", ""},
            {"base64Binary", "===="},
            {"anyURI", ""}
        };
        String[][] functions = {
            {"1.0", "integer-add"},
            {"1.0", "integer-multiply"},
            {"1.0", "integer-subtract"},
            {"1.0", "integer-divide"},
            {"1.0", "integer-mod"},
            {"1.0", "integer-abs"},
            {"1.0", "double-divide"},
            {"1.0", "double-to-integer"},
            {"1.0", "round"},
            {"1.0", "string-regexp-match"},
            {"1.0", "n-of"},
            {"1.0", "x500Name-match"},
            {"1.0", "dateTime-less-than"},
            {"3.0", "string-substring"},
            {"3.0", "dateTime-add-dayTimeDuration"},
            {"3.0", "dateTime-subtract-yearMonthDuration"},
            {"3.0", "date-add-yearMonthDuration"},
            {"3.0", "any-of"},
            {"3.0", "map"},
            {"3.0", "string-concatenate"}
        };
        StringBuilder body = new StringBuilder();
        int n = 0;
        for (String[] function : functions) {
            for (String[] value : odd) {
                for (int k = 0; k < 4; k++) {
                    String[] value2 = odd[k];
                    body.append("<Rule RuleId=\"")
                            .append(n)
                            .append("\" Effect=\"Permit\"><Condition><Apply FunctionId=\"urn:oasis:names:tc:xacml:")
                            .append(function[0])
                            .append(":function:")
                            .append(function[1])
                            .append("\">")
                            .append("<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#")
                            .append(value[0])
                            .append("\">")
                            .append(value[1].replace("\u0000", ""))
                            .append("</AttributeValue>")
                            .append("<AttributeValue DataType=\"http://www.w3.org/2001/XMLSchema#")
                            .append(value2[0])
                            .append("\">")
                            .append(value2[1].replace("\u0000", ""))
                            .append("</AttributeValue>")
                            .append(designator(Names.ACCESS_SUBJECT, "subject-id", Names.STRING, false))
                            .append("</Apply></Condition></Rule>");
                    n++;
                }
            }
        }
        String wide = "<Policy "
                + NS
                + " PolicyId=\"p\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-unless-deny\">"
                + body
                + "</Policy>";
        Policies widePolicies = Policies.compile(List.of(row("p", true, wide)));
        for (Instant when : new Instant[] {Instant.EPOCH, Instant.now(), Instant.EPOCH.minusSeconds(1L << 40)}) {
            Request request = subject("x");
            List<AttributeValue> values = request.categories.get(0).attributes.get(0).values;
            for (String[] value : odd) {
                values.add(new AttributeValue("http://www.w3.org/2001/XMLSchema#" + value[0], value[1]));
            }
            Response response = widePolicies.evaluate(request, when, new NoResolver());
            assertEquals(Decision.PERMIT, response.decision);
        }
    }
}
