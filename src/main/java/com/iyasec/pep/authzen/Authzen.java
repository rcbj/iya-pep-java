// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.authzen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.iyasec.pep.Json;
import com.iyasec.pep.engine.Attribute;
import com.iyasec.pep.engine.AttributeValue;
import com.iyasec.pep.engine.Category;
import com.iyasec.pep.engine.Names;
import com.iyasec.pep.engine.Request;
import com.iyasec.pep.engine.Response;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An AuthZEN access evaluation as an XACML request, and the decision back.
 * The code, the HTTP status and the order of the checks are the contract
 * with the service: a request with two problems is refused for the same one.
 */
public final class Authzen {
    static final String RECIPIENT_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject";
    static final String INTERMEDIARY_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject";
    static final String CODEBASE = "urn:oasis:names:tc:xacml:1.0:subject-category:codebase";
    static final String REQUESTING_MACHINE = "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine";

    static final String SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
    static final String RESOURCE_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
    static final String ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";
    static final String CURRENT_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-time";
    static final String CURRENT_DATE = "urn:oasis:names:tc:xacml:1.0:environment:current-date";
    static final String CURRENT_DATETIME = "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";

    static final String BOOLEAN = "http://www.w3.org/2001/XMLSchema#boolean";
    static final String INTEGER = "http://www.w3.org/2001/XMLSchema#integer";
    static final String DOUBLE = "http://www.w3.org/2001/XMLSchema#double";
    static final String TIME = "http://www.w3.org/2001/XMLSchema#time";
    static final String DATE = "http://www.w3.org/2001/XMLSchema#date";
    static final String DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";
    static final String DAYTIME_DURATION = "http://www.w3.org/2001/XMLSchema#dayTimeDuration";
    static final String YEARMONTH_DURATION = "http://www.w3.org/2001/XMLSchema#yearMonthDuration";
    static final String ANYURI = "http://www.w3.org/2001/XMLSchema#anyURI";
    static final String HEXBINARY = "http://www.w3.org/2001/XMLSchema#hexBinary";
    static final String BASE64BINARY = "http://www.w3.org/2001/XMLSchema#base64Binary";
    static final String RFC822NAME = "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";
    static final String X500NAME = "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";
    static final String DNSNAME = "urn:oasis:names:tc:xacml:2.0:data-type:dnsName";
    static final String IPADDRESS = "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress";

    static final String PROTOCOL = "urn:sts:xacml:protocol";
    static final String REALM = "urn:sts:xacml:realm";
    static final String AUTHZEN_SUBJECT_TYPE = "urn:sts:xacml:authzen:subject-type";
    static final String AUTHZEN_RESOURCE_TYPE = "urn:sts:xacml:authzen:resource-type";
    static final String AUTHZEN_CALLER = "urn:sts:xacml:authzen:caller";
    static final String AUTHZEN_APPLICATION = "urn:sts:xacml:authzen:application";
    static final String AUTHZEN_SUPPLIED = "urn:sts:xacml:authzen:supplied";

    private static final String[][] OBJECTS = {
            {"subject", Names.ACCESS_SUBJECT},
            {"resource", Names.RESOURCE},
            {"action", Names.ACTION},
            {"context", Names.ENVIRONMENT},
    };
    private static final String[] ROW_MEMBERS = {
            "object", "property", "attributeId", "category", "dataType", "multiplicity", "description"
    };
    private static final String[][] CATEGORIES = {
            {"access-subject", Names.ACCESS_SUBJECT},
            {"recipient-subject", RECIPIENT_SUBJECT},
            {"intermediary-subject", INTERMEDIARY_SUBJECT},
            {"codebase", CODEBASE},
            {"requesting-machine", REQUESTING_MACHINE},
            {"resource", Names.RESOURCE},
            {"action", Names.ACTION},
            {"environment", Names.ENVIRONMENT},
    };
    private static final String[][] DATATYPES = {
            {"string", Names.STRING},
            {"boolean", BOOLEAN},
            {"integer", INTEGER},
            {"double", DOUBLE},
            {"time", TIME},
            {"date", DATE},
            {"dateTime", DATETIME},
            {"dayTimeDuration", DAYTIME_DURATION},
            {"yearMonthDuration", YEARMONTH_DURATION},
            {"anyURI", ANYURI},
            {"hexBinary", HEXBINARY},
            {"base64Binary", BASE64BINARY},
            {"rfc822Name", RFC822NAME},
            {"x500Name", X500NAME},
            {"dnsName", DNSNAME},
            {"ipAddress", IPADDRESS},
    };
    private static final String[] SUBJECT_CATEGORIES = {
            Names.ACCESS_SUBJECT, RECIPIENT_SUBJECT, INTERMEDIARY_SUBJECT, CODEBASE, REQUESTING_MACHINE
    };
    private static final String[] ADAPTER_IDS = {
            SUBJECT_ID, RESOURCE_ID, ACTION_ID, CURRENT_TIME, CURRENT_DATE, CURRENT_DATETIME
    };
    private static final String[] ADAPTER_CONTEXT = {"supported_obligations", "approval", "application"};
    private static final String[] BINDING_CONTEXT = {
            "client_id", "acr", "amr", "auth_time", "cnf", "jti", "subject_token_type",
            "actor_token_type", "subject_token", "act", "may_act"
    };
    private static final String[][] ENTITIES = {
            {"subject", "type", "id"},
            {"action", "name"},
            {"resource", "type", "id"},
    };
    private static final String[][] OBLIGATION_TYPES = {
            {"step-up", "acr_value", "amr_values"},
            {"notification", "to", "body", "to"},
            {"session_termination", "subject"},
    };

    private static final String RESERVED_NAMESPACE = "urn:sts:xacml:";
    private static final int MAX_PATH_DEPTH = 6;
    private static final int MAX_ATTRIBUTE_ID = 512;
    private static final int MAX_TEXT = 1024;
    private static final int MAX_VALUE = 8192;
    private static final int MAX_BAG = 256;
    private static final int MAX_NESTING = 8;
    private static final double MAX_SAFE_INTEGER = 9_007_199_254_740_991.0;
    private static final String LOG_OBLIGATION = "urn:sts:xacml:obligation:log";
    private static final String MISSING_ATTRIBUTE = "urn:oasis:names:tc:xacml:1.0:status:missing-attribute";
    private static final String OBLIGATION_PREFIX = "urn:sts:xacml:authzen:obligation:";

    private static final Pattern BARE_NAME = Pattern.compile("^[A-Za-z][A-Za-z0-9;-]*$");
    private static final Pattern PATH_SEGMENT = Pattern.compile("^[A-Za-z0-9_$@:\\-]{1,64}$");
    private static final Pattern INTEGER_LEX = Pattern.compile("^[+-]?[0-9]+$");
    private static final Pattern DOUBLE_LEX = Pattern.compile("^[+-]?([0-9]+(\\.[0-9]*)?|\\.[0-9]+)([eE][+-]?[0-9]+)?$");
    private static final Pattern DATE_LEX = Pattern.compile("^(-?[0-9]{4,})-([0-9]{2})-([0-9]{2})(?:Z|[+-][0-9]{2}:[0-9]{2})?$");
    private static final Pattern TIME_LEX = Pattern.compile("^([0-9]{2}):([0-9]{2}):([0-9]{2}(?:\\.[0-9]+)?)(?:Z|[+-][0-9]{2}:[0-9]{2})?$");
    private static final Pattern DATETIME_LEX = Pattern.compile("^(-?[0-9]{4,})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2}(?:\\.[0-9]+)?)(?:Z|[+-][0-9]{2}:[0-9]{2})?$");
    private static final Pattern YEAR_MONTH = Pattern.compile("^-?P(?:([0-9]+)Y)?(?:([0-9]+)M)?$");
    private static final Pattern DAY_TIME = Pattern.compile("^-?P(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+(?:\\.[0-9]+)?)S)?)?$");

    private Authzen() {}

    /**
     * Maps one evaluation body through {@code catalogue}. The caller and the
     * application written into the request are the trusted ones. A
     * {@code context.application} naming another application is refused
     * (403, {@code STS-AUTHZEN-0025}).
     */
    public static Mapped mapEvaluation(JsonNode body, Catalogue catalogue, Trusted trusted) throws Refusal {
        Reading reading = readEvaluation(body, catalogue.rows);
        if (!reading.application.isEmpty() && !reading.application.equals(trusted.application)) {
            throw new Refusal(403, "STS-AUTHZEN-0025",
                    "context.application \"" + clip(reading.application, 120) + "\" is not an application this PEP may ask about.");
        }
        Request request = buildRequest(reading, trusted);
        if (trusted.fga) {
            addFgaAccess(request, trusted.application);
        }
        return new Mapped(request, reading.supportedObligations);
    }

    /**
     * The engine's answer mapped back. An Indeterminate over a missing
     * attribute is an ordinary false; one over a processing or syntax error
     * is a fault.
     */
    public static Outcome outcome(Response response, List<String> supported, boolean profile) {
        boolean fault = response.decision == com.iyasec.pep.engine.Decision.INDETERMINATE
                && !MISSING_ATTRIBUTE.equals(response.statusCode);
        return outcomeWithFault(response, fault, supported, profile);
    }

    /** {@link #outcome}, with the caller saying whether the answer is a fault. */
    public static Outcome outcomeWithFault(Response response, boolean fault, List<String> supported, boolean profile) {
        List<String> discharged = new ArrayList<>();
        List<String> undischargeable = new ArrayList<>();
        for (com.iyasec.pep.engine.Obligation obligation : response.obligations) {
            if (LOG_OBLIGATION.equals(obligation.id)) {
                discharged.add(obligation.id);
            } else {
                undischargeable.add(obligation.id);
            }
        }
        boolean permit = response.decision == com.iyasec.pep.engine.Decision.PERMIT;
        boolean decision = !fault && permit && undischargeable.isEmpty();
        String why;
        if (fault) {
            why = "The PDP could not evaluate the request (it said " + response.decision.asString() + ").";
        } else if (!permit) {
            why = "The policy said " + response.decision.asString() + ", and anything that is not Permit is a refusal.";
        } else if (undischargeable.isEmpty()) {
            why = "The policy said Permit.";
        } else {
            why = "The policy said Permit, but the decision carries obligation(s) this PEP cannot discharge ("
                    + String.join(", ", undischargeable)
                    + "); a PEP that cannot fulfil an obligation must not grant the access.";
        }
        List<Handed> handed = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        if (!fault && profile && supported != null) {
            Profiled profiled = profileObligations(response);
            problems = profiled.problems;
            boolean allDeclared = !profiled.handed.isEmpty()
                    && problems.isEmpty()
                    && profiled.handed.stream().allMatch(h -> supported.contains(h.kind));
            if (allDeclared) {
                handed = profiled.handed;
                undischargeable = new ArrayList<>();
                if (permit) {
                    decision = true;
                    why = "The policy said Permit, with obligations the caller declared it carries out.";
                }
            }
        }
        return new Outcome(decision, fault, response.decision, why, discharged, undischargeable, handed, problems);
    }

    static Row readRow(JsonNode value) throws Refusal {
        if (value != null && value.isTextual()) {
            try {
                value = Json.MAPPER.readTree(value.asText());
            } catch (Exception e) {
                String detail = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                throw rowRefused("STS-AUTHZEN-0010", "a catalogue row given as text must be JSON: " + detail);
            }
        }
        if (value == null || !value.isObject()) {
            throw rowRefused("STS-AUTHZEN-0010",
                    "a catalogue row is a JSON object: object, property, attributeId, and optionally category, dataType, multiplicity and description");
        }
        ObjectNode given = (ObjectNode) value;
        List<String> unknown = new ArrayList<>();
        for (String key : keysInJsOrder(given)) {
            if (!contains(ROW_MEMBERS, key)) {
                unknown.add("\"" + clip(key, 40) + "\"");
            }
        }
        if (!unknown.isEmpty()) {
            throw rowRefused("STS-AUTHZEN-0010",
                    "a catalogue row has no member " + String.join(", ", unknown) + "; its members are " + String.join(", ", ROW_MEMBERS));
        }
        String object = member(given, "object");
        String defaultCategory = null;
        for (String[] pair : OBJECTS) {
            if (pair[0].equals(object)) {
                defaultCategory = pair[1];
                break;
            }
        }
        if (defaultCategory == null) {
            throw rowRefused("STS-AUTHZEN-0010", "object is one of subject, resource, action, context");
        }
        String property = member(given, "property");
        String[] segments = property.isEmpty() ? new String[0] : property.split("\\.", -1);
        boolean segmentsOk = segments.length > 0 && segments.length <= MAX_PATH_DEPTH;
        if (segmentsOk) {
            for (String segment : segments) {
                if (!PATH_SEGMENT.matcher(segment).matches()) {
                    segmentsOk = false;
                    break;
                }
            }
        }
        if (!segmentsOk) {
            throw rowRefused("STS-AUTHZEN-0010",
                    "property is a member name or a dotted path of at most " + MAX_PATH_DEPTH
                            + " names, each of letters, digits, _ $ @ : or -");
        }
        if ("context".equals(object) && contains(ADAPTER_CONTEXT, segments[0])) {
            throw rowRefused("STS-AUTHZEN-0011",
                    "context." + segments[0] + " is read by the adapter itself and is never a policy property");
        }
        if ("context".equals(object) && contains(BINDING_CONTEXT, segments[0])) {
            throw rowRefused("STS-AUTHZEN-0011",
                    "context." + segments[0] + " is read by the token-exchange binding's fixed rules, which a row may add to but never override");
        }
        String attributeId = member(given, "attributeId");
        if (attributeId.isEmpty() || utf16Len(attributeId) > MAX_ATTRIBUTE_ID || anyJsSpace(attributeId)) {
            throw rowRefused("STS-AUTHZEN-0010",
                    "attributeId is a non-empty identifier without white space, of at most " + MAX_ATTRIBUTE_ID + " characters");
        }
        String categoryGiven = member(given, "category");
        String category = defaultCategory;
        if (!categoryGiven.isEmpty()) {
            category = null;
            for (String[] pair : CATEGORIES) {
                if (pair[0].equals(categoryGiven) || pair[1].equals(categoryGiven)) {
                    category = pair[1];
                    break;
                }
            }
            if (category == null) {
                throw rowRefused("STS-AUTHZEN-0010",
                        "category is one of access-subject, recipient-subject, intermediary-subject, codebase, requesting-machine, resource, action, environment, or its XACML URI");
            }
        }
        String typeGiven = member(given, "dataType");
        if (typeGiven.isEmpty()) {
            typeGiven = "string";
        }
        String dataType = null;
        for (String[] pair : DATATYPES) {
            if (pair[0].equals(typeGiven) || pair[1].equals(typeGiven)) {
                dataType = pair[1];
                break;
            }
        }
        if (dataType == null) {
            throw rowRefused("STS-AUTHZEN-0010",
                    "dataType is one of string, boolean, integer, double, time, date, dateTime, dayTimeDuration, yearMonthDuration, anyURI, hexBinary, base64Binary, rfc822Name, x500Name, dnsName, ipAddress, or its URI");
        }
        String multiplicity = member(given, "multiplicity");
        boolean bag;
        if (multiplicity.isEmpty() || "single".equals(multiplicity)) {
            bag = false;
        } else if ("bag".equals(multiplicity)) {
            bag = true;
        } else {
            throw rowRefused("STS-AUTHZEN-0010", "multiplicity is single or bag");
        }
        Refusal reserved = reserved(attributeId, category);
        if (reserved != null) {
            throw reserved;
        }
        return new Row(object, String.join(".", segments), attributeId, category, dataType, bag);
    }

    static String numberText(double n) {
        if (n == 0.0) {
            return "0";
        }
        String sign = n < 0 ? "-" : "";
        String rendered = Double.toString(Math.abs(n));
        int marker = rendered.indexOf('E');
        String mantissa = marker < 0 ? rendered : rendered.substring(0, marker);
        int exp;
        String digits;
        if (marker >= 0) {
            exp = Integer.parseInt(rendered.substring(marker + 1));
            int dot = mantissa.indexOf('.');
            digits = dot < 0 ? mantissa : mantissa.substring(0, dot) + mantissa.substring(dot + 1);
        } else {
            int dot = mantissa.indexOf('.');
            String whole = dot < 0 ? mantissa : mantissa.substring(0, dot);
            String frac = dot < 0 ? "" : mantissa.substring(dot + 1);
            if ("0".equals(whole)) {
                int zeros = 0;
                while (zeros < frac.length() && frac.charAt(zeros) == '0') {
                    zeros++;
                }
                digits = frac.substring(zeros);
                exp = -(zeros + 1);
            } else {
                digits = whole + frac;
                exp = whole.length() - 1;
            }
        }
        int end = digits.length();
        while (end > 1 && digits.charAt(end - 1) == '0') {
            end--;
        }
        digits = digits.substring(0, end);
        int k = digits.length();
        int point = exp + 1;
        String body;
        if (point >= k && point <= 21) {
            body = digits + "0".repeat(point - k);
        } else if (point >= 1 && point <= 21) {
            body = digits.substring(0, point) + "." + digits.substring(point);
        } else if (point >= -5 && point <= 0) {
            body = "0." + "0".repeat(-point) + digits;
        } else {
            int ee = point - 1;
            String eText = ee < 0 ? "-" + (-ee) : "+" + ee;
            body = k == 1 ? digits + "e" + eText : digits.charAt(0) + "." + digits.substring(1) + "e" + eText;
        }
        return sign + body;
    }

    static List<String> keysInJsOrder(ObjectNode map) {
        List<Map.Entry<Long, String>> indexed = new ArrayList<>();
        List<String> rest = new ArrayList<>();
        var fields = map.fieldNames();
        while (fields.hasNext()) {
            String key = fields.next();
            Long index = arrayIndex(key);
            if (index == null) {
                rest.add(key);
            } else {
                indexed.add(Map.entry(index, key));
            }
        }
        indexed.sort(Comparator.comparingLong(Map.Entry::getKey));
        List<String> keys = new ArrayList<>();
        for (Map.Entry<Long, String> entry : indexed) {
            keys.add(entry.getValue());
        }
        keys.addAll(rest);
        return keys;
    }

    static String lexical(String dataType, JsonNode value) {
        if (value == null) {
            return null;
        }
        if (value.isTextual()) {
            String text = value.asText();
            return utf16Len(text) <= MAX_VALUE ? text : null;
        }
        if (value.isBoolean()) {
            return BOOLEAN.equals(dataType) ? Boolean.toString(value.booleanValue()) : null;
        }
        if (value.isNumber()) {
            if (INTEGER.equals(dataType) && value.isIntegralNumber()) {
                // An integer wider than the safe range is not a JavaScript number.
                java.math.BigInteger exact = value.bigIntegerValue();
                java.math.BigInteger limit = java.math.BigInteger.valueOf((long) MAX_SAFE_INTEGER);
                if (exact.abs().compareTo(limit) > 0) {
                    return null;
                }
                return numberText(exact.doubleValue());
            }
            double n = value.doubleValue();
            if (!Double.isFinite(n)) {
                return null;
            }
            if (INTEGER.equals(dataType)) {
                if (n != Math.rint(n) || Math.abs(n) > MAX_SAFE_INTEGER) {
                    return null;
                }
                return numberText(n);
            }
            if (DOUBLE.equals(dataType)) {
                return numberText(n);
            }
            return null;
        }
        return null;
    }

    static boolean lexicallyValid(String dataType, String text) {
        if (BOOLEAN.equals(dataType)) {
            String trimmed = unicodeTrim(text);
            return "true".equals(trimmed) || "false".equals(trimmed) || "1".equals(trimmed) || "0".equals(trimmed);
        }
        if (INTEGER.equals(dataType)) {
            return INTEGER_LEX.matcher(unicodeTrim(text)).matches();
        }
        if (DOUBLE.equals(dataType)) {
            return validDouble(unicodeTrim(text));
        }
        if (DATE.equals(dataType)) {
            return temporal(DATE_LEX, text, true, false);
        }
        if (TIME.equals(dataType)) {
            return temporal(TIME_LEX, text, false, true);
        }
        if (DATETIME.equals(dataType)) {
            return temporal(DATETIME_LEX, text, true, true);
        }
        if (YEARMONTH_DURATION.equals(dataType)) {
            return validYearMonth(unicodeTrim(text));
        }
        if (DAYTIME_DURATION.equals(dataType)) {
            return validDayTime(unicodeTrim(text));
        }
        if (HEXBINARY.equals(dataType)) {
            String trimmed = unicodeTrim(text);
            if (trimmed.length() % 2 != 0) {
                return false;
            }
            for (int i = 0; i < trimmed.length(); i++) {
                char c = trimmed.charAt(i);
                boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) {
                    return false;
                }
            }
            return true;
        }
        if (BASE64BINARY.equals(dataType)) {
            return validBase64(text);
        }
        if (RFC822NAME.equals(dataType)) {
            return validRfc822(unicodeTrim(text));
        }
        if (X500NAME.equals(dataType)) {
            return validX500(unicodeTrim(text));
        }
        if (DNSNAME.equals(dataType)) {
            return validDns(unicodeTrim(text));
        }
        if (IPADDRESS.equals(dataType)) {
            return validIp(unicodeTrim(text));
        }
        return true;
    }

    private static Refusal rowRefused(String code, String message) {
        return new Refusal(400, code, message);
    }

    private static Refusal refused(String code, String message) {
        return new Refusal(400, code, message);
    }

    private static Refusal reserved(String attributeId, String category) {
        if (attributeId.toLowerCase(Locale.ROOT).startsWith(RESERVED_NAMESPACE)) {
            return rowRefused("STS-AUTHZEN-0011",
                    "\"" + attributeId + "\" is in " + RESERVED_NAMESPACE
                            + ", where the trusted facts live; a request-supplied value suppresses the PIP, so a row onto it would let a caller forge one");
        }
        if (contains(ADAPTER_IDS, attributeId)) {
            return rowRefused("STS-AUTHZEN-0011",
                    "\"" + attributeId + "\" is written from subject.id, action.name or resource.id, or supplied by the PDP, and from nothing else");
        }
        if (contains(SUBJECT_CATEGORIES, category) && BARE_NAME.matcher(attributeId).matches()) {
            return rowRefused("STS-AUTHZEN-0012",
                    "\"" + attributeId + "\" in a subject category names a directory attribute, which the directory answers; map the property onto an identifier of your own, such as urn:example:"
                            + attributeId);
        }
        return null;
    }

    private static void addFgaAccess(Request request, String application) {
        boolean include = true;
        outer:
        for (Category category : request.categories) {
            for (Attribute attribute : category.attributes) {
                include = attribute.includeInResult;
                break outer;
            }
        }
        put(request, Names.RESOURCE, "urn:sts:xacml:fga:application", application, include);
        put(request, Names.ENVIRONMENT, "urn:sts:xacml:fga:stage", "access", include);
    }

    private static void put(Request request, String category, String attributeId, String value, boolean include) {
        List<AttributeValue> values = new ArrayList<>();
        if (value != null && !value.isEmpty()) {
            values.add(AttributeValue.string(value));
        }
        Attribute attribute = new Attribute(attributeId, null, include, values);
        for (Category existing : request.categories) {
            if (existing.category.equals(category)) {
                existing.attributes.add(attribute);
                return;
            }
        }
        List<Attribute> attributes = new ArrayList<>();
        attributes.add(attribute);
        request.categories.add(new Category(category, false, attributes));
    }

    private static Reading readEvaluation(JsonNode body, List<Row> rows) throws Refusal {
        if (body == null || !body.isObject()) {
            throw refused("STS-AUTHZEN-0001",
                    "An access evaluation is a JSON object with subject, action, resource and, optionally, context.");
        }
        List<String> required = new ArrayList<>(5);
        for (String[] entity : ENTITIES) {
            JsonNode object = body.get(entity[0]);
            if (object == null) {
                List<String> wanted = new ArrayList<>();
                for (int i = 1; i < entity.length; i++) {
                    wanted.add(entity[0] + "." + entity[i]);
                }
                throw refused("STS-AUTHZEN-0002",
                        "The request has no " + entity[0] + "; AuthZEN requires " + String.join(" and ", wanted) + ".");
            }
            if (!object.isObject()) {
                throw refused("STS-AUTHZEN-0003", entity[0] + " is a JSON object.");
            }
            for (int i = 1; i < entity.length; i++) {
                String member = entity[i];
                JsonNode value = object.get(member);
                if (value == null || value.isNull() || (value.isTextual() && value.asText().isEmpty())) {
                    throw refused("STS-AUTHZEN-0002", entity[0] + "." + member + " is required, as a non-empty string.");
                }
                if (value.isTextual() && utf16Len(value.asText()) <= MAX_TEXT) {
                    required.add(value.asText());
                } else {
                    throw refused("STS-AUTHZEN-0003",
                            entity[0] + "." + member + " is a string of at most " + MAX_TEXT + " characters.");
                }
            }
            JsonNode properties = object.get("properties");
            if (properties != null && !properties.isObject()) {
                throw refused("STS-AUTHZEN-0003", entity[0] + ".properties is a JSON object.");
            }
        }
        JsonNode contextNode = body.get("context");
        ObjectNode context;
        if (contextNode == null) {
            context = Json.object();
        } else if (contextNode.isObject()) {
            context = (ObjectNode) contextNode;
        } else {
            throw refused("STS-AUTHZEN-0003", "context is a JSON object.");
        }
        String application;
        JsonNode applicationNode = context.get("application");
        if (applicationNode == null) {
            application = "";
        } else if (applicationNode.isTextual() && !applicationNode.asText().isEmpty() && utf16Len(applicationNode.asText()) <= MAX_TEXT) {
            application = applicationNode.asText();
        } else {
            throw refused("STS-AUTHZEN-0003",
                    "context.application is a non-empty string naming an application this caller may ask about.");
        }
        List<String> supported = null;
        if (context.get("supported_obligations") != null) {
            supported = declaredObligations(context.get("supported_obligations"));
        }
        boolean approval = false;
        JsonNode approvalNode = context.get("approval");
        if (approvalNode != null) {
            JsonNode id = approvalNode.get("id");
            boolean wellFormed = approvalNode.isObject() && id != null && id.isTextual()
                    && !id.asText().isEmpty() && utf16Len(id.asText()) <= MAX_TEXT;
            if (!wellFormed) {
                throw refused("STS-AUTHZEN-0003",
                        "context.approval is the approval object a completed access request returned, with its id.");
            }
            approval = true;
        }
        List<String> supplied = new ArrayList<>();
        supplied.add("subject.type");
        supplied.add("subject.id");
        supplied.add("action.name");
        supplied.add("resource.type");
        supplied.add("resource.id");
        if (!application.isEmpty()) {
            supplied.add("context.application");
        }
        if (supported != null) {
            supplied.add("context.supported_obligations");
        }
        if (approval) {
            supplied.add("context.approval");
        }
        Walker walker = new Walker(rows, supplied);
        for (String entity : new String[] {"subject", "action", "resource"}) {
            JsonNode properties = body.get(entity).get("properties");
            if (properties != null && properties.isObject()) {
                walker.walk(entity, entity + ".properties.", (ObjectNode) properties, "", 0);
            }
        }
        ObjectNode rest = Json.object();
        var fields = context.fieldNames();
        while (fields.hasNext()) {
            String key = fields.next();
            if (!contains(ADAPTER_CONTEXT, key)) {
                rest.set(key, context.get(key));
            }
        }
        walker.walk("context", "context.", rest, "", 0);
        return new Reading(
                new String[] {required.get(0), required.get(1), required.get(2), required.get(3), required.get(4)},
                application, supported, walker.supplied, walker.attributes);
    }

    private static List<String> declaredObligations(JsonNode value) throws Refusal {
        Refusal refusal = refused("STS-AUTHZEN-0003",
                "context.supported_obligations is an array of at most 32 obligation type names.");
        if (value == null || !value.isArray() || value.size() > 32) {
            throw refusal;
        }
        List<String> out = new ArrayList<>();
        for (JsonNode item : value) {
            if (!item.isTextual() || utf16Len(item.asText()) > 64) {
                throw refusal;
            }
            out.add(item.asText());
        }
        return out;
    }

    private static Request buildRequest(Reading reading, Trusted trusted) {
        Builder builder = new Builder();
        builder.text(Names.ACCESS_SUBJECT, SUBJECT_ID, List.of(reading.required[1]));
        builder.text(Names.ACCESS_SUBJECT, AUTHZEN_SUBJECT_TYPE, one(reading.required[0]));
        builder.text(Names.ACTION, ACTION_ID, List.of(reading.required[2]));
        builder.text(Names.RESOURCE, RESOURCE_ID, List.of(reading.required[4]));
        builder.text(Names.RESOURCE, AUTHZEN_RESOURCE_TYPE, one(reading.required[3]));
        builder.text(Names.ENVIRONMENT, PROTOCOL, List.of("authzen"));
        builder.text(Names.ENVIRONMENT, REALM, one(trusted.realm));
        builder.text(Names.ENVIRONMENT, AUTHZEN_CALLER, one(trusted.caller));
        builder.text(Names.ENVIRONMENT, AUTHZEN_APPLICATION, one(trusted.application));
        builder.text(Names.ENVIRONMENT, AUTHZEN_SUPPLIED, reading.supplied);
        for (MappedAttribute mapped : reading.attributes) {
            builder.add(mapped.row.category, mapped.row.attributeId, mapped.values, mapped.row.dataType);
        }
        return builder.build();
    }

    private static List<String> one(String value) {
        if (value == null || value.isEmpty()) {
            return List.of();
        }
        return List.of(value);
    }

    private static Profiled profileObligations(Response response) {
        List<Handed> handed = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        for (com.iyasec.pep.engine.Obligation obligation : response.obligations) {
            if (LOG_OBLIGATION.equals(obligation.id)) {
                continue;
            }
            String named = obligation.id.startsWith(OBLIGATION_PREFIX)
                    ? obligation.id.substring(OBLIGATION_PREFIX.length()) : "";
            String kind = "custom";
            String[] required = new String[0];
            String[] arrays = new String[0];
            for (String[] spec : OBLIGATION_TYPES) {
                if (spec[0].equals(named)) {
                    kind = spec[0];
                    if ("step-up".equals(kind)) {
                        required = new String[] {"acr_value"};
                        arrays = new String[] {"amr_values"};
                    } else if ("notification".equals(kind)) {
                        required = new String[] {"to", "body"};
                        arrays = new String[] {"to"};
                    } else {
                        required = new String[] {"subject"};
                        arrays = new String[0];
                    }
                    break;
                }
            }
            ObjectNode properties = Json.object();
            if ("custom".equals(kind)) {
                properties.put("xacml_obligation", obligation.id);
            }
            if (obligation.assignments != null) {
                for (com.iyasec.pep.engine.Assignment assignment : obligation.assignments) {
                    int colon = assignment.attributeId.lastIndexOf(':');
                    String name = colon < 0 ? assignment.attributeId : assignment.attributeId.substring(colon + 1);
                    if (name.isEmpty()) {
                        continue;
                    }
                    JsonNode existing = properties.get(name);
                    if (existing == null && contains(arrays, name)) {
                        ArrayNode items = Json.array();
                        items.add(assignment.value);
                        properties.set(name, items);
                    } else if (existing == null) {
                        properties.put(name, assignment.value);
                    } else if (existing.isArray()) {
                        ((ArrayNode) existing).add(assignment.value);
                    } else {
                        ArrayNode items = Json.array();
                        items.add(existing.deepCopy());
                        items.add(assignment.value);
                        properties.set(name, items);
                    }
                }
            }
            List<String> missing = new ArrayList<>();
            for (String name : required) {
                JsonNode held = properties.get(name);
                if (held == null || (held.isTextual() && held.asText().isEmpty())) {
                    missing.add(name);
                }
            }
            if (!missing.isEmpty()) {
                problems.add(obligation.id + " is a " + kind + " obligation without " + String.join(", ", missing));
                continue;
            }
            ObjectNode object = Json.object();
            object.put("id", "obligation-" + (handed.size() + 1));
            object.put("type", kind);
            object.set("properties", properties);
            handed.add(new Handed(kind, object));
        }
        return new Profiled(handed, problems);
    }

    private static List<String> rowValues(Row row, JsonNode value, String named) throws Refusal {
        String shown = clip(named, 200);
        if (value.isObject()) {
            throw refused("STS-AUTHZEN-0008",
                    shown + " is an object, which reaches a request only through rows for its own members (" + shown + ".<member>).");
        }
        if (value.isArray() && !row.bag) {
            throw refused("STS-AUTHZEN-0007", shown + " is an array, and its row sends a single value.");
        }
        List<JsonNode> items = new ArrayList<>();
        if (value.isArray()) {
            value.forEach(items::add);
        } else {
            items.add(value);
        }
        if (items.size() > MAX_BAG) {
            throw refused("STS-AUTHZEN-0007", shown + " carries more than " + MAX_BAG + " values.");
        }
        List<String> out = new ArrayList<>();
        for (JsonNode item : items) {
            if (item == null || item.isNull()) {
                throw refused("STS-AUTHZEN-0005", shown + " holds a null, which is not a value.");
            }
            if (item.isObject() || item.isArray()) {
                throw refused("STS-AUTHZEN-0008", shown + " holds an object or an array; a bag holds scalars.");
            }
            String text = lexical(row.dataType, item);
            if (text == null) {
                throw refused("STS-AUTHZEN-0006",
                        shown + " is a JSON " + jsonKind(item) + ", which does not reach its row's " + typeLabel(row.dataType) + ".");
            }
            if (!lexicallyValid(row.dataType, text)) {
                throw refused("STS-AUTHZEN-0006", shown + " is not a valid " + typeLabel(row.dataType) + ".");
            }
            out.add(text);
        }
        return out;
    }

    private static String typeLabel(String uri) {
        for (String[] pair : DATATYPES) {
            if (pair[1].equals(uri)) {
                return pair[0];
            }
        }
        return uri;
    }

    private static String jsonKind(JsonNode value) {
        if (value.isTextual()) {
            return "string";
        }
        if (value.isNumber()) {
            return "number";
        }
        if (value.isBoolean()) {
            return "boolean";
        }
        return "object";
    }

    private static boolean temporal(Pattern pattern, String text, boolean dated, boolean timed) {
        Matcher caps = pattern.matcher(unicodeTrim(text));
        if (!caps.matches()) {
            return false;
        }
        int next = 1;
        if (dated) {
            Long month = parseLong(caps, 2);
            Long day = parseLong(caps, 3);
            if (parseLong(caps, 1) == null || month == null || day == null) {
                return false;
            }
            if (month < 1 || month > 12 || day < 1 || day > 31) {
                return false;
            }
            next = 4;
        }
        if (timed) {
            Long hour = parseLong(caps, next);
            Long minute = parseLong(caps, next + 1);
            if (hour == null || minute == null || caps.group(next + 2) == null) {
                return false;
            }
            double second;
            try {
                second = Double.parseDouble(caps.group(next + 2));
            } catch (NumberFormatException e) {
                return false;
            }
            if (hour > 24 || minute > 59 || second >= 61.0) {
                return false;
            }
        }
        return true;
    }

    private static Long parseLong(Matcher caps, int group) {
        String text = caps.group(group);
        if (text == null) {
            return null;
        }
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static boolean validYearMonth(String text) {
        Matcher caps = YEAR_MONTH.matcher(text);
        if (!caps.matches()) {
            return false;
        }
        boolean any = false;
        for (int i = 1; i <= 2; i++) {
            if (caps.group(i) != null) {
                any = true;
                if (parseGroupLong(caps.group(i)) == null) {
                    return false;
                }
            }
        }
        return any;
    }

    private static boolean validDayTime(String text) {
        Matcher caps = DAY_TIME.matcher(text);
        if (!caps.matches()) {
            return false;
        }
        if (text.endsWith("T")) {
            return false;
        }
        boolean any = false;
        for (int i = 1; i <= 4; i++) {
            if (caps.group(i) != null) {
                any = true;
            }
        }
        if (!any) {
            return false;
        }
        for (int i = 1; i <= 3; i++) {
            if (caps.group(i) != null && parseGroupLong(caps.group(i)) == null) {
                return false;
            }
        }
        return true;
    }

    private static Long parseGroupLong(String text) {
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static boolean validDouble(String text) {
        if ("INF".equals(text) || "+INF".equals(text) || "-INF".equals(text) || "NaN".equals(text)) {
            return true;
        }
        if (!DOUBLE_LEX.matcher(text).matches()) {
            return false;
        }
        try {
            Double.parseDouble(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean validBase64(String text) {
        StringBuilder compact = new StringBuilder();
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (!isUnicodeSpace(cp)) {
                compact.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
        }
        String body = compact.toString();
        int end = body.length();
        while (end > 0 && body.charAt(end - 1) == '=') {
            end--;
        }
        String raw = body.substring(0, end);
        if (body.length() % 4 != 0 || body.length() - raw.length() > 2) {
            return false;
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean validRfc822(String text) {
        int at = text.lastIndexOf('@');
        if (at < 0) {
            return false;
        }
        String local = text.substring(0, at);
        String domain = text.substring(at + 1);
        return !local.isEmpty() && !domain.isEmpty() && cleanRfc822(local) && cleanRfc822(domain);
    }

    private static boolean cleanRfc822(String text) {
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (isUnicodeSpace(cp) || cp == '@') {
                return false;
            }
            i += Character.charCount(cp);
        }
        return true;
    }

    private static boolean validX500(String text) {
        if (text.isEmpty()) {
            return false;
        }
        List<StringBuilder> pieces = new ArrayList<>();
        pieces.add(new StringBuilder());
        boolean escaped = false;
        boolean quoted = false;
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            StringBuilder current = pieces.get(pieces.size() - 1);
            if (escaped) {
                escaped = false;
                current.appendCodePoint(cp);
            } else if (cp == '\\') {
                escaped = true;
                current.appendCodePoint(cp);
            } else if (cp == '"') {
                quoted = !quoted;
                current.appendCodePoint(cp);
            } else if (cp == ',' && !quoted) {
                pieces.add(new StringBuilder());
            } else {
                current.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
        }
        for (StringBuilder piece : pieces) {
            String trimmed = unicodeTrim(piece.toString());
            int eq = trimmed.indexOf('=');
            if (eq <= 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean validPorts(String ports) {
        if (ports.isEmpty() || ports.indexOf('-') >= 0) {
            return true;
        }
        String trimmed = trimStart(ports);
        if (!trimmed.isEmpty() && (trimmed.charAt(0) == '-' || trimmed.charAt(0) == '+')) {
            trimmed = trimmed.substring(1);
        }
        int digits = 0;
        while (digits < trimmed.length() && trimmed.charAt(digits) >= '0' && trimmed.charAt(digits) <= '9') {
            digits++;
        }
        if (digits == 0) {
            return false;
        }
        try {
            Long.parseLong(trimmed.substring(0, digits));
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean validDns(String text) {
        int colon = text.indexOf(':');
        String host = colon < 0 ? text : text.substring(0, colon);
        String ports = colon < 0 ? "" : text.substring(colon + 1);
        if (host.isEmpty() || anyUnicodeSpace(host)) {
            return false;
        }
        return validPorts(ports);
    }

    private static boolean validIp(String text) {
        if (text.isEmpty()) {
            return false;
        }
        String rest;
        if (text.charAt(0) == '[') {
            int close = text.indexOf(']');
            if (close < 0) {
                return false;
            }
            rest = text.substring(close + 1);
        } else {
            int colon = text.indexOf(':');
            rest = colon < 0 ? "" : text.substring(colon);
        }
        if (rest.startsWith(":")) {
            rest = rest.substring(1);
        }
        return validPorts(rest);
    }

    /** Unicode White_Space, the set {@code trim} uses, plus U+FEFF for JSON member text. */
    static boolean isJsSpace(int codePoint) {
        return codePoint == 0xFEFF || isUnicodeSpace(codePoint);
    }

    private static boolean isUnicodeSpace(int codePoint) {
        return switch (codePoint) {
            case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000 -> true;
            default -> codePoint >= 0x2000 && codePoint <= 0x200A;
        };
    }

    private static String jsTrim(String text) {
        int start = 0;
        int end = text.length();
        while (start < end && isJsSpace(text.codePointAt(start))) {
            start += Character.charCount(text.codePointAt(start));
        }
        while (end > start) {
            int cp = text.codePointBefore(end);
            if (!isJsSpace(cp)) {
                break;
            }
            end -= Character.charCount(cp);
        }
        return text.substring(start, end);
    }

    private static String unicodeTrim(String text) {
        int start = 0;
        int end = text.length();
        while (start < end && isUnicodeSpace(text.codePointAt(start))) {
            start += Character.charCount(text.codePointAt(start));
        }
        while (end > start) {
            int cp = text.codePointBefore(end);
            if (!isUnicodeSpace(cp)) {
                break;
            }
            end -= Character.charCount(cp);
        }
        return text.substring(start, end);
    }

    private static String trimStart(String text) {
        int start = 0;
        while (start < text.length() && isUnicodeSpace(text.codePointAt(start))) {
            start += Character.charCount(text.codePointAt(start));
        }
        return text.substring(start);
    }

    private static boolean anyJsSpace(String text) {
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (isJsSpace(cp)) {
                return true;
            }
            i += Character.charCount(cp);
        }
        return false;
    }

    private static boolean anyUnicodeSpace(String text) {
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (isUnicodeSpace(cp)) {
                return true;
            }
            i += Character.charCount(cp);
        }
        return false;
    }

    private static int utf16Len(String text) {
        return text.length();
    }

    private static String clip(String text, int limit) {
        int used = 0;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            int width = Character.charCount(cp);
            if (used + width > limit) {
                break;
            }
            out.appendCodePoint(cp);
            used += width;
            i += width;
        }
        return out.toString();
    }

    private static Long arrayIndex(String key) {
        if (key.isEmpty()) {
            return null;
        }
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
        }
        if (!"0".equals(key) && key.charAt(0) == '0') {
            return null;
        }
        try {
            long n = Long.parseLong(key);
            if (n >= 0 && n < 4_294_967_295L) {
                return n;
            }
        } catch (NumberFormatException ignored) {
            return null;
        }
        return null;
    }

    private static String member(ObjectNode given, String name) {
        JsonNode value = given.get(name);
        if (value == null || !value.isTextual()) {
            return "";
        }
        return jsTrim(value.asText());
    }

    private static boolean contains(String[] values, String wanted) {
        for (String value : values) {
            if (value.equals(wanted)) {
                return true;
            }
        }
        return false;
    }

    private static final class MappedAttribute {
        final Row row;
        final List<String> values;

        MappedAttribute(Row row, List<String> values) {
            this.row = row;
            this.values = values;
        }
    }

    private static final class Reading {
        final String[] required;
        final String application;
        final List<String> supportedObligations;
        final List<String> supplied;
        final List<MappedAttribute> attributes;

        Reading(String[] required, String application, List<String> supportedObligations,
                List<String> supplied, List<MappedAttribute> attributes) {
            this.required = required;
            this.application = application;
            this.supportedObligations = supportedObligations;
            this.supplied = supplied;
            this.attributes = attributes;
        }
    }

    private static final class Walker {
        final List<Row> rows;
        final List<String> supplied;
        final List<MappedAttribute> attributes = new ArrayList<>();

        Walker(List<Row> rows, List<String> supplied) {
            this.rows = rows;
            this.supplied = supplied;
        }

        void walk(String object, String shown, ObjectNode members, String prefix, int depth) throws Refusal {
            for (String key : keysInJsOrder(members)) {
                String path = prefix.isEmpty() ? key : prefix + "." + key;
                String named = shown + path;
                JsonNode value = members.get(key);
                Row row = null;
                for (Row candidate : rows) {
                    if (candidate.object.equals(object) && candidate.property.equals(path)) {
                        row = candidate;
                        break;
                    }
                }
                String branchPrefix = path + ".";
                boolean branch = false;
                if (row == null) {
                    for (Row candidate : rows) {
                        if (candidate.object.equals(object) && candidate.property.startsWith(branchPrefix)) {
                            branch = true;
                            break;
                        }
                    }
                }
                if (row == null && !(branch && value != null && value.isObject())) {
                    throw refused("STS-AUTHZEN-0004",
                            clip(named, 200) + " is not in this realm's AuthZEN attribute catalogue, and an undeclared property is refused in every mode.");
                }
                if (value == null || value.isNull()) {
                    throw refused("STS-AUTHZEN-0005",
                            clip(named, 200) + " is null, which is neither absent nor empty: leave it out, or send a value.");
                }
                supplied.add(named);
                if (row != null) {
                    attributes.add(new MappedAttribute(row, rowValues(row, value, named)));
                } else {
                    if (depth + 1 > MAX_NESTING) {
                        throw refused("STS-AUTHZEN-0008", clip(named, 200) + " is nested too deeply.");
                    }
                    if (value.isObject()) {
                        walk(object, shown, (ObjectNode) value, path, depth + 1);
                    }
                }
            }
        }
    }

    private static final class Builder {
        final List<Category> categories = new ArrayList<>();

        void add(String category, String attributeId, List<String> values, String dataType) {
            int index = -1;
            for (int i = 0; i < categories.size(); i++) {
                if (categories.get(i).category.equals(category)) {
                    index = i;
                    break;
                }
            }
            if (index < 0) {
                categories.add(new Category(category, false, new ArrayList<>()));
                index = categories.size() - 1;
            }
            List<AttributeValue> typed = new ArrayList<>();
            for (String value : values) {
                typed.add(new AttributeValue(dataType, value));
            }
            categories.get(index).attributes.add(new Attribute(attributeId, null, true, typed));
        }

        void text(String category, String attributeId, List<String> values) {
            add(category, attributeId, values, Names.STRING);
        }

        Request build() {
            return new Request(true, false, categories);
        }
    }

    private static final class Profiled {
        final List<Handed> handed;
        final List<String> problems;

        Profiled(List<Handed> handed, List<String> problems) {
            this.handed = handed;
            this.problems = problems;
        }
    }
}
