// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

/**
 * The datatypes, by URI. {@link #OTHER} is a datatype this engine does not know:
 * a designator may still name it, and any value of it fails to parse.
 */
enum Type {
    STRING,
    BOOLEAN,
    INTEGER,
    DOUBLE,
    TIME,
    DATE,
    DATE_TIME,
    DAY_TIME_DURATION,
    YEAR_MONTH_DURATION,
    ANY_URI,
    HEX_BINARY,
    BASE64_BINARY,
    RFC822_NAME,
    X500_NAME,
    DNS_NAME,
    IP_ADDRESS,
    XPATH_EXPRESSION,
    OTHER;

    private static final String XS = "http://www.w3.org/2001/XMLSchema#";
    private static final String LEGACY_XQ = "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#";

    /** Every known type but {@link #XPATH_EXPRESSION}, which takes part in no function family, and {@link #OTHER}. */
    static final Type[] FAMILY = {
        STRING,
        BOOLEAN,
        INTEGER,
        DOUBLE,
        TIME,
        DATE,
        DATE_TIME,
        DAY_TIME_DURATION,
        YEAR_MONTH_DURATION,
        ANY_URI,
        HEX_BINARY,
        BASE64_BINARY,
        RFC822_NAME,
        X500_NAME,
        DNS_NAME,
        IP_ADDRESS
    };

    /** The type a URI names. The two pre-3.0 XQuery spellings of the durations are accepted. */
    static Type fromUri(String uri) {
        if (uri.startsWith(XS)) {
            return switch (uri.substring(XS.length())) {
                case "string" -> STRING;
                case "boolean" -> BOOLEAN;
                case "integer" -> INTEGER;
                case "double" -> DOUBLE;
                case "time" -> TIME;
                case "date" -> DATE;
                case "dateTime" -> DATE_TIME;
                case "dayTimeDuration" -> DAY_TIME_DURATION;
                case "yearMonthDuration" -> YEAR_MONTH_DURATION;
                case "anyURI" -> ANY_URI;
                case "hexBinary" -> HEX_BINARY;
                case "base64Binary" -> BASE64_BINARY;
                default -> OTHER;
            };
        }
        return switch (uri) {
            case "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name" -> RFC822_NAME;
            case "urn:oasis:names:tc:xacml:1.0:data-type:x500Name" -> X500_NAME;
            case "urn:oasis:names:tc:xacml:2.0:data-type:dnsName" -> DNS_NAME;
            case "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress" -> IP_ADDRESS;
            case "urn:oasis:names:tc:xacml:3.0:data-type:xpathExpression" -> XPATH_EXPRESSION;
            default -> {
                if (uri.startsWith(LEGACY_XQ)) {
                    yield switch (uri.substring(LEGACY_XQ.length())) {
                        case "dayTimeDuration" -> DAY_TIME_DURATION;
                        case "yearMonthDuration" -> YEAR_MONTH_DURATION;
                        default -> OTHER;
                    };
                }
                yield OTHER;
            }
        };
    }

    /** The canonical URI; {@code null} for {@link #OTHER}. */
    String uri() {
        return switch (this) {
            case STRING -> "http://www.w3.org/2001/XMLSchema#string";
            case BOOLEAN -> "http://www.w3.org/2001/XMLSchema#boolean";
            case INTEGER -> "http://www.w3.org/2001/XMLSchema#integer";
            case DOUBLE -> "http://www.w3.org/2001/XMLSchema#double";
            case TIME -> "http://www.w3.org/2001/XMLSchema#time";
            case DATE -> "http://www.w3.org/2001/XMLSchema#date";
            case DATE_TIME -> "http://www.w3.org/2001/XMLSchema#dateTime";
            case DAY_TIME_DURATION -> "http://www.w3.org/2001/XMLSchema#dayTimeDuration";
            case YEAR_MONTH_DURATION -> "http://www.w3.org/2001/XMLSchema#yearMonthDuration";
            case ANY_URI -> "http://www.w3.org/2001/XMLSchema#anyURI";
            case HEX_BINARY -> "http://www.w3.org/2001/XMLSchema#hexBinary";
            case BASE64_BINARY -> "http://www.w3.org/2001/XMLSchema#base64Binary";
            case RFC822_NAME -> "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";
            case X500_NAME -> "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";
            case DNS_NAME -> "urn:oasis:names:tc:xacml:2.0:data-type:dnsName";
            case IP_ADDRESS -> "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress";
            case XPATH_EXPRESSION -> "urn:oasis:names:tc:xacml:3.0:data-type:xpathExpression";
            case OTHER -> null;
        };
    }

    /** The short name function identifiers are built from. */
    String shortName() {
        return switch (this) {
            case STRING -> "string";
            case BOOLEAN -> "boolean";
            case INTEGER -> "integer";
            case DOUBLE -> "double";
            case TIME -> "time";
            case DATE -> "date";
            case DATE_TIME -> "dateTime";
            case DAY_TIME_DURATION -> "dayTimeDuration";
            case YEAR_MONTH_DURATION -> "yearMonthDuration";
            case ANY_URI -> "anyURI";
            case HEX_BINARY -> "hexBinary";
            case BASE64_BINARY -> "base64Binary";
            case RFC822_NAME -> "rfc822Name";
            case X500_NAME -> "x500Name";
            case DNS_NAME -> "dnsName";
            case IP_ADDRESS -> "ipAddress";
            case XPATH_EXPRESSION -> "xpathExpression";
            case OTHER -> "";
        };
    }

    /** Whether the type has an order (and so the four comparison functions). */
    boolean isOrdered() {
        return switch (this) {
            case STRING, INTEGER, DOUBLE, TIME, DATE, DATE_TIME, DAY_TIME_DURATION, YEAR_MONTH_DURATION -> true;
            default -> false;
        };
    }
}
