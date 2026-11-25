// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.regex.Pattern;

/** A standard function, resolved once at compile time. */
final class Func {
    enum Kind {
        EQUAL,
        COMPARE,
        MAKE_BAG,
        BAG_SIZE,
        ONE_AND_ONLY,
        IS_IN,
        INTERSECTION,
        UNION,
        AT_LEAST_ONE_MEMBER_OF,
        SUBSET,
        SET_EQUALS,
        AND,
        OR,
        NOT,
        N_OF,
        INTEGER_ARITH,
        INTEGER_ABS,
        INTEGER_DIVIDE,
        INTEGER_MOD,
        DOUBLE_ARITH,
        DOUBLE_ABS,
        DOUBLE_DIVIDE,
        ROUND,
        FLOOR,
        DOUBLE_TO_INTEGER,
        INTEGER_TO_DOUBLE,
        TEXT,
        SUBSTRING,
        NORMALIZE_SPACE,
        NORMALIZE_TO_LOWER_CASE,
        CONCATENATE,
        STRING_FROM,
        FROM_STRING,
        TEMPORAL_ARITH,
        REGEXP_MATCH,
        RFC822_NAME_MATCH,
        X500_NAME_MATCH,
        HIGHER_ORDER,
        MAP,
        XPATH_NODE_COUNT
    }

    enum Cmp {
        GT,
        GE,
        LT,
        LE
    }

    enum Arith {
        ADD,
        SUBTRACT,
        MULTIPLY
    }

    enum TextTest {
        CONTAINS,
        STARTS_WITH,
        ENDS_WITH
    }

    enum Higher {
        ANY_OF,
        ALL_OF,
        ANY_OF_ANY,
        ALL_OF_ALL,
        ALL_OF_ANY,
        ANY_OF_ALL
    }

    /** A regexp-match's pattern: compiled at compile time when it is a literal. */
    enum PatternKind {
        DYNAMIC,
        READY,
        INVALID
    }

    final Kind kind;
    final Type type;
    final Cmp cmp;
    final Arith arith;
    final TextTest text;
    final Higher higher;
    final int sign;
    final PatternKind patternKind;
    final Pattern pattern;

    private Func(
            Kind kind,
            Type type,
            Cmp cmp,
            Arith arith,
            TextTest text,
            Higher higher,
            int sign,
            PatternKind patternKind,
            Pattern pattern) {
        this.kind = kind;
        this.type = type;
        this.cmp = cmp;
        this.arith = arith;
        this.text = text;
        this.higher = higher;
        this.sign = sign;
        this.patternKind = patternKind;
        this.pattern = pattern;
    }

    private static Func of(Kind kind) {
        return new Func(kind, null, null, null, null, null, 0, null, null);
    }

    static Func equal(Type type) {
        return new Func(Kind.EQUAL, type, null, null, null, null, 0, null, null);
    }

    static Func compare(Cmp cmp) {
        return new Func(Kind.COMPARE, null, cmp, null, null, null, 0, null, null);
    }

    static Func makeBag(Type type) {
        return new Func(Kind.MAKE_BAG, type, null, null, null, null, 0, null, null);
    }

    static Func oneAndOnly(Type type) {
        return new Func(Kind.ONE_AND_ONLY, type, null, null, null, null, 0, null, null);
    }

    static Func intersection(Type type) {
        return new Func(Kind.INTERSECTION, type, null, null, null, null, 0, null, null);
    }

    static Func union(Type type) {
        return new Func(Kind.UNION, type, null, null, null, null, 0, null, null);
    }

    static Func integerArith(Arith arith) {
        return new Func(Kind.INTEGER_ARITH, null, null, arith, null, null, 0, null, null);
    }

    static Func doubleArith(Arith arith) {
        return new Func(Kind.DOUBLE_ARITH, null, null, arith, null, null, 0, null, null);
    }

    static Func text(TextTest test) {
        return new Func(Kind.TEXT, null, null, null, test, null, 0, null, null);
    }

    static Func stringFrom(Type type) {
        return new Func(Kind.STRING_FROM, type, null, null, null, null, 0, null, null);
    }

    static Func fromString(Type type) {
        return new Func(Kind.FROM_STRING, type, null, null, null, null, 0, null, null);
    }

    static Func temporal(Type subject, int sign) {
        return new Func(Kind.TEMPORAL_ARITH, subject, null, null, null, null, sign, null, null);
    }

    static Func regexp(Type type) {
        return new Func(Kind.REGEXP_MATCH, type, null, null, null, null, 0, PatternKind.DYNAMIC, null);
    }

    static Func higher(Higher higher) {
        return new Func(Kind.HIGHER_ORDER, null, null, null, null, higher, 0, null, null);
    }

    static Func plain(Kind kind) {
        return of(kind);
    }

    Func withPattern(PatternKind kind, Pattern pattern) {
        return new Func(this.kind, type, cmp, arith, text, higher, sign, kind, pattern);
    }

    boolean isLazy() {
        return kind == Kind.AND || kind == Kind.OR || kind == Kind.N_OF || kind == Kind.HIGHER_ORDER || kind == Kind.MAP;
    }

    /** The type of the bag the function returns; {@code null} for map. */
    Type returns() {
        return switch (kind) {
            case EQUAL, COMPARE, IS_IN, AT_LEAST_ONE_MEMBER_OF, SUBSET, SET_EQUALS, AND, OR, NOT, N_OF, TEXT,
                    REGEXP_MATCH, RFC822_NAME_MATCH, X500_NAME_MATCH, HIGHER_ORDER -> Type.BOOLEAN;
            case MAKE_BAG, ONE_AND_ONLY, INTERSECTION, UNION, FROM_STRING -> type;
            case BAG_SIZE, INTEGER_ARITH, INTEGER_ABS, INTEGER_DIVIDE, INTEGER_MOD, DOUBLE_TO_INTEGER,
                    XPATH_NODE_COUNT -> Type.INTEGER;
            case DOUBLE_ARITH, DOUBLE_ABS, DOUBLE_DIVIDE, ROUND, FLOOR, INTEGER_TO_DOUBLE -> Type.DOUBLE;
            case SUBSTRING, NORMALIZE_SPACE, NORMALIZE_TO_LOWER_CASE, CONCATENATE, STRING_FROM -> Type.STRING;
            case TEMPORAL_ARITH -> type;
            case MAP -> null;
        };
    }
}
