// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import com.iyasec.pep.engine.Values.Value;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** The function library. Evaluation matches on {@link Func}; no identifier is looked up per request. */
final class Functions {
    private Functions() {}

    private static final String PREFIX = "urn:oasis:names:tc:xacml:";

    private record Named(Func func, String version) {}

    /** The function an identifier names, or {@code null}. */
    static Func lookup(String uri) {
        if (!uri.startsWith(PREFIX)) {
            return null;
        }
        String rest = uri.substring(PREFIX.length());
        String marker = ":function:";
        int at = rest.indexOf(marker);
        if (at < 0) {
            return null;
        }
        String version = rest.substring(0, at);
        String name = rest.substring(at + marker.length());
        Named named = byName(name);
        if (named == null || !named.version.equals(version)) {
            return null;
        }
        return named.func;
    }

    private static Named byName(String name) {
        Named fixed = switch (name) {
            case "and" -> new Named(Func.plain(Func.Kind.AND), "1.0");
            case "or" -> new Named(Func.plain(Func.Kind.OR), "1.0");
            case "not" -> new Named(Func.plain(Func.Kind.NOT), "1.0");
            case "n-of" -> new Named(Func.plain(Func.Kind.N_OF), "1.0");
            case "integer-add" -> new Named(Func.integerArith(Func.Arith.ADD), "1.0");
            case "integer-subtract" -> new Named(Func.integerArith(Func.Arith.SUBTRACT), "1.0");
            case "integer-multiply" -> new Named(Func.integerArith(Func.Arith.MULTIPLY), "1.0");
            case "integer-abs" -> new Named(Func.plain(Func.Kind.INTEGER_ABS), "1.0");
            case "integer-divide" -> new Named(Func.plain(Func.Kind.INTEGER_DIVIDE), "1.0");
            case "integer-mod" -> new Named(Func.plain(Func.Kind.INTEGER_MOD), "1.0");
            case "double-add" -> new Named(Func.doubleArith(Func.Arith.ADD), "1.0");
            case "double-subtract" -> new Named(Func.doubleArith(Func.Arith.SUBTRACT), "1.0");
            case "double-multiply" -> new Named(Func.doubleArith(Func.Arith.MULTIPLY), "1.0");
            case "double-abs" -> new Named(Func.plain(Func.Kind.DOUBLE_ABS), "1.0");
            case "double-divide" -> new Named(Func.plain(Func.Kind.DOUBLE_DIVIDE), "1.0");
            case "round" -> new Named(Func.plain(Func.Kind.ROUND), "1.0");
            case "floor" -> new Named(Func.plain(Func.Kind.FLOOR), "1.0");
            case "double-to-integer" -> new Named(Func.plain(Func.Kind.DOUBLE_TO_INTEGER), "1.0");
            case "integer-to-double" -> new Named(Func.plain(Func.Kind.INTEGER_TO_DOUBLE), "1.0");
            case "string-contains", "anyURI-contains" -> new Named(Func.text(Func.TextTest.CONTAINS), "3.0");
            case "string-starts-with", "anyURI-starts-with" -> new Named(Func.text(Func.TextTest.STARTS_WITH), "3.0");
            case "string-ends-with", "anyURI-ends-with" -> new Named(Func.text(Func.TextTest.ENDS_WITH), "3.0");
            case "string-substring", "anyURI-substring" -> new Named(Func.plain(Func.Kind.SUBSTRING), "3.0");
            case "string-normalize-space" -> new Named(Func.plain(Func.Kind.NORMALIZE_SPACE), "1.0");
            case "string-normalize-to-lower-case" -> new Named(Func.plain(Func.Kind.NORMALIZE_TO_LOWER_CASE), "1.0");
            case "string-concatenate" -> new Named(Func.plain(Func.Kind.CONCATENATE), "3.0");
            case "dateTime-add-dayTimeDuration", "dateTime-add-yearMonthDuration" ->
                    new Named(Func.temporal(Type.DATE_TIME, 1), "3.0");
            case "dateTime-subtract-dayTimeDuration", "dateTime-subtract-yearMonthDuration" ->
                    new Named(Func.temporal(Type.DATE_TIME, -1), "3.0");
            case "date-add-yearMonthDuration" -> new Named(Func.temporal(Type.DATE, 1), "3.0");
            case "date-subtract-yearMonthDuration" -> new Named(Func.temporal(Type.DATE, -1), "3.0");
            case "rfc822Name-match" -> new Named(Func.plain(Func.Kind.RFC822_NAME_MATCH), "1.0");
            case "x500Name-match" -> new Named(Func.plain(Func.Kind.X500_NAME_MATCH), "1.0");
            case "any-of" -> new Named(Func.higher(Func.Higher.ANY_OF), "3.0");
            case "all-of" -> new Named(Func.higher(Func.Higher.ALL_OF), "3.0");
            case "any-of-any" -> new Named(Func.higher(Func.Higher.ANY_OF_ANY), "3.0");
            case "all-of-all" -> new Named(Func.higher(Func.Higher.ALL_OF_ALL), "1.0");
            case "all-of-any" -> new Named(Func.higher(Func.Higher.ALL_OF_ANY), "1.0");
            case "any-of-all" -> new Named(Func.higher(Func.Higher.ANY_OF_ALL), "1.0");
            case "map" -> new Named(Func.plain(Func.Kind.MAP), "3.0");
            case "xpath-node-count" -> new Named(Func.plain(Func.Kind.XPATH_NODE_COUNT), "3.0");
            default -> null;
        };
        if (fixed != null) {
            return fixed;
        }
        if (name.startsWith("string-from-")) {
            Type type = familyType(name.substring("string-from-".length()));
            if (type != null) {
                return new Named(Func.stringFrom(type), "3.0");
            }
        }
        for (Type type : Type.FAMILY) {
            String prefix = type.shortName() + "-";
            if (!name.startsWith(prefix)) {
                continue;
            }
            String suffix = name.substring(prefix.length());
            String familyVersion = type == Type.DAY_TIME_DURATION || type == Type.YEAR_MONTH_DURATION ? "3.0" : "1.0";
            return switch (suffix) {
                case "from-string" -> new Named(Func.fromString(type), "3.0");
                case "regexp-match" -> switch (type) {
                    case STRING -> new Named(Func.regexp(type), "1.0");
                    case ANY_URI, RFC822_NAME, X500_NAME, DNS_NAME, IP_ADDRESS -> new Named(Func.regexp(type), "2.0");
                    default -> null;
                };
                case "equal" -> new Named(Func.equal(type), familyVersion);
                case "greater-than" -> type.isOrdered() ? new Named(Func.compare(Func.Cmp.GT), familyVersion) : null;
                case "greater-than-or-equal" ->
                        type.isOrdered() ? new Named(Func.compare(Func.Cmp.GE), familyVersion) : null;
                case "less-than" -> type.isOrdered() ? new Named(Func.compare(Func.Cmp.LT), familyVersion) : null;
                case "less-than-or-equal" ->
                        type.isOrdered() ? new Named(Func.compare(Func.Cmp.LE), familyVersion) : null;
                case "bag" -> new Named(Func.makeBag(type), familyVersion);
                case "bag-size" -> new Named(Func.plain(Func.Kind.BAG_SIZE), familyVersion);
                case "one-and-only" -> new Named(Func.oneAndOnly(type), familyVersion);
                case "is-in" -> new Named(Func.plain(Func.Kind.IS_IN), familyVersion);
                case "intersection" -> new Named(Func.intersection(type), familyVersion);
                case "union" -> new Named(Func.union(type), familyVersion);
                case "at-least-one-member-of" -> new Named(Func.plain(Func.Kind.AT_LEAST_ONE_MEMBER_OF), familyVersion);
                case "subset" -> new Named(Func.plain(Func.Kind.SUBSET), familyVersion);
                case "set-equals" -> new Named(Func.plain(Func.Kind.SET_EQUALS), familyVersion);
                default -> null;
            };
        }
        return null;
    }

    private static Type familyType(String name) {
        for (Type type : Type.FAMILY) {
            if (type.shortName().equals(name)) {
                return type;
            }
        }
        return null;
    }

    /** A regexp-match whose pattern is a literal string gets it compiled now. */
    static Func precompile(Func func, Expr first) {
        if (func.kind == Func.Kind.REGEXP_MATCH
                && func.patternKind == Func.PatternKind.DYNAMIC
                && first instanceof Expr.Literal literal) {
            List<Value> values = literal.bag.values;
            if (values.size() == 1 && values.get(0) instanceof Value.Str source) {
                java.util.regex.Pattern compiled = XsdRegex.compile(source.text());
                if (compiled == null) {
                    return func.withPattern(Func.PatternKind.INVALID, null);
                }
                return func.withPattern(Func.PatternKind.READY, compiled);
            }
        }
        return func;
    }

    private static void arity(List<Bag> args, int n) {
        if (args.size() != n) {
            throw Indet.processing("a function was given the wrong number of arguments");
        }
    }

    private static BigInteger integer(Value value) {
        if (value instanceof Value.Int i) {
            return i.value();
        }
        throw Indet.processing("expected an integer");
    }

    private static double dbl(Value value) {
        if (value instanceof Value.DoubleVal d) {
            return d.value;
        }
        throw Indet.processing("expected a double");
    }

    private static String text(Value value) {
        String text = Values.text(value);
        if (text == null) {
            throw Indet.processing("expected a string");
        }
        return text;
    }

    private static Indet overflow() {
        return Indet.processing("integer arithmetic overflowed 128 bits");
    }

    private static BigInteger requireI128(BigInteger value) {
        if (!Values.fitsI128(value)) {
            throw overflow();
        }
        return value;
    }

    private static boolean contains(List<Value> values, Value candidate) {
        for (Value value : values) {
            if (Values.equal(value, candidate)) {
                return true;
            }
        }
        return false;
    }

    private static boolean subset(List<Value> left, List<Value> right) {
        for (Value value : left) {
            if (!contains(right, value)) {
                return false;
            }
        }
        return true;
    }

    private static Bag stringBag(String text) {
        return Bag.one(Type.STRING, new Value.Str(text));
    }

    /** Applies a strict function to evaluated argument bags. */
    static Bag call(Func func, List<Bag> args) {
        return switch (func.kind) {
            case EQUAL -> {
                arity(args, 2);
                yield Bag.bool(Values.equal(args.get(0).single(), args.get(1).single()));
            }
            case COMPARE -> {
                arity(args, 2);
                Integer order = Values.compare(args.get(0).single(), args.get(1).single());
                if (order == null) {
                    throw Indet.processing("the two values are not comparable");
                }
                boolean result = switch (func.cmp) {
                    case GT -> order > 0;
                    case GE -> order >= 0;
                    case LT -> order < 0;
                    case LE -> order <= 0;
                };
                yield Bag.bool(result);
            }
            case MAKE_BAG -> {
                List<Value> values = new ArrayList<>(args.size());
                for (Bag arg : args) {
                    values.add(arg.single());
                }
                yield Bag.fromList(func.type, values);
            }
            case BAG_SIZE -> {
                arity(args, 1);
                yield Bag.one(Type.INTEGER, new Value.Int(BigInteger.valueOf(args.get(0).len())));
            }
            case ONE_AND_ONLY -> {
                arity(args, 1);
                if (args.get(0).len() == 0) {
                    throw Indet.missing("one-and-only was given an empty bag");
                }
                yield Bag.one(func.type, args.get(0).single());
            }
            case IS_IN -> {
                arity(args, 2);
                yield Bag.bool(contains(args.get(1).values, args.get(0).single()));
            }
            case INTERSECTION -> {
                arity(args, 2);
                List<Value> out = new ArrayList<>();
                for (Value value : args.get(0).values) {
                    if (contains(args.get(1).values, value) && !contains(out, value)) {
                        out.add(value);
                    }
                }
                yield Bag.fromList(func.type, out);
            }
            case UNION -> {
                arity(args, 2);
                List<Value> out = new ArrayList<>();
                for (Bag arg : args) {
                    for (Value value : arg.values) {
                        if (!contains(out, value)) {
                            out.add(value);
                        }
                    }
                }
                yield Bag.fromList(func.type, out);
            }
            case AT_LEAST_ONE_MEMBER_OF -> {
                arity(args, 2);
                boolean any = false;
                for (Value value : args.get(0).values) {
                    if (contains(args.get(1).values, value)) {
                        any = true;
                        break;
                    }
                }
                yield Bag.bool(any);
            }
            case SUBSET -> {
                arity(args, 2);
                yield Bag.bool(subset(args.get(0).values, args.get(1).values));
            }
            case SET_EQUALS -> {
                arity(args, 2);
                List<Value> a = args.get(0).values;
                List<Value> b = args.get(1).values;
                yield Bag.bool(subset(a, b) && subset(b, a));
            }
            case NOT -> {
                arity(args, 1);
                if (args.get(0).single() instanceof Value.Bool b) {
                    yield Bag.bool(!b.value());
                }
                throw Indet.processing("not expects a boolean");
            }
            case INTEGER_ARITH -> {
                arity(args, 2);
                BigInteger a = integer(args.get(0).single());
                BigInteger b = integer(args.get(1).single());
                BigInteger result = switch (func.arith) {
                    case ADD -> a.add(b);
                    case SUBTRACT -> a.subtract(b);
                    case MULTIPLY -> a.multiply(b);
                };
                yield Bag.one(Type.INTEGER, new Value.Int(requireI128(result)));
            }
            case INTEGER_ABS -> {
                arity(args, 1);
                BigInteger a = integer(args.get(0).single());
                if (a.equals(Values.I128_MIN)) {
                    throw overflow();
                }
                yield Bag.one(Type.INTEGER, new Value.Int(a.abs()));
            }
            case INTEGER_DIVIDE, INTEGER_MOD -> {
                arity(args, 2);
                BigInteger a = integer(args.get(0).single());
                BigInteger b = integer(args.get(1).single());
                if (b.equals(BigInteger.ZERO)) {
                    throw Indet.processing("division by zero");
                }
                if (a.equals(Values.I128_MIN) && b.equals(BigInteger.valueOf(-1))) {
                    throw overflow();
                }
                BigInteger result = func.kind == Func.Kind.INTEGER_DIVIDE ? a.divide(b) : a.remainder(b);
                yield Bag.one(Type.INTEGER, new Value.Int(result));
            }
            case DOUBLE_ARITH -> {
                arity(args, 2);
                double a = dbl(args.get(0).single());
                double b = dbl(args.get(1).single());
                double result = switch (func.arith) {
                    case ADD -> a + b;
                    case SUBTRACT -> a - b;
                    case MULTIPLY -> a * b;
                };
                yield Bag.one(Type.DOUBLE, new Value.DoubleVal(result));
            }
            case DOUBLE_ABS, ROUND, FLOOR -> {
                arity(args, 1);
                double a = dbl(args.get(0).single());
                double result = switch (func.kind) {
                    case DOUBLE_ABS -> Math.abs(a);
                    case FLOOR -> Math.floor(a);
                    default -> roundHalfEven(a);
                };
                yield Bag.one(Type.DOUBLE, new Value.DoubleVal(result));
            }
            case DOUBLE_DIVIDE -> {
                arity(args, 2);
                double a = dbl(args.get(0).single());
                double b = dbl(args.get(1).single());
                if (b == 0.0) {
                    throw Indet.processing("division by zero");
                }
                yield Bag.one(Type.DOUBLE, new Value.DoubleVal(a / b));
            }
            case DOUBLE_TO_INTEGER -> {
                arity(args, 1);
                double a = dbl(args.get(0).single());
                double t = a < 0 ? Math.ceil(a) : Math.floor(a);
                if (!Double.isFinite(t) || Math.abs(t) >= 1.7e38) {
                    throw Indet.processing("double-to-integer cannot convert this value");
                }
                yield Bag.one(Type.INTEGER, new Value.Int(new java.math.BigDecimal(t).toBigInteger()));
            }
            case INTEGER_TO_DOUBLE -> {
                arity(args, 1);
                yield Bag.one(Type.DOUBLE, new Value.DoubleVal(integer(args.get(0).single()).doubleValue()));
            }
            case TEXT -> {
                arity(args, 2);
                String needle = text(args.get(0).single());
                String haystack = text(args.get(1).single());
                boolean result = switch (func.text) {
                    case CONTAINS -> haystack.contains(needle);
                    case STARTS_WITH -> haystack.startsWith(needle);
                    case ENDS_WITH -> haystack.endsWith(needle);
                };
                yield Bag.bool(result);
            }
            case SUBSTRING -> {
                arity(args, 3);
                yield stringBag(substring(text(args.get(0).single()), integer(args.get(1).single()), integer(args.get(2).single())));
            }
            case NORMALIZE_SPACE, NORMALIZE_TO_LOWER_CASE -> {
                arity(args, 1);
                String s = text(args.get(0).single());
                yield stringBag(func.kind == Func.Kind.NORMALIZE_SPACE ? Values.trimUnicode(s) : s.toLowerCase(Locale.ROOT));
            }
            case CONCATENATE -> {
                StringBuilder out = new StringBuilder();
                for (Bag arg : args) {
                    out.append(text(arg.single()));
                }
                yield stringBag(out.toString());
            }
            case STRING_FROM -> {
                arity(args, 1);
                String written = Values.write(func.type, args.get(0).single());
                if (written == null) {
                    throw Indet.processing("the value is not of the type");
                }
                yield stringBag(written);
            }
            case FROM_STRING -> {
                arity(args, 1);
                Value parsed = Values.parse(func.type, text(args.get(0).single()));
                if (parsed == null) {
                    throw Indet.syntax("not a valid lexical form");
                }
                yield Bag.one(func.type, parsed);
            }
            case TEMPORAL_ARITH -> {
                arity(args, 2);
                if (!(args.get(0).single() instanceof Value.TemporalVal temporal)) {
                    throw Indet.processing("expected a date or dateTime");
                }
                Values.Temporal result;
                Value duration = args.get(1).single();
                if (duration instanceof Value.YearMonth months) {
                    long scaled;
                    try {
                        scaled = Math.multiplyExact(months.months(), func.sign);
                    } catch (ArithmeticException e) {
                        throw Indet.processing("the date is out of range");
                    }
                    result = Values.addMonths(temporal.temporal(), scaled);
                } else if (duration instanceof Value.DayTime seconds) {
                    result = Values.addSeconds(temporal.temporal(), func.sign * seconds.seconds);
                } else {
                    throw Indet.processing("expected a duration");
                }
                if (result == null) {
                    throw Indet.processing("the date is out of range");
                }
                yield Bag.one(func.type, new Value.TemporalVal(result));
            }
            case REGEXP_MATCH -> {
                arity(args, 2);
                String source = text(args.get(0).single());
                String subject = Values.write(func.type, args.get(1).single());
                if (subject == null) {
                    throw Indet.processing("the value is not of the type");
                }
                boolean matched = switch (func.patternKind) {
                    case READY -> XsdRegex.matches(func.pattern, subject);
                    case INVALID -> throw Indet.processing("the regular expression is refused or invalid");
                    case DYNAMIC -> {
                        java.util.regex.Pattern compiled = XsdRegex.compile(source);
                        if (compiled == null) {
                            throw Indet.processing("the regular expression is refused or invalid");
                        }
                        yield XsdRegex.matches(compiled, subject);
                    }
                };
                yield Bag.bool(matched);
            }
            case RFC822_NAME_MATCH -> {
                arity(args, 2);
                String pattern = text(args.get(0).single());
                if (!(args.get(1).single() instanceof Value.Rfc822 name)) {
                    throw Indet.processing("expected an rfc822Name");
                }
                boolean matched;
                int at = pattern.lastIndexOf('@');
                if (at >= 0) {
                    matched = pattern.substring(0, at).equals(name.local())
                            && pattern.substring(at + 1).toLowerCase(Locale.ROOT).equals(name.domain());
                } else if (pattern.startsWith(".")) {
                    matched = name.domain().endsWith(pattern.toLowerCase(Locale.ROOT));
                } else {
                    matched = name.domain().equals(pattern.toLowerCase(Locale.ROOT));
                }
                yield Bag.bool(matched);
            }
            case X500_NAME_MATCH -> {
                arity(args, 2);
                if (!(args.get(0).single() instanceof Value.X500 pattern)
                        || !(args.get(1).single() instanceof Value.X500 subject)) {
                    throw Indet.processing("expected two x500Names");
                }
                boolean matched = pattern.rdns().size() <= subject.rdns().size()
                        && Values.x500Equal(
                                pattern.rdns(),
                                subject.rdns().subList(subject.rdns().size() - pattern.rdns().size(), subject.rdns().size()));
                yield Bag.bool(matched);
            }
            case XPATH_NODE_COUNT -> throw Indet.processing("XPath is not evaluated by this engine");
            case AND, OR, N_OF, HIGHER_ORDER, MAP ->
                    throw Indet.processing("a lazy function cannot be applied to values");
        };
    }

    /** Round half to even. Non-finite values are unchanged. */
    private static double roundHalfEven(double a) {
        if (!Double.isFinite(a)) {
            return a;
        }
        double floor = Math.floor(a);
        double difference = a - floor;
        if (difference > 0.5 || (difference == 0.5 && floor % 2.0 != 0.0)) {
            return floor + 1.0;
        }
        return floor;
    }

    /** Zero-based UTF-16 indices; {@code to} -1 is the end. */
    private static String substring(String subject, BigInteger from, BigInteger to) {
        BigInteger len = BigInteger.valueOf(subject.length());
        BigInteger end = to.equals(BigInteger.valueOf(-1)) ? len : to;
        if (from.signum() < 0
                || from.compareTo(len) > 0
                || end.compareTo(len) > 0
                || (!to.equals(BigInteger.valueOf(-1)) && to.compareTo(from) < 0)) {
            throw Indet.processing("substring indices out of range");
        }
        int start = from.intValue();
        int stop = end.max(from).intValue();
        return utf16Lossy(subject.substring(start, stop));
    }

    private static String utf16Lossy(String slice) {
        StringBuilder out = new StringBuilder(slice.length());
        for (int i = 0; i < slice.length(); i++) {
            char c = slice.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < slice.length() && Character.isLowSurrogate(slice.charAt(i + 1))) {
                    out.append(c).append(slice.charAt(++i));
                } else {
                    out.append('\uFFFD');
                }
            } else if (Character.isLowSurrogate(c)) {
                out.append('\uFFFD');
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    @FunctionalInterface
    interface Eval {
        Bag eval(Expr expr);
    }

    /** Applies a lazy function. {@code eval} evaluates one argument expression. */
    static Bag callLazy(Func func, List<Expr> args, Eval eval) {
        return switch (func.kind) {
            case AND -> {
                for (Expr arg : args) {
                    if (!eval.eval(arg).asBoolean()) {
                        yield Bag.bool(false);
                    }
                }
                yield Bag.bool(true);
            }
            case OR -> {
                for (Expr arg : args) {
                    if (eval.eval(arg).asBoolean()) {
                        yield Bag.bool(true);
                    }
                }
                yield Bag.bool(false);
            }
            case N_OF -> nOf(args, eval);
            case HIGHER_ORDER -> {
                Func applied = functionArgument(args);
                if (args.size() != 3) {
                    throw Indet.processing("a higher-order function takes a function and two arguments");
                }
                Bag a = eval.eval(args.get(1));
                Bag b = eval.eval(args.get(2));
                yield Bag.bool(quantify(func.higher, applied, a, b));
            }
            case MAP -> map(args, eval);
            default -> throw Indet.processing("not a lazy function");
        };
    }

    private static Bag nOf(List<Expr> args, Eval eval) {
        if (args.isEmpty()) {
            throw Indet.processing("n-of needs its count");
        }
        Bag count = eval.eval(args.get(0));
        if (count.ty != Type.INTEGER || count.values.size() != 1 || !(count.values.get(0) instanceof Value.Int n)) {
            throw Indet.processing("n-of's count must be one integer");
        }
        int rest = args.size() - 1;
        if (n.value().signum() < 0 || n.value().compareTo(BigInteger.valueOf(rest)) > 0) {
            throw Indet.processing("n-of's count cannot be satisfied");
        }
        int needed = n.value().intValue();
        int found = 0;
        for (int i = 1; i < args.size(); i++) {
            if (found >= needed) {
                break;
            }
            if (eval.eval(args.get(i)).asBoolean()) {
                found++;
            }
        }
        return Bag.bool(found >= needed);
    }

    private static Bag map(List<Expr> args, Eval eval) {
        Func applied = functionArgument(args);
        List<Bag> bags = new ArrayList<>();
        for (int i = 1; i < args.size(); i++) {
            bags.add(eval.eval(args.get(i)));
        }
        if (bags.isEmpty()) {
            throw Indet.processing("map takes a function and a bag");
        }
        Bag target = bags.remove(bags.size() - 1);
        Type resultType = null;
        List<Value> values = new ArrayList<>(target.len());
        for (Value candidate : target.values) {
            bags.add(Bag.one(target.ty, candidate));
            Bag produced = call(applied, bags);
            bags.remove(bags.size() - 1);
            values.add(produced.single());
            resultType = produced.ty;
        }
        Type ty = resultType != null ? resultType : applied.returns();
        if (ty == null) {
            ty = target.ty;
        }
        return Bag.fromList(ty, values);
    }

    private static Func functionArgument(List<Expr> args) {
        if (!args.isEmpty() && args.get(0) instanceof Expr.FunctionRef ref) {
            return ref.func;
        }
        throw Indet.processing("a higher-order function needs a <Function> first");
    }

    private static boolean applyPair(Func func, Type leftType, Value left, Type rightType, Value right) {
        if (func.isLazy()) {
            throw Indet.processing("a lazy function cannot be applied to values");
        }
        return call(func, List.of(Bag.one(leftType, left), Bag.one(rightType, right))).asBoolean();
    }

    private static boolean anyOf(List<Value> items, java.util.function.Function<Value, Boolean> test) {
        for (Value item : items) {
            if (test.apply(item)) {
                return true;
            }
        }
        return false;
    }

    private static boolean allOf(List<Value> items, java.util.function.Function<Value, Boolean> test) {
        for (Value item : items) {
            if (!test.apply(item)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The six higher-order functions. {@code all-of-any} quantifies all over the first bag
     * and {@code any-of-all} all over the second.
     */
    private static boolean quantify(Func.Higher kind, Func func, Bag a, Bag b) {
        if (kind == Func.Higher.ANY_OF || kind == Func.Higher.ALL_OF) {
            boolean valueFirst = a.len() == 1 && b.len() != 1;
            Bag single = valueFirst ? a : b;
            Bag many = valueFirst ? b : a;
            if (single.values.isEmpty()) {
                throw Indet.processing("any-of and all-of need one value against a bag");
            }
            Value one = single.values.get(0);
            boolean any = false;
            boolean all = true;
            for (Value candidate : many.values) {
                boolean result = valueFirst
                        ? applyPair(func, single.ty, one, many.ty, candidate)
                        : applyPair(func, many.ty, candidate, single.ty, one);
                any |= result;
                all &= result;
            }
            return kind == Func.Higher.ANY_OF ? any : all;
        }
        return switch (kind) {
            case ANY_OF_ANY -> anyOf(a.values, x -> anyOf(b.values, y -> applyPair(func, a.ty, x, b.ty, y)));
            case ALL_OF_ALL -> allOf(a.values, x -> allOf(b.values, y -> applyPair(func, a.ty, x, b.ty, y)));
            case ALL_OF_ANY -> allOf(a.values, x -> anyOf(b.values, y -> applyPair(func, a.ty, x, b.ty, y)));
            case ANY_OF_ALL -> allOf(b.values, y -> anyOf(a.values, x -> applyPair(func, a.ty, x, b.ty, y)));
            default -> throw Indet.processing("not a higher-order function");
        };
    }
}
