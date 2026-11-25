// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** Lexical form to value, value back to the canonical lexical form, equality and order. */
final class Values {
    private Values() {}

    /** Years beyond this are refused rather than risking overflow in the calendar arithmetic. */
    static final long MAX_YEAR = 999_999_999L;
    static final BigInteger I128_MAX = BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE);
    static final BigInteger I128_MIN = BigInteger.ONE.shiftLeft(127).negate();

    enum Shape {
        DATE,
        TIME,
        DATE_TIME
    }

    /** A date, time or dateTime. {@code tz} is minutes east of UTC; {@code null} is not UTC. */
    static final class Temporal {
        final Shape shape;
        final long year;
        final int month;
        final int day;
        final int hour;
        final int minute;
        final double second;
        final Integer tz;

        Temporal(Shape shape, long year, int month, int day, int hour, int minute, double second, Integer tz) {
            this.shape = shape;
            this.year = year;
            this.month = month;
            this.day = day;
            this.hour = hour;
            this.minute = minute;
            this.second = second;
            this.tz = tz;
        }

        Temporal withDate(long year, int month, int day) {
            return new Temporal(shape, year, month, day, hour, minute, second, tz);
        }

        Temporal withTime(int hour, int minute, double second) {
            return new Temporal(shape, year, month, day, hour, minute, second, tz);
        }
    }

    /** A port range; {@code null} at an end is unbounded. */
    static final class Ports {
        final Long low;
        final Long high;

        Ports(Long low, Long high) {
            this.low = low;
            this.high = high;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Ports other)) {
                return false;
            }
            return Objects.equals(low, other.low) && Objects.equals(high, other.high);
        }

        @Override
        public int hashCode() {
            return Objects.hash(low, high);
        }
    }

    static final class Rdn {
        final String attribute;
        final String value;

        Rdn(String attribute, String value) {
            this.attribute = attribute;
            this.value = value;
        }
    }

    static final class IpAddress {
        final String address;
        final String mask;
        final Ports ports;

        IpAddress(String address, String mask, Ports ports) {
            this.address = address;
            this.mask = mask;
            this.ports = ports;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof IpAddress other)) {
                return false;
            }
            return address.equals(other.address) && Objects.equals(mask, other.mask) && ports.equals(other.ports);
        }

        @Override
        public int hashCode() {
            return Objects.hash(address, mask, ports);
        }
    }

    sealed interface Value {
        record Str(String text) implements Value {}

        record Bool(boolean value) implements Value {}

        record Int(BigInteger value) implements Value {}

        final class DoubleVal implements Value {
            final double value;

            DoubleVal(double value) {
                this.value = value;
            }

            @Override
            public boolean equals(Object o) {
                return o instanceof DoubleVal other && value == other.value;
            }

            @Override
            public int hashCode() {
                return Double.hashCode(value);
            }
        }

        record TemporalVal(Temporal temporal) implements Value {}

        record YearMonth(long months) implements Value {}

        final class DayTime implements Value {
            final double seconds;

            DayTime(double seconds) {
                this.seconds = seconds;
            }

            @Override
            public boolean equals(Object o) {
                return o instanceof DayTime other && seconds == other.seconds;
            }

            @Override
            public int hashCode() {
                return Double.hashCode(seconds);
            }
        }

        record AnyUri(String text) implements Value {}

        final class Hex implements Value {
            final byte[] data;

            Hex(byte[] data) {
                this.data = data;
            }

            @Override
            public boolean equals(Object o) {
                return o instanceof Hex other && Arrays.equals(data, other.data);
            }

            @Override
            public int hashCode() {
                return Arrays.hashCode(data);
            }
        }

        final class Base64Val implements Value {
            final byte[] data;

            Base64Val(byte[] data) {
                this.data = data;
            }

            @Override
            public boolean equals(Object o) {
                return o instanceof Base64Val other && Arrays.equals(data, other.data);
            }

            @Override
            public int hashCode() {
                return Arrays.hashCode(data);
            }
        }

        /** The local part as written and the domain lower-cased. */
        record Rfc822(String local, String domain) implements Value {}

        record X500(List<Rdn> rdns) implements Value {}

        /** The host lower-cased. */
        record Dns(String host, Ports ports) implements Value {}

        record Ip(IpAddress address) implements Value {}

        record XPath(String text) implements Value {}
    }

    /** The text of a string or an anyURI, which the string functions treat alike. */
    static String text(Value value) {
        if (value instanceof Value.Str s) {
            return s.text;
        }
        if (value instanceof Value.AnyUri s) {
            return s.text;
        }
        return null;
    }

    /**
     * A canonical datatype URI: the legacy duration spellings mapped to XML Schema's,
     * anything else unchanged.
     */
    static String canonicalUri(String uri) {
        Type type = Type.fromUri(uri);
        if (type == Type.DAY_TIME_DURATION || type == Type.YEAR_MONTH_DURATION) {
            String canonical = type.uri();
            return canonical == null ? uri : canonical;
        }
        return uri;
    }

    /** Parses a lexical form at a type. {@code null} is a syntax error. */
    static Value parse(Type type, String lexical) {
        String text = lexical.trim();
        return switch (type) {
            case STRING -> new Value.Str(lexical);
            case BOOLEAN -> switch (text) {
                case "true", "1" -> new Value.Bool(true);
                case "false", "0" -> new Value.Bool(false);
                default -> null;
            };
            case INTEGER -> {
                BigInteger integer = parseInteger(text);
                yield integer == null ? null : new Value.Int(integer);
            }
            case DOUBLE -> {
                Double parsed = parseDouble(text);
                yield parsed == null ? null : new Value.DoubleVal(parsed);
            }
            case DATE -> {
                Temporal temporal = parseTemporal(text, Shape.DATE);
                yield temporal == null ? null : new Value.TemporalVal(temporal);
            }
            case TIME -> {
                Temporal temporal = parseTemporal(text, Shape.TIME);
                yield temporal == null ? null : new Value.TemporalVal(temporal);
            }
            case DATE_TIME -> {
                Temporal temporal = parseTemporal(text, Shape.DATE_TIME);
                yield temporal == null ? null : new Value.TemporalVal(temporal);
            }
            case YEAR_MONTH_DURATION -> {
                Long months = parseYearMonth(text);
                yield months == null ? null : new Value.YearMonth(months);
            }
            case DAY_TIME_DURATION -> {
                Double seconds = parseDayTime(text);
                yield seconds == null ? null : new Value.DayTime(seconds);
            }
            case ANY_URI -> new Value.AnyUri(text);
            case HEX_BINARY -> {
                byte[] bytes = parseHex(text);
                yield bytes == null ? null : new Value.Hex(bytes);
            }
            case BASE64_BINARY -> {
                byte[] bytes = parseBase64(lexical);
                yield bytes == null ? null : new Value.Base64Val(bytes);
            }
            case RFC822_NAME -> parseRfc822(text);
            case X500_NAME -> {
                List<Rdn> rdns = parseX500(text);
                yield rdns == null ? null : new Value.X500(rdns);
            }
            case DNS_NAME -> parseDns(text);
            case IP_ADDRESS -> parseIp(text);
            case XPATH_EXPRESSION -> new Value.XPath(text);
            case OTHER -> null;
        };
    }

    /** A value's canonical lexical form at a type. {@code null} when it cannot be written. */
    static String write(Type type, Value value) {
        return switch (type) {
            case STRING, ANY_URI -> {
                String text = text(value);
                yield text;
            }
            case BOOLEAN -> value instanceof Value.Bool b ? Boolean.toString(b.value) : null;
            case INTEGER -> value instanceof Value.Int i ? i.value.toString() : null;
            case DOUBLE -> value instanceof Value.DoubleVal d ? writeDouble(d.value) : null;
            case DATE, TIME, DATE_TIME -> value instanceof Value.TemporalVal t ? writeTemporal(t.temporal) : null;
            case YEAR_MONTH_DURATION -> value instanceof Value.YearMonth m ? writeYearMonth(m.months) : null;
            case DAY_TIME_DURATION -> value instanceof Value.DayTime d ? writeDayTime(d.seconds) : null;
            case HEX_BINARY -> value instanceof Value.Hex h ? writeHex(h.data) : null;
            case BASE64_BINARY -> value instanceof Value.Base64Val b ? encodeBase64(b.data) : null;
            case RFC822_NAME -> value instanceof Value.Rfc822 r ? r.local + "@" + r.domain : null;
            case X500_NAME -> value instanceof Value.X500 x ? writeX500(x.rdns) : null;
            case DNS_NAME -> value instanceof Value.Dns d ? writeHostPorts(d.host, d.ports) : null;
            case IP_ADDRESS -> value instanceof Value.Ip ip ? writeIp(ip.address) : null;
            case XPATH_EXPRESSION -> value instanceof Value.XPath x ? x.text : null;
            case OTHER -> null;
        };
    }

    static boolean equal(Value a, Value b) {
        if (a instanceof Value.DoubleVal x && b instanceof Value.DoubleVal y) {
            return (Double.isNaN(x.value) && Double.isNaN(y.value)) || x.value == y.value;
        }
        if (a instanceof Value.TemporalVal x && b instanceof Value.TemporalVal y) {
            Integer order = compareTemporal(x.temporal, y.temporal);
            return order != null && order == 0;
        }
        if (a instanceof Value.X500 x && b instanceof Value.X500 y) {
            return x500Equal(x.rdns, y.rdns);
        }
        return a.equals(b);
    }

    /** The order, or {@code null} when the two are incomparable. */
    static Integer compare(Value a, Value b) {
        if (a instanceof Value.Str x && b instanceof Value.Str y) {
            return x.text.compareTo(y.text);
        }
        if (a instanceof Value.Int x && b instanceof Value.Int y) {
            return x.value.compareTo(y.value);
        }
        if (a instanceof Value.DoubleVal x && b instanceof Value.DoubleVal y) {
            return partialCompare(x.value, y.value);
        }
        if (a instanceof Value.TemporalVal x && b instanceof Value.TemporalVal y) {
            return compareTemporal(x.temporal, y.temporal);
        }
        if (a instanceof Value.YearMonth x && b instanceof Value.YearMonth y) {
            return Long.compare(x.months, y.months);
        }
        if (a instanceof Value.DayTime x && b instanceof Value.DayTime y) {
            return partialCompare(x.seconds, y.seconds);
        }
        return null;
    }

    static boolean x500Equal(List<Rdn> a, List<Rdn> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (int i = 0; i < a.size(); i++) {
            if (!a.get(i).attribute.equals(b.get(i).attribute)
                    || !a.get(i).value.toLowerCase(Locale.ROOT).equals(b.get(i).value.toLowerCase(Locale.ROOT))) {
                return false;
            }
        }
        return true;
    }

    static boolean fitsI128(BigInteger value) {
        return value.compareTo(I128_MIN) >= 0 && value.compareTo(I128_MAX) <= 0;
    }

    private static boolean allDigits(String text) {
        if (text.isEmpty()) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            if (!isDigit(text.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /** Unicode White_Space, the characters trimmed from a string. */
    static boolean isUnicodeSpace(int cp) {
        return cp == 0x09 || cp == 0x0A || cp == 0x0B || cp == 0x0C || cp == 0x0D || cp == 0x20
                || cp == 0x85 || cp == 0xA0 || cp == 0x1680 || cp == 0x2028 || cp == 0x2029
                || cp == 0x202F || cp == 0x205F || cp == 0x3000 || (cp >= 0x2000 && cp <= 0x200A);
    }

    static String trimUnicode(String text) {
        int start = 0;
        int end = text.length();
        while (start < end) {
            int cp = text.codePointAt(start);
            if (!isUnicodeSpace(cp)) {
                break;
            }
            start += Character.charCount(cp);
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

    private static boolean hasSpace(String text) {
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (isUnicodeSpace(cp)) {
                return true;
            }
            i += Character.charCount(cp);
        }
        return false;
    }

    private static BigInteger parseInteger(String text) {
        String digits = text.startsWith("+") || text.startsWith("-") ? text.substring(1) : text;
        if (!allDigits(digits)) {
            return null;
        }
        String body = text.startsWith("+") ? text.substring(1) : text;
        try {
            BigInteger value = new BigInteger(body);
            return fitsI128(value) ? value : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Double parseDouble(String text) {
        switch (text) {
            case "INF", "+INF" -> {
                return Double.POSITIVE_INFINITY;
            }
            case "-INF" -> {
                return Double.NEGATIVE_INFINITY;
            }
            case "NaN" -> {
                return Double.NaN;
            }
            default -> {
            }
        }
        String body = text.startsWith("+") || text.startsWith("-") ? text.substring(1) : text;
        int expAt = indexOfExponent(body);
        String mantissa = expAt < 0 ? body : body.substring(0, expAt);
        String exponent = expAt < 0 ? null : body.substring(expAt + 1);
        boolean mantissaOk;
        int dot = mantissa.indexOf('.');
        if (dot < 0) {
            mantissaOk = allDigits(mantissa);
        } else {
            String whole = mantissa.substring(0, dot);
            String fraction = mantissa.substring(dot + 1);
            mantissaOk = (allDigits(whole) && (fraction.isEmpty() || allDigits(fraction)))
                    || (whole.isEmpty() && allDigits(fraction));
        }
        boolean exponentOk = exponent == null || allDigits(stripSign(exponent));
        if (!(mantissaOk && exponentOk)) {
            return null;
        }
        try {
            return Double.parseDouble(javaDouble(text));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** {@code Double.parseDouble} rejects a trailing dot; the lexical grammar allows it. */
    private static String javaDouble(String text) {
        int exp = indexOfExponent(text.startsWith("+") || text.startsWith("-") ? text.substring(1) : text);
        int absolute = exp < 0 ? -1 : exp + ((text.startsWith("+") || text.startsWith("-")) ? 1 : 0);
        String mantissa = absolute < 0 ? text : text.substring(0, absolute);
        String exponent = absolute < 0 ? "" : text.substring(absolute);
        if (mantissa.endsWith(".")) {
            mantissa = mantissa + "0";
        }
        return mantissa + exponent;
    }

    private static int indexOfExponent(String body) {
        int e = body.indexOf('e');
        int big = body.indexOf('E');
        if (e < 0) {
            return big;
        }
        if (big < 0) {
            return e;
        }
        return Math.min(e, big);
    }

    private static String stripSign(String text) {
        if (text.startsWith("+") || text.startsWith("-")) {
            return text.substring(1);
        }
        return text;
    }

    private static Long digitsN(String text, int n, long[] value) {
        if (text.length() < n) {
            return null;
        }
        String head = text.substring(0, n);
        if (!allDigits(head)) {
            return null;
        }
        value[0] = Long.parseLong(head);
        return (long) n;
    }

    /** {@code Z}, {@code +hh:mm} or {@code -hh:mm}, or nothing. Hours and minutes are not range-checked. */
    private static Integer[] parseTimezone(String text) {
        if (text.isEmpty()) {
            return new Integer[] {null};
        }
        if (text.equals("Z")) {
            return new Integer[] {0};
        }
        int sign = switch (text.charAt(0)) {
            case '+' -> 1;
            case '-' -> -1;
            default -> 0;
        };
        if (sign == 0) {
            return null;
        }
        long[] hours = new long[1];
        Long consumed = digitsN(text.substring(1), 2, hours);
        if (consumed == null) {
            return null;
        }
        String rest = text.substring(1 + consumed.intValue());
        if (!rest.startsWith(":")) {
            return null;
        }
        long[] minutes = new long[1];
        consumed = digitsN(rest.substring(1), 2, minutes);
        if (consumed == null || rest.length() != 1 + consumed) {
            return null;
        }
        return new Integer[] {sign * (int) (hours[0] * 60 + minutes[0])};
    }

    private static Object[] parseDatePart(String text) {
        boolean negative = text.startsWith("-");
        String rest = negative ? text.substring(1) : text;
        int yearLen = 0;
        while (yearLen < rest.length() && isDigit(rest.charAt(yearLen))) {
            yearLen++;
        }
        if (yearLen < 4) {
            return null;
        }
        long year;
        try {
            year = Long.parseLong(rest.substring(0, yearLen));
        } catch (NumberFormatException e) {
            return null;
        }
        if (year > MAX_YEAR) {
            return null;
        }
        rest = rest.substring(yearLen);
        if (!rest.startsWith("-")) {
            return null;
        }
        long[] month = new long[1];
        Long consumed = digitsN(rest.substring(1), 2, month);
        if (consumed == null) {
            return null;
        }
        rest = rest.substring(1 + consumed.intValue());
        if (!rest.startsWith("-")) {
            return null;
        }
        long[] day = new long[1];
        consumed = digitsN(rest.substring(1), 2, day);
        if (consumed == null) {
            return null;
        }
        return new Object[] {negative ? -year : year, month[0], day[0], rest.substring(1 + consumed.intValue())};
    }

    private static Object[] parseTimePart(String text) {
        long[] hour = new long[1];
        Long consumed = digitsN(text, 2, hour);
        if (consumed == null) {
            return null;
        }
        String rest = text.substring(consumed.intValue());
        if (!rest.startsWith(":")) {
            return null;
        }
        long[] minute = new long[1];
        consumed = digitsN(rest.substring(1), 2, minute);
        if (consumed == null) {
            return null;
        }
        rest = rest.substring(1 + consumed.intValue());
        if (!rest.startsWith(":")) {
            return null;
        }
        rest = rest.substring(1);
        if (rest.length() < 2 || !allDigits(rest.substring(0, 2))) {
            return null;
        }
        int end = 2;
        if (rest.length() > 2 && rest.charAt(2) == '.') {
            int fraction = 0;
            int i = 3;
            while (i < rest.length() && isDigit(rest.charAt(i))) {
                fraction++;
                i++;
            }
            if (fraction == 0) {
                return null;
            }
            end = 3 + fraction;
        }
        double second;
        try {
            second = Double.parseDouble(rest.substring(0, end));
        } catch (NumberFormatException e) {
            return null;
        }
        return new Object[] {hour[0], minute[0], second, rest.substring(end)};
    }

    private static Temporal parseTemporal(String text, Shape shape) {
        long year = 1970;
        long month = 1;
        long day = 1;
        long hour = 0;
        long minute = 0;
        double second = 0;
        String rest;
        switch (shape) {
            case DATE -> {
                Object[] part = parseDatePart(text);
                if (part == null) {
                    return null;
                }
                year = (Long) part[0];
                month = (Long) part[1];
                day = (Long) part[2];
                rest = (String) part[3];
            }
            case TIME -> {
                Object[] part = parseTimePart(text);
                if (part == null) {
                    return null;
                }
                hour = (Long) part[0];
                minute = (Long) part[1];
                second = (Double) part[2];
                rest = (String) part[3];
            }
            case DATE_TIME -> {
                Object[] date = parseDatePart(text);
                if (date == null) {
                    return null;
                }
                rest = (String) date[3];
                if (!rest.startsWith("T")) {
                    return null;
                }
                Object[] time = parseTimePart(rest.substring(1));
                if (time == null) {
                    return null;
                }
                year = (Long) date[0];
                month = (Long) date[1];
                day = (Long) date[2];
                hour = (Long) time[0];
                minute = (Long) time[1];
                second = (Double) time[2];
                rest = (String) time[3];
            }
            default -> {
                return null;
            }
        }
        Integer[] tz = parseTimezone(rest);
        if (tz == null) {
            return null;
        }
        if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 24 || minute > 59 || second >= 61.0) {
            return null;
        }
        return new Temporal(shape, year, (int) month, (int) day, (int) hour, (int) minute, second, tz[0]);
    }

    private static Long parseYearMonth(String text) {
        boolean negative = text.startsWith("-");
        String rest = negative ? text.substring(1) : text;
        if (!rest.startsWith("P")) {
            return null;
        }
        rest = rest.substring(1);
        long months = 0;
        boolean any = false;
        for (int unit = 0; unit < 2; unit++) {
            char mark = unit == 0 ? 'Y' : 'M';
            long scale = unit == 0 ? 12 : 1;
            int n = 0;
            while (n < rest.length() && isDigit(rest.charAt(n))) {
                n++;
            }
            if (n > 0 && n < rest.length() && rest.charAt(n) == mark) {
                long value;
                try {
                    value = Long.parseLong(rest.substring(0, n));
                    months = Math.addExact(months, Math.multiplyExact(value, scale));
                } catch (ArithmeticException | NumberFormatException e) {
                    return null;
                }
                rest = rest.substring(n + 1);
                any = true;
            }
        }
        if (!any || !rest.isEmpty()) {
            return null;
        }
        return negative ? -months : months;
    }

    private static Double parseDayTime(String text) {
        boolean negative = text.startsWith("-");
        String rest = negative ? text.substring(1) : text;
        if (!rest.startsWith("P")) {
            return null;
        }
        rest = rest.substring(1);
        double[] seconds = {0};
        boolean[] any = {false};
        String[] holder = {rest};
        if (!takeDuration(holder, 'D', 86400.0, false, seconds, any)) {
            return null;
        }
        if (holder[0].startsWith("T")) {
            if (holder[0].length() == 1) {
                return null;
            }
            holder[0] = holder[0].substring(1);
            if (!takeDuration(holder, 'H', 3600.0, false, seconds, any)
                    || !takeDuration(holder, 'M', 60.0, false, seconds, any)
                    || !takeDuration(holder, 'S', 1.0, true, seconds, any)) {
                return null;
            }
        }
        if (!any[0] || !holder[0].isEmpty()) {
            return null;
        }
        return negative ? -seconds[0] : seconds[0];
    }

    /** {@code false} is a hard failure; {@code true} may have consumed nothing. */
    private static boolean takeDuration(
            String[] rest, char unit, double scale, boolean fraction, double[] seconds, boolean[] any) {
        String s = rest[0];
        int n = 0;
        while (n < s.length() && isDigit(s.charAt(n))) {
            n++;
        }
        if (n == 0) {
            return true;
        }
        int end = n;
        if (fraction && n < s.length() && s.charAt(n) == '.') {
            int f = 0;
            int i = n + 1;
            while (i < s.length() && isDigit(s.charAt(i))) {
                f++;
                i++;
            }
            if (f == 0) {
                return true;
            }
            end = n + 1 + f;
        }
        if (end >= s.length() || s.charAt(end) != unit) {
            return true;
        }
        double value;
        try {
            if (fraction) {
                value = Double.parseDouble(s.substring(0, end));
            } else {
                value = Long.parseLong(s.substring(0, end));
            }
        } catch (NumberFormatException e) {
            return false;
        }
        seconds[0] += value * scale;
        any[0] = true;
        rest[0] = s.substring(end + 1);
        return true;
    }

    private static byte[] parseHex(String text) {
        if (text.length() % 2 != 0) {
            return null;
        }
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(text.charAt(i * 2), 16);
            int lo = Character.digit(text.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static byte[] parseBase64(String lexical) {
        StringBuilder stripped = new StringBuilder(lexical.length());
        for (int i = 0; i < lexical.length(); ) {
            int cp = lexical.codePointAt(i);
            if (!isUnicodeSpace(cp)) {
                stripped.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
        }
        byte[] text = stripped.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        if (stripped.length() != text.length || text.length % 4 != 0) {
            return null;
        }
        int bodyLen = 0;
        for (int i = text.length - 1; i >= 0; i--) {
            if (text[i] != '=') {
                bodyLen = i + 1;
                break;
            }
        }
        if (text.length - bodyLen > 2) {
            return null;
        }
        byte[] out = new byte[bodyLen * 3 / 4];
        int written = 0;
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < bodyLen; i++) {
            Integer sextet = sextet(text[i]);
            if (sextet == null) {
                return null;
            }
            buffer = (buffer << 6) | sextet;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[written++] = (byte) (buffer >> bits);
                buffer &= (1 << bits) - 1;
            }
        }
        if (written != out.length) {
            return Arrays.copyOf(out, written);
        }
        return out;
    }

    private static Integer sextet(byte b) {
        int c = b & 0xFF;
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        return null;
    }

    private static boolean hasSpaceOrAt(String text) {
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (cp == '@' || isUnicodeSpace(cp)) {
                return true;
            }
            i += Character.charCount(cp);
        }
        return false;
    }

    private static Value parseRfc822(String text) {
        int at = text.lastIndexOf('@');
        if (at <= 0 || at == text.length() - 1) {
            return null;
        }
        String local = text.substring(0, at);
        String domain = text.substring(at + 1);
        if (hasSpaceOrAt(local) || hasSpaceOrAt(domain)) {
            return null;
        }
        return new Value.Rfc822(local, domain.toLowerCase(Locale.ROOT));
    }

    private static List<Rdn> parseX500(String text) {
        if (text.isEmpty()) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean escaped = false;
        boolean quoted = false;
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            i += Character.charCount(cp);
            if (escaped) {
                escaped = false;
            } else if (cp == '\\') {
                escaped = true;
            } else if (cp == '"') {
                quoted = !quoted;
            } else if (cp == ',' && !quoted) {
                parts.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.appendCodePoint(cp);
        }
        parts.add(current.toString());
        List<Rdn> rdns = new ArrayList<>(parts.size());
        for (String part : parts) {
            String piece = part.trim();
            int equals = piece.indexOf('=');
            if (equals <= 0) {
                return null;
            }
            rdns.add(new Rdn(
                    piece.substring(0, equals).trim().toLowerCase(Locale.ROOT),
                    piece.substring(equals + 1).trim()));
        }
        return rdns;
    }

    /** Leading digits after a sign; trailing junk is ignored. Overflow is a failure. */
    static Long jsParseInt(String text) {
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            if (!isUnicodeSpace(cp)) {
                break;
            }
            i += Character.charCount(cp);
        }
        int sign = 1;
        if (i < text.length() && text.charAt(i) == '-') {
            sign = -1;
            i++;
        } else if (i < text.length() && text.charAt(i) == '+') {
            i++;
        }
        int start = i;
        while (i < text.length() && isDigit(text.charAt(i))) {
            i++;
        }
        if (i == start) {
            return null;
        }
        try {
            return sign * Long.parseLong(text.substring(start, i));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Ports parsePorts(String text) {
        if (text.isEmpty()) {
            return new Ports(null, null);
        }
        int dash = text.indexOf('-');
        if (dash < 0) {
            Long single = jsParseInt(text);
            if (single == null) {
                return null;
            }
            return new Ports(single, single);
        }
        String left = text.substring(0, dash);
        String right = text.substring(dash + 1);
        Long low = left.isEmpty() ? null : jsParseInt(left);
        Long high = right.isEmpty() ? null : jsParseInt(right);
        return new Ports(low, high);
    }

    private static Value parseDns(String text) {
        int colon = text.indexOf(':');
        String host = colon < 0 ? text : text.substring(0, colon);
        String ports = colon < 0 ? "" : text.substring(colon + 1);
        if (host.isEmpty() || hasSpace(host)) {
            return null;
        }
        Ports parsed = parsePorts(ports);
        if (parsed == null) {
            return null;
        }
        return new Value.Dns(host.toLowerCase(Locale.ROOT), parsed);
    }

    private static Value parseIp(String text) {
        if (text.isEmpty()) {
            return null;
        }
        String address;
        String rest;
        if (text.startsWith("[")) {
            int close = text.indexOf(']');
            if (close < 0) {
                return null;
            }
            address = text.substring(1, close);
            rest = text.substring(close + 1);
        } else {
            int colon = text.indexOf(':');
            if (colon < 0) {
                address = text;
                rest = "";
            } else {
                address = text.substring(0, colon);
                rest = text.substring(colon);
            }
        }
        String mask = null;
        int slash = address.indexOf('/');
        if (slash >= 0) {
            mask = address.substring(slash + 1);
            address = address.substring(0, slash);
        }
        String portText = rest.startsWith(":") ? rest.substring(1) : rest;
        Ports ports = parsePorts(portText);
        if (ports == null) {
            return null;
        }
        return new Value.Ip(new IpAddress(address.toLowerCase(Locale.ROOT), mask, ports));
    }

    private static String writeYearMonth(long months) {
        if (months == Long.MIN_VALUE) {
            return null;
        }
        String sign = months < 0 ? "-" : "";
        long absolute = Math.abs(months);
        return sign + "P" + (absolute / 12) + "Y" + (absolute % 12) + "M";
    }

    private static String writeHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format(Locale.US, "%02X", b));
        }
        return out.toString();
    }

    private static String writeX500(List<Rdn> rdns) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < rdns.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append(rdns.get(i).attribute.toUpperCase(Locale.ROOT)).append('=').append(rdns.get(i).value);
        }
        return out.toString();
    }

    /** The port range is not written back. */
    private static String writeIp(IpAddress ip) {
        if (ip.mask != null && !ip.mask.isEmpty()) {
            return ip.address + "/" + ip.mask;
        }
        return ip.address;
    }

    private static String writeHostPorts(String host, Ports ports) {
        if (ports.low == null && ports.high == null) {
            return host;
        }
        String low = ports.low == null ? "" : Long.toString(ports.low);
        if (Objects.equals(ports.low, ports.high)) {
            return host + ":" + low;
        }
        String high = ports.high == null ? "" : Long.toString(ports.high);
        return host + ":" + low + "-" + high;
    }

    /** An integral value keeps a {@code .0}. */
    static String writeDouble(double v) {
        if (v == Double.POSITIVE_INFINITY) {
            return "INF";
        }
        if (v == Double.NEGATIVE_INFINITY) {
            return "-INF";
        }
        if (Double.isNaN(v)) {
            return "NaN";
        }
        if (v == Math.floor(v) && Math.abs(v) < 1e21) {
            if (v == 0.0) {
                return "0.0";
            }
            return new BigDecimal(v).toBigInteger().toString() + ".0";
        }
        return jsNumber(v);
    }

    static String writeDayTime(double total) {
        String sign = total < 0.0 ? "-" : "";
        double rest = Math.abs(total);
        double days = Math.floor(rest / 86400.0);
        rest -= days * 86400.0;
        double hours = Math.floor(rest / 3600.0);
        rest -= hours * 3600.0;
        double minutes = Math.floor(rest / 60.0);
        rest -= minutes * 60.0;
        return sign + "P" + jsNumber(days) + "DT" + jsNumber(hours) + "H" + jsNumber(minutes) + "M" + jsNumber(rest) + "S";
    }

    static String writeTemporal(Temporal t) {
        String year;
        if (Math.abs(t.year) < 1000 && t.year >= 0) {
            year = String.format(Locale.US, "%04d", t.year);
        } else if (t.year < 0 && t.year > -100) {
            String raw = Long.toString(t.year);
            year = "0".repeat(4 - raw.length()) + raw;
        } else {
            year = Long.toString(t.year);
        }
        String seconds = (t.second < 10.0 ? "0" : "") + jsNumber(t.second);
        String date = String.format(Locale.US, "%s-%02d-%02d", year, t.month, t.day);
        String time = String.format(Locale.US, "%02d:%02d:%s", t.hour, t.minute, seconds);
        String body = switch (t.shape) {
            case DATE -> date;
            case TIME -> time;
            case DATE_TIME -> date + "T" + time;
        };
        String zone;
        if (t.tz == null) {
            zone = "";
        } else if (t.tz == 0) {
            zone = "Z";
        } else {
            int absolute = Math.abs(t.tz);
            zone = String.format(Locale.US, "%c%02d:%02d", t.tz < 0 ? '-' : '+', absolute / 60, absolute % 60);
        }
        return body + zone;
    }

    /**
     * The shortest round-trip decimal, then the plain or scientific form used for
     * a double inside a duration or a time.
     */
    static String jsNumber(double v) {
        if (Double.isNaN(v)) {
            return "NaN";
        }
        if (v == Double.POSITIVE_INFINITY) {
            return "Infinity";
        }
        if (v == Double.NEGATIVE_INFINITY) {
            return "-Infinity";
        }
        if (v == 0.0) {
            return "0";
        }
        boolean negative = v < 0;
        BigDecimal decimal = BigDecimal.valueOf(Math.abs(v)).stripTrailingZeros();
        String digits = decimal.unscaledValue().abs().toString();
        int scale = decimal.scale();
        int k = digits.length();
        int exponent = k - 1 - scale;
        int n = exponent + 1;
        String body;
        if (k <= n && n <= 21) {
            body = digits + "0".repeat(n - k);
        } else if (0 < n && n <= 21) {
            body = digits.substring(0, n) + "." + digits.substring(n);
        } else if (-6 < n && n <= 0) {
            body = "0." + "0".repeat(-n) + digits;
        } else {
            int e = n - 1;
            char sign = e >= 0 ? '+' : '-';
            int abs = Math.abs(e);
            if (k == 1) {
                body = digits + "e" + sign + abs;
            } else {
                body = digits.charAt(0) + "." + digits.substring(1) + "e" + sign + abs;
            }
        }
        return negative ? "-" + body : body;
    }

    static String encodeBase64(byte[] bytes) {
        final byte[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        StringBuilder out = new StringBuilder((bytes.length + 2) / 3 * 4);
        for (int i = 0; i < bytes.length; i += 3) {
            int remaining = Math.min(3, bytes.length - i);
            int n = 0;
            for (int j = 0; j < remaining; j++) {
                n |= (bytes[i + j] & 0xFF) << (16 - 8 * j);
            }
            for (int j = 0; j < 4; j++) {
                if (j <= remaining) {
                    out.append((char) alphabet[(n >> (18 - 6 * j)) & 63]);
                } else {
                    out.append('=');
                }
            }
        }
        return out.toString();
    }

    /** Floor division, so a negative dividend is not truncated toward zero. */
    static long divEuclid(long a, long b) {
        long q = a / b;
        long r = a % b;
        if (r < 0) {
            q += b > 0 ? -1 : 1;
        }
        return q;
    }

    static long remEuclid(long a, long b) {
        long r = a % b;
        if (r < 0) {
            r += Math.abs(b);
        }
        return r;
    }

    /** Days since 1970-01-01 in the proleptic Gregorian calendar. */
    static long daysFromCivil(long year, long month, long day) {
        long y = month <= 2 ? year - 1 : year;
        long era = divEuclid(y, 400);
        long yoe = y - era * 400;
        long mp = (month + 9) % 12;
        long doy = (153 * mp + 2) / 5 + day - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146_097 + doe - 719_468;
    }

    static long[] civilFromDays(long days) {
        long z = days + 719_468;
        long era = divEuclid(z, 146_097);
        long doe = z - era * 146_097;
        long yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long day = doy - (153 * mp + 2) / 5 + 1;
        long month = mp < 10 ? mp + 3 : mp - 9;
        long year = yoe + era * 400 + (month <= 2 ? 1 : 0);
        return new long[] {year, month, day};
    }

    private static Integer partialCompare(double x, double y) {
        if (Double.isNaN(x) || Double.isNaN(y)) {
            return null;
        }
        if (x < y) {
            return -1;
        }
        if (x > y) {
            return 1;
        }
        return 0;
    }

    private static double instant(Temporal t, int assumed) {
        double seconds = 0;
        if (t.shape != Shape.TIME) {
            seconds += (double) (daysFromCivil(t.year, t.month, t.day) * 86_400L);
        }
        seconds += t.hour * 3600.0 + t.minute * 60.0 + t.second;
        int zone = t.tz == null ? assumed : t.tz;
        seconds -= (double) zone * 60.0;
        return seconds;
    }

    private static Integer compareTemporal(Temporal a, Temporal b) {
        if ((a.tz == null) == (b.tz == null)) {
            return partialCompare(instant(a, 0), instant(b, 0));
        }
        Integer east = partialCompare(instant(a, 14 * 60), instant(b, 14 * 60));
        Integer west = partialCompare(instant(a, -14 * 60), instant(b, -14 * 60));
        if (east == null || west == null || !east.equals(west)) {
            return null;
        }
        return east;
    }

    private static int daysInMonth(long year, long month) {
        int[] lengths = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        boolean leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        if (month == 2 && leap) {
            return 29;
        }
        int index = (int) month - 1;
        if (index < 0) {
            index = 0;
        } else if (index > 11) {
            index = 11;
        }
        return lengths[index];
    }

    /** Months added on the local components, the day clamped, the timezone carried through. */
    static Temporal addMonths(Temporal t, long months) {
        long total;
        try {
            total = Math.addExact(Math.addExact(Math.multiplyExact(t.year, 12), t.month - 1L), months);
        } catch (ArithmeticException e) {
            return null;
        }
        long year = divEuclid(total, 12);
        if (Math.abs(year) > MAX_YEAR) {
            return null;
        }
        long month = remEuclid(total, 12) + 1;
        int day = (int) Math.min(t.day, daysInMonth(year, month));
        return t.withDate(year, (int) month, day);
    }

    /** Seconds added on the local components, the timezone carried through. */
    static Temporal addSeconds(Temporal t, double seconds) {
        double date = t.shape == Shape.TIME ? 0.0 : (double) (daysFromCivil(t.year, t.month, t.day) * 86_400L);
        double total = date + t.hour * 3600.0 + t.minute * 60.0 + t.second + seconds;
        if (!Double.isFinite(total) || Math.abs(total) > (double) MAX_YEAR * 366.0 * 86_400.0) {
            return null;
        }
        double days = Math.floor(total / 86_400.0);
        double rest = total - days * 86_400.0;
        double hour = Math.floor(rest / 3600.0);
        rest -= hour * 3600.0;
        double minute = Math.floor(rest / 60.0);
        double second = rest - minute * 60.0;
        long[] civil = civilFromDays((long) days);
        return new Temporal(
                t.shape,
                civil[0],
                (int) civil[1],
                (int) civil[2],
                (int) hour,
                (int) minute,
                second,
                t.tz);
    }

    /** {@code now} as the three current values, in UTC to the whole second. */
    static Temporal nowTemporal(long seconds, Shape shape) {
        long days = divEuclid(seconds, 86_400);
        long ofDay = remEuclid(seconds, 86_400);
        long[] civil = civilFromDays(days);
        Temporal t = new Temporal(
                shape,
                civil[0],
                (int) civil[1],
                (int) civil[2],
                (int) (ofDay / 3600),
                (int) (ofDay % 3600 / 60),
                ofDay % 60,
                0);
        return switch (shape) {
            case DATE -> t.withTime(0, 0, 0);
            case TIME -> t.withDate(1970, 1, 1);
            case DATE_TIME -> t;
        };
    }
}
