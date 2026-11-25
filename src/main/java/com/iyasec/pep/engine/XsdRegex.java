// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * XML Schema regular expressions.
 *
 * <p>An XML Schema regex is anchored: {@code bc} matches {@code bc} and not {@code abcd}.
 * The pattern is wrapped as {@code ^(?:…)$}. {@code \i}, {@code \I}, {@code \c} and {@code \C}
 * become ASCII classes. Character class subtraction is refused.
 */
final class XsdRegex {
    private XsdRegex() {}

    /** Translates and compiles; {@code null} when the pattern is refused or invalid. */
    static Pattern compile(String pattern) {
        if (hasClassSubtraction(pattern)) {
            return null;
        }
        StringBuilder translated = new StringBuilder(pattern.length() + 16);
        translated.append("^(?:");
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c != '\\') {
                translated.append(c);
                continue;
            }
            if (i + 1 >= pattern.length()) {
                translated.append('\\');
                break;
            }
            char other = pattern.charAt(++i);
            switch (other) {
                case 'i' -> translated.append("[A-Za-z_:]");
                case 'I' -> translated.append("[^A-Za-z_:]");
                case 'c' -> translated.append("[A-Za-z0-9_:.\\-]");
                case 'C' -> translated.append("[^A-Za-z0-9_:.\\-]");
                default -> translated.append('\\').append(other);
            }
        }
        translated.append(")$");
        try {
            return Pattern.compile(translated.toString());
        } catch (PatternSyntaxException e) {
            return null;
        }
    }

    static boolean matches(Pattern pattern, String subject) {
        return pattern.matcher(subject).matches();
    }

    /** An opening bracket, anything but a closing one, then {@code -[}. */
    private static boolean hasClassSubtraction(String pattern) {
        for (int start = 0; start < pattern.length(); start++) {
            if (pattern.charAt(start) != '[') {
                continue;
            }
            int end = pattern.indexOf(']', start + 1);
            if (end < 0) {
                end = pattern.length();
            }
            if (pattern.substring(start + 1, end).contains("-[")) {
                return true;
            }
        }
        return false;
    }
}
