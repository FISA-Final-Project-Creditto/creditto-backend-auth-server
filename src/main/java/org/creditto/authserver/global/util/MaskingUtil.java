package org.creditto.authserver.global.util;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class MaskingUtil {

    private static final List<String> SENSITIVE_KEYS = List.of(
            "password",
            "secret",
            "token",
            "key",
            "certificateNumber"
    );

    private static final Pattern JSON_KEY_VALUE_PATTERN = Pattern.compile(
            "(\"(?:" + String.join("|", SENSITIVE_KEYS) + ")\"\\s*:\\s*\")(.*?)(\")",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern KEY_VALUE_PATTERN = Pattern.compile(
            "(?i)((?:password|secret|token|key[number]?|certificateNumber)\\s*[=:]\\s*)([^,\\s}\\]]+)"
    );

    private static final Pattern PHONE_PATTERN = Pattern.compile("(?<!\\d)(\\d{3})(\\d{3,4})(\\d{4})(?!\\d)");

    private MaskingUtil() {
    }

    public static String maskSensitiveData(final String raw) {
        if (raw == null || raw.isBlank()) {
            return raw;
        }

        String masked = maskJsonSensitiveValues(raw);
        masked = maskKeyValuePairs(masked);
        masked = maskPhoneNumbers(masked);

        return masked;
    }

    private static String maskJsonSensitiveValues(final String input) {
        final Matcher matcher = JSON_KEY_VALUE_PATTERN.matcher(input);
        final StringBuilder buffer = new StringBuilder();

        while (matcher.find()) {
            final String maskedValue = maskValue(matcher.group(2));
            matcher.appendReplacement(buffer,
                    Matcher.quoteReplacement(matcher.group(1) + maskedValue + matcher.group(3)));
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }

    private static String maskKeyValuePairs(final String input) {
        final Matcher matcher = KEY_VALUE_PATTERN.matcher(input);
        final StringBuilder buffer = new StringBuilder();

        while (matcher.find()) {
            final String maskedValue = maskValue(matcher.group(2));
            matcher.appendReplacement(buffer,
                    Matcher.quoteReplacement(matcher.group(1) + maskedValue));
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }

    private static String maskPhoneNumbers(final String input) {
        final Matcher matcher = PHONE_PATTERN.matcher(input);
        final StringBuilder buffer = new StringBuilder();

        while (matcher.find()) {
            final String masked = matcher.group(1) + "****" + matcher.group(3);
            matcher.appendReplacement(buffer, masked);
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }

    private static String maskValue(final String value) {
        if (value == null || value.isBlank()) {
            return value;
        }

        final String trimmed = value.trim();
        if (trimmed.length() <= 2) {
            return "*".repeat(trimmed.length());
        }

        final int length = trimmed.length();
        return trimmed.charAt(0) +
                "*".repeat(length - 2) +
                trimmed.charAt(length - 1);
    }
}
