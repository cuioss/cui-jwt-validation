/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.security;

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.tools.logging.LogRecord;
import lombok.NonNull;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Provides counters for relevant security events in the JWT token handling module.
 * <p>
 * This class is designed to be thread-safe and highly concurrent, allowing for
 * accurate counting of security events in multi-threaded environments.
 * <p>
 * The counter follows the same naming/numbering scheme as {@link de.cuioss.jwt.token.JWTTokenLogMessages}
 * for consistency and easier correlation between logs and metrics.
 * <p>
 * This implementation is structured to simplify later integration with micrometer
 * but does not create any dependency on it.
 * 
 * @since 1.0
 */
public class SecurityEventCounter {

    /**
     * Enum defining all security event types that can be counted.
     * <p>
     * Each event type has an identifier that follows the same numbering scheme
     * as {@link de.cuioss.jwt.token.JWTTokenLogMessages}.
     */
    public enum EventType {
        // Token format issues
        TOKEN_EMPTY(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY),
        TOKEN_SIZE_EXCEEDED(JWTTokenLogMessages.WARN.TOKEN_SIZE_EXCEEDED),
        FAILED_TO_DECODE_JWT(JWTTokenLogMessages.WARN.FAILED_TO_DECODE_JWT),
        INVALID_JWT_FORMAT(JWTTokenLogMessages.WARN.INVALID_JWT_FORMAT),
        FAILED_TO_DECODE_HEADER(JWTTokenLogMessages.WARN.FAILED_TO_DECODE_HEADER),
        FAILED_TO_DECODE_PAYLOAD(JWTTokenLogMessages.WARN.FAILED_TO_DECODE_PAYLOAD),
        DECODED_PART_SIZE_EXCEEDED(JWTTokenLogMessages.WARN.DECODED_PART_SIZE_EXCEEDED),

        // Missing claims
        MISSING_CLAIM(JWTTokenLogMessages.WARN.MISSING_CLAIM),
        MISSING_RECOMMENDED_ELEMENT(JWTTokenLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT),

        // Validation failures
        TOKEN_EXPIRED(JWTTokenLogMessages.WARN.TOKEN_EXPIRED),
        TOKEN_NBF_FUTURE(JWTTokenLogMessages.WARN.TOKEN_NBF_FUTURE),
        AUDIENCE_MISMATCH(JWTTokenLogMessages.WARN.AUDIENCE_MISMATCH),
        AZP_MISMATCH(JWTTokenLogMessages.WARN.AZP_MISMATCH),
        ISSUER_MISMATCH(JWTTokenLogMessages.WARN.ISSUER_MISMATCH),
        NO_ISSUER_CONFIG(JWTTokenLogMessages.WARN.NO_ISSUER_CONFIG),

        // Signature issues
        SIGNATURE_VALIDATION_FAILED(JWTTokenLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED),
        KEY_NOT_FOUND(JWTTokenLogMessages.WARN.KEY_NOT_FOUND),

        // Algorithm issues
        UNSUPPORTED_ALGORITHM(JWTTokenLogMessages.WARN.UNSUPPORTED_ALGORITHM),

        // JWKS issues
        JWKS_FETCH_FAILED(JWTTokenLogMessages.WARN.JWKS_FETCH_FAILED),
        JWKS_JSON_PARSE_FAILED(JWTTokenLogMessages.WARN.JWKS_JSON_PARSE_FAILED),
        FAILED_TO_READ_JWKS_FILE(JWTTokenLogMessages.WARN.FAILED_TO_READ_JWKS_FILE),
        KEY_ROTATION_DETECTED(JWTTokenLogMessages.WARN.KEY_ROTATION_DETECTED),

        // Successful operations
        ACCESS_TOKEN_CREATED(JWTTokenLogMessages.DEBUG.ACCESS_TOKEN_CREATED),
        ID_TOKEN_CREATED(JWTTokenLogMessages.DEBUG.ID_TOKEN_CREATED),
        REFRESH_TOKEN_CREATED(JWTTokenLogMessages.DEBUG.REFRESH_TOKEN_CREATED);

        private final LogRecord logRecord;

        EventType(LogRecord logRecord) {
            this.logRecord = logRecord;
        }

        /**
         * @return the numeric identifier for this event type
         */
        public int getId() {
            return logRecord.getIdentifier();
        }

        /**
         * @return a human-readable description of this event type
         */
        public String getDescription() {
            return logRecord.getTemplate();
        }

        /**
         * Returns the corresponding log record from {@link de.cuioss.jwt.token.JWTTokenLogMessages}
         * that is associated with this event type.
         * <p>
         * This method provides a bidirectional link between the event type and its
         * corresponding log message, allowing for consistent error reporting and logging.
         * 
         * @return the corresponding log record from JWTTokenLogMessages
         */
        public LogRecord getLogRecord() {
            return logRecord;
        }
    }

    private final ConcurrentHashMap<EventType, AtomicLong> counters = new ConcurrentHashMap<>();

    /**
     * Increments the counter for the specified event type.
     * <p>
     * If the counter doesn't exist yet, it will be created.
     * 
     * @param eventType the type of security event to count
     * @return the new count value
     */
    public long increment(@NonNull EventType eventType) {
        return counters.computeIfAbsent(eventType, k -> new AtomicLong(0)).incrementAndGet();
    }

    /**
     * Gets the current count for the specified event type.
     * 
     * @param eventType the type of security event
     * @return the current count, or 0 if the event has never been counted
     */
    public long getCount(@NonNull EventType eventType) {
        AtomicLong counter = counters.get(eventType);
        return counter != null ? counter.get() : 0;
    }

    /**
     * Gets a snapshot of all current counter values.
     * 
     * @return an unmodifiable map of event types to their current counts
     */
    public Map<EventType, Long> getCounters() {
        return counters.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().get()));
    }

    /**
     * Resets all counters to zero.
     */
    public void reset() {
        counters.clear();
    }

    /**
     * Resets the counter for the specified event type to zero.
     * 
     * @param eventType the type of security event to reset
     */
    public void reset(@NonNull EventType eventType) {
        counters.remove(eventType);
    }
}
